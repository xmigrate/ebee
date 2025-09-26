# CO-RE and BTF: Portable eBPF Programs

CO-RE (Compile Once, Run Everywhere) and BTF (BPF Type Format) are revolutionary technologies that solve one of eBPF's biggest challenges: **kernel version compatibility**. This guide covers how to write portable eBPF programs that work across different kernel versions without recompilation.

## 🎯 The Problem CO-RE Solves

### Traditional eBPF Challenges

```c
// ❌ Problem: Kernel structure layouts change between versions
struct task_struct {
    int pid;           // Kernel 4.19: offset 1234
    char comm[16];     // Kernel 5.4:  offset 1248
    // ... but in kernel 5.10, pid might be at offset 1240!
};

// This breaks when you access fields directly
int get_pid_old_way(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return task->pid;  // ❌ Might access wrong memory location
}
```

### CO-RE Solution

```c
// ✅ Solution: CO-RE handles kernel differences automatically
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>

int get_pid_core_way(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, pid);  // ✅ Works across kernel versions
}
```

## 🧬 What is BTF?

BTF (BPF Type Format) is a compact metadata format that describes:

- **Data structure layouts** in the kernel
- **Function signatures** and parameters
- **Type relationships** and dependencies
- **Source code locations** for debugging

### BTF in Action

```bash
# Check if your kernel has BTF support
ls /sys/kernel/btf/vmlinux

# View BTF information
bpftool btf dump file /sys/kernel/btf/vmlinux | grep "STRUCT 'task_struct'"
```

### BTF Type Information

```c
// BTF contains metadata like this for every kernel type
struct task_struct {
    // BTF knows: field 'pid' is at offset X in kernel version Y
    int pid;                    /* offset: varies by kernel */
    int tgid;                   /* offset: varies by kernel */
    char comm[16];              /* offset: varies by kernel */
    struct mm_struct *mm;       /* offset: varies by kernel */
    // ... hundreds more fields
};
```

## 🔧 CO-RE Programming Patterns

### 1. Field Access with BPF_CORE_READ

```c
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>

struct process_info {
    u32 pid;
    u32 tgid;
    char comm[16];
    u32 ppid;
};

SEC("kprobe/do_exit")
int trace_process_exit(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct process_info info = {};

    // ✅ CO-RE field access - works across kernel versions
    info.pid = BPF_CORE_READ(task, pid);
    info.tgid = BPF_CORE_READ(task, tgid);
    BPF_CORE_READ_STR_INTO(&info.comm, task, comm);

    // Access nested fields safely
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (parent) {
        info.ppid = BPF_CORE_READ(parent, tgid);
    }

    // Submit to ring buffer
    bpf_ringbuf_output(&events, &info, sizeof(info), 0);
    return 0;
}
```

### 2. Handling Field Existence

```c
// Some fields might not exist in older kernels
SEC("kprobe/do_fork")
int trace_fork(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Check if field exists before accessing
    if (bpf_core_field_exists(task->cgroups)) {
        // This field was added in kernel 4.6
        void *cgroups = BPF_CORE_READ(task, cgroups);
        // Use cgroups information
    }

    // Alternative: use different fields based on kernel version
    u64 start_time = 0;
    if (bpf_core_field_exists(task->start_boottime)) {
        // Newer kernels
        start_time = BPF_CORE_READ(task, start_boottime);
    } else if (bpf_core_field_exists(task->real_start_time)) {
        // Older kernels
        start_time = BPF_CORE_READ(task, real_start_time.tv_sec);
    }

    return 0;
}
```

### 3. Type Preservation

```c
// CO-RE preserves type information
struct file_event {
    u32 pid;
    u32 fd;
    char filename[256];
    u64 inode;
};

SEC("kprobe/vfs_open")
int trace_file_open(struct pt_regs *ctx) {
    // PT_REGS_PARM1 is CO-RE-aware for function parameters
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    struct file_event event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;

    // Navigate complex nested structures with CO-RE
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);

    if (inode) {
        event.inode = BPF_CORE_READ(inode, i_ino);
    }

    // Read filename from dentry
    BPF_CORE_READ_STR_INTO(&event.filename, dentry, d_name.name);

    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}
```

## 🚀 Advanced CO-RE Features

### 1. Conditional Compilation

```c
// Compile different code paths based on kernel features
#if __has_builtin(__builtin_preserve_enum_value)
    // Use modern eBPF features
    #define USE_MODERN_FEATURES 1
#else
    // Fallback for older kernels
    #define USE_MODERN_FEATURES 0
#endif

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    #if USE_MODERN_FEATURES
        // Use advanced tracepoint features
        u64 filename_ptr = ctx->args[1];
        char filename[256];
        bpf_probe_read_user_str(&filename, sizeof(filename), (void *)filename_ptr);
    #else
        // Fallback method
        char filename[256] = "unknown";
    #endif

    return 0;
}
```

### 2. Enum Value Preservation

```c
// Safely use kernel enum values
enum {
    TRACE_EVENT_TYPE_EXEC = 1,
    TRACE_EVENT_TYPE_EXIT = 2,
    TRACE_EVENT_TYPE_FORK = 3,
};

// Preserve kernel enum values for compatibility
static const int TASK_RUNNING = __builtin_preserve_enum_value(*(typeof(TASK_RUNNING) *)TASK_RUNNING);
static const int TASK_INTERRUPTIBLE = __builtin_preserve_enum_value(*(typeof(TASK_INTERRUPTIBLE) *)TASK_INTERRUPTIBLE);

SEC("kprobe/schedule")
int trace_schedule(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    long state = BPF_CORE_READ(task, __state);  // or 'state' in older kernels

    if (state == TASK_RUNNING) {
        // Handle running task
    } else if (state == TASK_INTERRUPTIBLE) {
        // Handle sleeping task
    }

    return 0;
}
```

### 3. Relocations and Field Sizes

```c
// Handle varying field sizes across kernel versions
struct network_event {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
};

SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct network_event event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;

    // CO-RE handles different socket structure layouts
    struct inet_sock *inet = (struct inet_sock *)sk;

    // These field accesses work across kernel versions
    event.saddr = BPF_CORE_READ(inet, inet_saddr);
    event.daddr = BPF_CORE_READ(inet, inet_daddr);
    event.sport = BPF_CORE_READ(inet, inet_sport);
    event.dport = BPF_CORE_READ(inet, inet_dport);

    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}
```

## 📦 Complete CO-RE Example: Process Lineage Tracker

Here's a complete example showing advanced CO-RE usage:

```c
// process_lineage.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct process_lineage {
    u32 pid;
    u32 ppid;
    u32 tgid;
    char comm[16];
    char parent_comm[16];
    u64 start_time;
    u32 uid;
    u32 gid;
    u8 depth;  // How deep in the process tree
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Helper to safely get process lineage
static int get_process_lineage(struct task_struct *task, struct process_lineage *lineage) {
    if (!task || !lineage)
        return -1;

    // Basic process info
    lineage->pid = BPF_CORE_READ(task, pid);
    lineage->tgid = BPF_CORE_READ(task, tgid);
    BPF_CORE_READ_STR_INTO(&lineage->comm, task, comm);

    // Get credentials (might vary by kernel version)
    const struct cred *cred = BPF_CORE_READ(task, cred);
    if (cred) {
        lineage->uid = BPF_CORE_READ(cred, uid.val);
        lineage->gid = BPF_CORE_READ(cred, gid.val);
    }

    // Parent process info with CO-RE
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (parent && parent != task) {  // Avoid init process loop
        lineage->ppid = BPF_CORE_READ(parent, tgid);
        BPF_CORE_READ_STR_INTO(&lineage->parent_comm, parent, comm);

        // Calculate process tree depth
        lineage->depth = 1;
        struct task_struct *current_parent = parent;

        #pragma unroll
        for (int i = 0; i < 10; i++) {  // Limit depth to prevent verifier issues
            struct task_struct *next_parent = BPF_CORE_READ(current_parent, real_parent);
            if (!next_parent || next_parent == current_parent)
                break;
            lineage->depth++;
            current_parent = next_parent;
        }
    }

    // Get start time (field name varies by kernel version)
    if (bpf_core_field_exists(task->start_boottime)) {
        lineage->start_time = BPF_CORE_READ(task, start_boottime);
    } else if (bpf_core_field_exists(task->real_start_time)) {
        // Handle older kernel versions
        lineage->start_time = BPF_CORE_READ(task, real_start_time.tv_sec);
    }

    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_process_lineage(struct trace_event_raw_sched_process_exec *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct process_lineage *lineage = bpf_ringbuf_reserve(&events, sizeof(*lineage), 0);
    if (!lineage)
        return 0;

    if (get_process_lineage(task, lineage) < 0) {
        bpf_ringbuf_discard(lineage, 0);
        return 0;
    }

    bpf_ringbuf_submit(lineage, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

## 🛠️ Building CO-RE Programs

### 1. Makefile for CO-RE

```makefile
# Generate vmlinux.h for your kernel
gen_vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h

# Build with CO-RE support
build_core:
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		-I./bpf/headers \
		-c bpf/process_lineage.c \
		-o bpf/process_lineage.o

# Generate Go bindings
generate:
	go generate ./...
```

### 2. Go Integration

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native -type process_lineage processlineage ../bpf/process_lineage.c

package main

import (
    "bytes"
    "encoding/binary"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
)

func main() {
    // Load the CO-RE program
    objs := processlineageObjects{}
    if err := loadProcesslineageObjects(&objs, nil); err != nil {
        log.Fatalf("loading objects: %v", err)
    }
    defer objs.Close()

    // Attach to tracepoint
    l, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceProcessLineage, nil)
    if err != nil {
        log.Fatalf("opening tracepoint: %v", err)
    }
    defer l.Close()

    // Read events
    rd, err := ringbuf.NewReader(objs.Events)
    if err != nil {
        log.Fatalf("opening ringbuf reader: %v", err)
    }
    defer rd.Close()

    // Handle events
    go handleEvents(rd)

    // Wait for signal
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    <-sig
}

func handleEvents(rd *ringbuf.Reader) {
    for {
        record, err := rd.Read()
        if err != nil {
            log.Printf("reading from reader: %v", err)
            continue
        }

        var event processlineageProcessLineage
        if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
            log.Printf("parsing event: %v", err)
            continue
        }

        log.Printf("Process: %s (PID=%d, PPID=%d, Depth=%d, UID=%d)",
            nullTerminatedString(event.Comm[:]),
            event.Pid,
            event.Ppid,
            event.Depth,
            event.Uid)
    }
}

func nullTerminatedString(b []byte) string {
    for i, c := range b {
        if c == 0 {
            return string(b[:i])
        }
    }
    return string(b)
}
```

## 🔍 Debugging CO-RE Programs

### 1. BTF Debug Information

```bash
# Check BTF generation
bpftool gen skeleton bpf/process_lineage.o

# Verify relocations
llvm-objdump -r bpf/process_lineage.o

# Check CO-RE relocations
bpftool prog show id <prog_id> --pretty
```

### 2. Verifier with BTF

```bash
# Load with verifier debug info
echo 2 > /proc/sys/net/core/bpf_jit_enable
echo 1 > /proc/sys/kernel/bpf_stats_enabled

# View detailed verifier log
bpftool prog load bpf/process_lineage.o /sys/fs/bpf/test_prog type kprobe \
    log_level 2 log_file verifier.log
```

## ⚠️ CO-RE Limitations and Best Practices

### Limitations

1. **BTF Requirement**: Target kernel must have BTF enabled
2. **Field Dependencies**: Some fields might not exist in older kernels
3. **Compilation Complexity**: More complex build process
4. **Debug Challenges**: Harder to debug relocation issues

### Best Practices

```c
// ✅ Always check field existence for optional fields
if (bpf_core_field_exists(task->some_new_field)) {
    value = BPF_CORE_READ(task, some_new_field);
}

// ✅ Use CO-RE read macros consistently
data = BPF_CORE_READ(ptr, field);           // Single field
BPF_CORE_READ_STR_INTO(&dest, ptr, field); // String field

// ✅ Handle nested structures safely
nested_ptr = BPF_CORE_READ(outer, inner_ptr);
if (nested_ptr) {
    value = BPF_CORE_READ(nested_ptr, field);
}

// ❌ Don't mix CO-RE and direct access
struct task_struct *task = get_current_task();
pid = task->pid;  // Wrong - bypasses CO-RE
```

## 🎯 When to Use CO-RE

### Perfect for:
- **Production deployments** across multiple kernel versions
- **Distribution packages** that need wide compatibility
- **Open source tools** used by diverse environments
- **Long-term maintenance** scenarios

### Consider alternatives for:
- **Single kernel environment** with guaranteed version
- **Rapid prototyping** where compatibility isn't critical
- **Learning eBPF** (start simple, add CO-RE later)

CO-RE and BTF represent the future of eBPF development, enabling truly portable programs that work across the entire Linux ecosystem. Master these concepts to build professional-grade eBPF tools! 🚀