# eBPF Fundamentals

This guide covers the fundamental concepts of eBPF (extended Berkeley Packet Filter) that you need to understand to develop tools with the ebee project.

## What is eBPF?

eBPF (extended Berkeley Packet Filter) is a revolutionary technology that allows you to run sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules.

### Key Concepts

- **Sandboxed Execution**: eBPF programs run in a virtual machine within the kernel
- **Event-Driven**: Programs are triggered by kernel events (system calls, tracepoints, etc.)
- **Type Safety**: Programs are verified before execution to ensure kernel safety
- **Zero-Copy**: Efficient data transfer between kernel and userspace

## eBPF Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Userspace     │    │   Kernel        │    │   Hardware      │
│   Application   │    │   eBPF VM       │    │   Events        │
│                 │    │                 │    │                 │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │   Go      │  │    │  │  eBPF     │  │    │  │ Tracepoint│  │
│  │  App      │◄─┼────┼─►│  Program  │◄─┼────┼─►│  /Kprobe  │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
│                 │    │                 │    │                 │
│  ┌───────────┐  │    │  ┌───────────┐  │    │                 │
│  │  Ring     │  │    │  │  eBPF     │  │    │                 │
│  │  Buffer   │◄─┼────┼─►│  Maps     │  │    │                 │
│  └───────────┘  │    │  └───────────┘  │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## eBPF Program Types

### 1. Tracepoints
Attach to predefined kernel tracepoints for monitoring specific events.

```c
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // Program logic here
    return 0;
}
```

### 2. Kprobes
Attach to kernel function entry and exit points.

```c
SEC("kprobe/do_execve")
int kprobe_execve(struct pt_regs *ctx) {
    // Program logic here
    return 0;
}
```

### 3. Kretprobes
Attach to kernel function return points.

```c
SEC("kretprobe/do_execve")
int kretprobe_execve(struct pt_regs *ctx) {
    // Program logic here
    return 0;
}
```

## eBPF Maps

Maps are the primary mechanism for sharing data between eBPF programs and userspace applications.

### Common Map Types

#### 1. Ring Buffer
Efficient zero-copy communication between kernel and userspace.

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
```

#### 2. Hash Maps
Key-value storage for eBPF programs.

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1024);
} counters SEC(".maps");
```

#### 3. Arrays
Fixed-size array storage.

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} config SEC(".maps");
```

## eBPF Helper Functions

eBPF programs can call predefined helper functions to interact with the kernel.

### Common Helpers

```c
// Get current process ID and thread group ID
u64 pid_tgid = bpf_get_current_pid_tgid();

// Get current process name
bpf_get_current_comm(&comm, sizeof(comm));

// Read kernel memory safely
bpf_probe_read(&value, sizeof(value), (void *)ptr);

// Read string from kernel memory
bpf_probe_read_str(&str, sizeof(str), (void *)ptr);

// Get current task structure
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
```

## eBPF Program Lifecycle

### 1. Compilation
eBPF programs are written in C and compiled to eBPF bytecode.

```bash
clang -O2 -target bpf -c program.c -o program.o
```

### 2. Loading
Programs are loaded into the kernel and verified.

```go
objs := programObjects{}
if err := loadProgramObjects(&objs, nil); err != nil {
    log.Fatalf("loading objects: %v", err)
}
```

### 3. Attachment
Programs are attached to kernel events.

```go
link, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceExec, nil)
```

### 4. Execution
Programs execute when their attached events occur.

### 5. Cleanup
Programs are detached and resources are freed.

```go
defer objs.Close()
defer link.Close()
```

## eBPF Verifier

The eBPF verifier ensures programs are safe to run in the kernel.

### Verification Checks

1. **Bounds Checking**: All memory accesses are bounds-checked
2. **Type Safety**: Programs must use correct data types
3. **Loop Prevention**: Programs cannot have unbounded loops
4. **Resource Limits**: Programs have size and complexity limits

### Common Verifier Errors

```bash
# Invalid memory access
R0 invalid mem access 'scalar'

# Unbounded loop
back-edge from insn 10 to 10

# Invalid helper function usage
invalid func unknown#0
```

## Data Structures

### Event Data Structure
```c
struct data_t {
    u32 pid;           // Process ID
    u32 ppid;          // Parent process ID
    char comm[16];     // Command name
    char argv[256];    // Arguments
};
```

### Kernel Structures
```c
// Task structure (simplified)
struct task_struct {
    u32 pid;
    u32 tgid;
    struct task_struct *real_parent;
    char comm[16];
    // ... many more fields
};
```

## Best Practices

### 1. Memory Safety
Always use `bpf_probe_read()` and `bpf_probe_read_str()` for kernel memory access.

```c
// ❌ Unsafe
data->pid = current->pid;

// ✅ Safe
bpf_probe_read(&data->pid, sizeof(data->pid), &current->pid);
```

### 2. Error Handling
Check return values and handle errors gracefully.

```c
struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
if (!data) {
    return 0; // Skip event if reservation fails
}
```

### 3. Resource Management
Always clean up resources in userspace.

```go
defer objs.Close()
defer link.Close()
```

### 4. Performance
Use efficient data structures and minimize kernel/userspace communication.

## Debugging eBPF Programs

### 1. Verifier Logs
```bash
cat /sys/kernel/debug/bpf/verifier_log
```

### 2. bpftool
```bash
# List loaded programs
sudo bpftool prog list

# Show program details
sudo bpftool prog show id <prog_id>

# Dump program bytecode
sudo bpftool prog dump xlated id <prog_id>
```

### 3. Kernel Logs
```bash
dmesg | tail
```

## Common Patterns

### 1. Event Filtering
```c
// Filter by PID
if (target_pid != 0 && current_pid != target_pid) {
    return 0;
}
```

### 2. Data Collection
```c
// Collect process information
data->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
bpf_get_current_comm(&data->comm, sizeof(data->comm));
```

### 3. Map Operations
```c
// Update counters
u64 *counter = bpf_map_lookup_elem(&counters, &key);
if (counter) {
    (*counter)++;
}
```

## Next Steps

Now that you understand eBPF fundamentals:

1. Explore the [tool documentation](tools/) to see these concepts in action
2. Try modifying existing tools to understand the patterns
3. Create your own eBPF tools following the established patterns
4. Read the [development setup guide](development-setup.md) to get started
