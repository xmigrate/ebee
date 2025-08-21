# Writing eBPF C Code

Let's create your first eBPF program from scratch! We'll build a simple file operation monitor that tracks when files are opened.

## 🎯 What We're Building

A tool called `fileopen` that monitors file open operations and reports:
- Process ID that opened the file
- Process name
- Filename that was opened

## 📝 Step 1: Create the eBPF Program

Create `bpf/fileopen.c`:

```c
#include "common.h"

// Data structure for events sent to userspace
struct file_event {
    u32 pid;                // Process ID
    char comm[16];         // Process name (limited to 16 chars in kernel)
    char filename[256];    // Filename (truncated if longer)
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB buffer
} events SEC(".maps");

// eBPF program attached to file open operations
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_file_open(struct trace_event_raw_sys_enter *ctx) {
    // Reserve space in the ring buffer
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;  // Skip if no space available
    }
    
    // Get process information
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Get filename from system call arguments
    // ctx->args[1] contains the filename pointer
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), 
                           (void *)ctx->args[1]);
    
    // Submit the event to userspace
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

## 🔍 Code Breakdown

Let's understand each part of this eBPF program:

### Data Structure
```c
struct file_event {
    u32 pid;                // Process ID
    char comm[16];         // Process name
    char filename[256];    // Filename
};
```

!!! info "Why these sizes?"
    - `comm` is limited to 16 characters in the Linux kernel
    - `filename` is limited to prevent the eBPF program from being too large
    - `u32` for PID is sufficient (PIDs are 32-bit values)

### Ring Buffer Map
```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB
} events SEC(".maps");
```

!!! tip "Ring Buffer Benefits"
    - **Zero-copy**: Efficient data transfer to userspace
    - **Lock-free**: High performance under load
    - **Overflow handling**: Old events are discarded if buffer is full

### Program Attachment Point
```c
SEC("tracepoint/syscalls/sys_enter_openat")
```

!!! info "Tracepoint Choice"
    - `sys_enter_openat` catches most file opens in modern Linux
    - Tracepoints are stable interfaces (unlike kprobes)
    - `sys_enter_` gives us access to system call arguments

### Helper Functions Used

#### `bpf_get_current_pid_tgid()`
```c
event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
```
- Returns 64-bit value: upper 32 bits = thread group ID, lower 32 bits = process ID
- We mask to get just the PID

#### `bpf_get_current_comm()`
```c
bpf_get_current_comm(&event->comm, sizeof(event->comm));
```
- Safely copies process name to our buffer
- Automatically null-terminates the string

#### `bpf_probe_read_user_str()`
```c
bpf_probe_read_user_str(&event->filename, sizeof(event->filename), 
                       (void *)ctx->args[1]);
```
- Safely reads string from userspace memory
- Handles page faults and invalid pointers
- Null-terminates the result

## 🛡️ Safety Considerations

eBPF programs must be **verifiably safe**. Here's how our program ensures safety:

### 1. Bounds Checking
```c
// ✅ Good: Size is specified and bounded
bpf_get_current_comm(&event->comm, sizeof(event->comm));

// ❌ Bad: Unbounded copy
// strcpy(event->comm, current->comm);  // This won't compile
```

### 2. Null Pointer Checking
```c
struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
if (!event) {
    return 0;  // Handle allocation failure
}
```

### 3. Safe Memory Access
```c
// ✅ Good: Safe helper function
bpf_probe_read_user_str(&event->filename, sizeof(event->filename), ptr);

// ❌ Bad: Direct memory access
// strcpy(event->filename, (char *)ptr);  // Verifier will reject
```

## 🧪 Testing Your eBPF Program

Before moving to the Go code, let's verify our eBPF program compiles:

```bash
# Compile the eBPF program
clang -O2 -target bpf -c bpf/fileopen.c -o bpf/fileopen.o -I bpf/headers

# Check if it compiled successfully
file bpf/fileopen.o
# Should show: ELF 64-bit LSB relocatable, eBPF
```

### Common Compilation Errors

!!! failure "vmlinux.h not found"
    ```bash
    # Generate kernel headers first
    make gen_vmlinux
    ```

!!! failure "Unknown helper function"
    ```c
    // Make sure you're using valid helper functions
    // Check: https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
    ```

!!! failure "Program too large"
    ```c
    // Reduce array sizes or simplify logic
    char filename[128];  // Instead of 512
    ```

## 📚 Alternative Attachment Points

Our program uses `sys_enter_openat`, but there are other options:

### System Call Tracepoints
```c
// Monitor different system calls
SEC("tracepoint/syscalls/sys_enter_open")     // Older open() syscall
SEC("tracepoint/syscalls/sys_enter_openat")   // Modern openat() syscall
SEC("tracepoint/syscalls/sys_exit_openat")    // Exit point (has return value)
```

### Kernel Function Tracepoints
```c
// Monitor VFS layer operations
SEC("tracepoint/vfs/vfs_open")               // Virtual filesystem layer
```

### Kprobes (Advanced)
```c
// Attach to any kernel function (less stable)
SEC("kprobe/do_sys_openat2")                 // Internal kernel function
```

!!! tip "Choosing Attachment Points"
    - **Tracepoints**: Stable, well-documented, recommended for beginners
    - **Kprobes**: Flexible but can break between kernel versions
    - **System call entry**: Good for monitoring user actions
    - **System call exit**: Good when you need return values

## 🎓 Learning Exercises

Try modifying the program to learn more:

### Exercise 1: Add Timestamps
```c
struct file_event {
    u32 pid;
    char comm[16];
    char filename[256];
    u64 timestamp;      // Add this field
};

// In the program
event->timestamp = bpf_ktime_get_ns();
```

### Exercise 2: Filter by Process Name
```c
// Only monitor files opened by specific processes
char target_comm[16] = "cat";
char current_comm[16];
bpf_get_current_comm(&current_comm, sizeof(current_comm));

// Simple string comparison (eBPF style)
bool match = true;
for (int i = 0; i < 16; i++) {
    if (current_comm[i] != target_comm[i]) {
        match = false;
        break;
    }
    if (current_comm[i] == '\0') break;
}

if (!match) return 0;  // Skip event
```

### Exercise 3: Count Operations
```c
// Add a hash map to count operations per process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);      // PID
    __type(value, u64);    // Count
    __uint(max_entries, 1024);
} process_counts SEC(".maps");

// In the program
u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
u64 *count = bpf_map_lookup_elem(&process_counts, &pid);
if (count) {
    (*count)++;
} else {
    u64 initial_count = 1;
    bpf_map_update_elem(&process_counts, &pid, &initial_count, BPF_ANY);
}
```

## ✅ Checkpoint

Before moving to the next section, make sure you:

- [ ] Understand the basic eBPF program structure
- [ ] Know how to define data structures for events
- [ ] Understand ring buffers for data transfer
- [ ] Can use basic eBPF helper functions
- [ ] Your program compiles without errors

## 🚀 What's Next?

Great! You've written your first eBPF program. Now let's create the Go userspace application to load this program and display the events:

**[Next: Go Integration →](go-userspace.md)**

## 📖 Additional Resources

- **[eBPF Helper Functions](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)** - Complete list of available helpers
- **[Linux Tracepoints](https://www.kernel.org/doc/html/latest/trace/events.html)** - Available tracepoints
- **[eBPF Verifier](https://www.kernel.org/doc/html/latest/bpf/verifier.html)** - Understanding program verification