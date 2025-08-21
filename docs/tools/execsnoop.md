# execsnoop - Process Execution Monitor

## What it does

`execsnoop` is an eBPF-based tool that monitors process executions in real-time by attaching to the `sched_process_exec` tracepoint. It captures the process ID, command name, and arguments of executed processes.

### Use Cases

- **Security monitoring**: Track unauthorized process executions
- **Audit trails**: Monitor which processes are being started
- **Debugging**: Understand process creation during troubleshooting
- **Performance analysis**: Identify process execution patterns
- **Compliance**: Ensure process execution policies are followed

## How it works

### Kernel Hook

The tool attaches to the `sched_process_exec` tracepoint, which is triggered whenever a new process is executed. This tracepoint is called when the kernel schedules a new process for execution.

```c
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // Program logic here
    return 0;
}
```

### Data Flow

```
Process Execution Event
        ↓
sched_process_exec tracepoint
        ↓
eBPF Program (execsnoop.c)
        ↓
Ring Buffer (events map)
        ↓
Go Application (execsnoop.go)
        ↓
Console Output
```

### eBPF Program Details

#### Data Structure
```c
struct exec_data_t {
    u32 pid;           // Process ID of the executed process
    u32 ppid;          // Parent process ID (currently set to 0)
    char comm[16];     // Command name (process name)
    char argv[256];    // Arguments (currently stores command name)
};
```

#### Ring Buffer
```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB buffer
} events SEC(".maps");
```

#### Program Logic
1. **Reserve space** in the ring buffer for the event data
2. **Get current process ID** using `bpf_get_current_pid_tgid()`
3. **Get command name** using `bpf_get_current_comm()`
4. **Store command name in argv field** (placeholder for future argument capture)
5. **Submit data** to the ring buffer for userspace consumption

## Implementation Details

### eBPF Program (`bpf/execsnoop.c`)

```c
#include "common.h"

struct exec_data_t {
    u32 pid;
    u32 ppid;
    char comm[16];
    char argv[256];
};

// Define the ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct exec_data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct exec_data_t), 0);
    if (!data) {
        return 0; // Skip event if ring buffer reservation fails
    }
    
    // Get current PID (lower 32 bits of the 64-bit value)
    data->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // For now, set ppid to 0 to avoid complex kernel structure access
    data->ppid = 0;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    // Store the command name in argv field for now
    bpf_probe_read_str(&data->argv, sizeof(data->argv), (void *)data->comm);
    
    bpf_ringbuf_submit(data, 0); // Submit data to ring buffer
    return 0;
}

char _license[] SEC("license") = "GPL";
```

### Go Application (`cmd/execsnoop.go`)

The Go application:
1. **Loads the eBPF program** into the kernel
2. **Attaches to the tracepoint** using the cilium/ebpf library
3. **Reads events** from the ring buffer
4. **Applies filters** (PID, command name)
5. **Displays results** in a formatted table

## Usage

### Basic Usage

```bash
# Monitor all process executions
sudo ./ebee execsnoop
```

### Filtering Options

```bash
# Monitor executions by specific PID
sudo ./ebee execsnoop --pid 1234

# Monitor executions by specific command
sudo ./ebee execsnoop --comm "bash"

# Monitor executions by specific command (case-insensitive)
sudo ./ebee execsnoop --comm "python"
```

### Example Output

```
Monitoring process executions... Press Ctrl+C to stop
PID     Command         Arguments
---     -------         ----------
1234    bash            bash
5678    python          python
9012    ls              ls
```

## Technical Deep Dive

### Kernel Tracepoint Details

The `sched_process_exec` tracepoint is defined in the Linux kernel source:

```c
// From kernel source: kernel/sched/core.c
TRACE_EVENT(sched_process_exec,
    TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm),
    TP_ARGS(p, old_pid, bprm),
    TP_STRUCT__entry(
        __array(char, filename, 256)
        __field(pid_t, pid)
        __field(pid_t, old_pid)
    ),
    TP_fast_assign(
        memcpy(__entry->filename, bprm->filename, 256);
        __entry->pid = p->pid;
        __entry->old_pid = old_pid;
    ),
    TP_printk("filename=%s pid=%d old_pid=%d", __entry->filename, __entry->pid, __entry->old_pid)
);
```

### Performance Considerations

- **Ring Buffer Size**: 16MB buffer can handle high-frequency execution events
- **Zero-Copy**: Ring buffer provides efficient kernel-to-userspace communication
- **Minimal Overhead**: eBPF program executes quickly with minimal impact
- **Filtering**: Userspace filtering reduces processing overhead

### Limitations

1. **Parent PID**: Currently set to 0 due to kernel structure access complexity
2. **Arguments**: Currently stores command name instead of actual arguments
3. **Kernel Version**: Requires kernel with sched tracepoint support
4. **Permission Required**: Needs root privileges to load eBPF programs

## Troubleshooting

### Common Issues

1. **"permission denied"**
   ```bash
   # Solution: Run with sudo
   sudo ./ebee execsnoop
   ```

2. **"tracepoint not found"**
   ```bash
   # Check if tracepoint exists
   sudo cat /sys/kernel/debug/tracing/available_events | grep sched_process_exec
   ```

3. **"no events showing"**
   ```bash
   # Test by executing a command
   ls -la
   ```

### Debug Commands

```bash
# Check if eBPF program is loaded
sudo bpftool prog list | grep execsnoop

# Check tracepoint attachment
sudo cat /sys/kernel/debug/tracing/events/sched/sched_process_exec/enable

# Monitor kernel logs
dmesg | tail

# List available sched events
sudo cat /sys/kernel/debug/tracing/available_events | grep sched
```

## Extending execsnoop

### Adding Parent PID Support

To capture parent PID, you could use a different approach:

```c
// Option 1: Use bpf_get_current_task_btf() (requires BTF)
struct task_struct *current = (struct task_struct *)bpf_get_current_task_btf();
if (current) {
    bpf_probe_read(&data->ppid, sizeof(data->ppid), &current->real_parent->tgid);
}

// Option 2: Use a separate kprobe on do_fork/do_execve
SEC("kprobe/do_fork")
int kprobe_do_fork(struct pt_regs *ctx) {
    // Capture parent-child relationship
    return 0;
}
```

### Adding Argument Capture

To capture actual command arguments:

```c
// Read arguments from the tracepoint context
bpf_probe_read_str(&data->argv, sizeof(data->argv), (void *)ctx->filename);

// Or use a kprobe on do_execve to get more details
SEC("kprobe/do_execve")
int kprobe_do_execve(struct pt_regs *ctx) {
    // Access filename and arguments from pt_regs
    return 0;
}
```

### Adding Timestamp

```c
struct exec_data_t {
    u32 pid;
    u32 ppid;
    char comm[16];
    char argv[256];
    u64 timestamp;  // Add timestamp field
};

// In the eBPF program
data->timestamp = bpf_ktime_get_ns();
```

## Advanced Features

### Process Tree Tracking

You could extend execsnoop to build a process tree:

```c
// Use a hash map to track parent-child relationships
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1024);
} process_tree SEC(".maps");
```

### Command Line Arguments

To capture full command line arguments, you'd need to:

1. **Use kprobes** instead of tracepoints
2. **Parse the argument structure** from kernel memory
3. **Handle string encoding** and length limits

### Performance Monitoring

Add performance metrics:

```c
// Track execution frequency
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[16]);
    __type(value, u64);
    __uint(max_entries, 1024);
} exec_count SEC(".maps");
```

## Related Tools

- **rmdetect**: Monitor file deletions
- **opensnoop**: Monitor file opens
- **tcpconnect**: Monitor TCP connections
- **biolatency**: Monitor block I/O latency

## References

- [eBPF Documentation](https://ebpf.io/)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [Linux Kernel Scheduler](https://www.kernel.org/doc/html/latest/scheduler/)
- [Process Management in Linux](https://www.kernel.org/doc/html/latest/process/)
- [BCC execsnoop](https://github.com/iovisor/bcc/blob/master/tools/execsnoop.py)
