# rmdetect - File Deletion Monitor

## What it does

`rmdetect` is an eBPF-based tool that monitors file deletions in real-time by attaching to the `ext4_free_inode` tracepoint. It captures the process ID and command name of processes that delete files from the filesystem.

### Use Cases

- **Security monitoring**: Track unauthorized file deletions
- **Audit trails**: Monitor which processes are deleting files
- **Debugging**: Understand file system activity during troubleshooting
- **Compliance**: Ensure file deletion policies are followed

## How it works

### Kernel Hook

The tool attaches to the `ext4_free_inode` tracepoint, which is triggered whenever a file is deleted from an ext4 filesystem. This tracepoint is called when the kernel frees an inode (index node) that represents a file.

```c
SEC("tracepoint/ext4/ext4_free_inode")
int trace_inode_free(struct trace_event_raw_ext4_free_inode *ctx) {
    // Program logic here
    return 0;
}
```

### Data Flow

```
File Deletion Event
        ↓
ext4_free_inode tracepoint
        ↓
eBPF Program (rmdetect.c)
        ↓
Ring Buffer (events map)
        ↓
Go Application (rmdetect.go)
        ↓
Console Output
```

### eBPF Program Details

#### Data Structure
```c
struct data_t {
    u32 pid;           // Process ID that deleted the file
    char comm[16];     // Command name (process name)
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
4. **Submit data** to the ring buffer for userspace consumption

## Implementation Details

### eBPF Program (`bpf/rmdetect.c`)

```c
#include "common.h"

struct data_t {
    u32 pid;
    char comm[16];
};

// Define the ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/ext4/ext4_free_inode")
int trace_inode_free(struct trace_event_raw_ext4_free_inode *ctx) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) {
        return 0; // Skip event if ring buffer reservation fails
    }
    data->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    bpf_ringbuf_submit(data, 0); // Submit data to ring buffer
    return 0;
}

char _license[] SEC("license") = "GPL";
```

### Go Application (`cmd/rmdetect.go`)

The Go application:
1. **Loads the eBPF program** into the kernel
2. **Attaches to the tracepoint** using the cilium/ebpf library
3. **Reads events** from the ring buffer
4. **Applies filters** (PID, command name)
5. **Displays results** in a formatted table

## Usage

### Basic Usage

```bash
# Monitor all file deletions
sudo ./ebee rmdetect
```

### Filtering Options

```bash
# Monitor deletions by specific PID
sudo ./ebee rmdetect --pid 1234

# Monitor deletions by specific command
sudo ./ebee rmdetect --comm "rm"

# Monitor deletions by specific command (case-insensitive)
sudo ./ebee rmdetect --comm "unlink"
```

### Example Output

```
Monitoring file deletions... Press Ctrl+C to stop
PID     Command
---     -------
1234    rm
5678    unlink
9012    find
```

## Technical Deep Dive

### Kernel Tracepoint Details

The `ext4_free_inode` tracepoint is defined in the Linux kernel source:

```c
// From kernel source: fs/ext4/ext4.h
TRACE_EVENT(ext4_free_inode,
    TP_PROTO(struct inode *inode),
    TP_ARGS(inode),
    TP_STRUCT__entry(
        __field(dev_t, dev)
        __field(ino_t, ino)
        __field(umode_t, mode)
        __field(uid_t, uid)
        __field(gid_t, gid)
        __field(blkcnt_t, blocks)
    ),
    TP_fast_assign(
        __entry->dev = inode->i_sb->s_dev;
        __entry->ino = inode->i_ino;
        __entry->mode = inode->i_mode;
        __entry->uid = i_uid_read(inode);
        __entry->gid = i_gid_read(inode);
        __entry->blocks = inode->i_blocks;
    ),
    TP_printk("dev %d,%d ino %lu mode 0%o uid %u gid %u blocks %llu",
        MAJOR(__entry->dev), MINOR(__entry->dev),
        (unsigned long) __entry->ino,
        __entry->mode, __entry->uid, __entry->gid, __entry->blocks)
);
```

### Performance Considerations

- **Ring Buffer Size**: 16MB buffer can handle high-frequency deletion events
- **Zero-Copy**: Ring buffer provides efficient kernel-to-userspace communication
- **Minimal Overhead**: eBPF program executes quickly with minimal impact

### Limitations

1. **Filesystem Specific**: Only works with ext4 filesystem
2. **Kernel Version**: Requires kernel with ext4 tracepoint support
3. **Permission Required**: Needs root privileges to load eBPF programs

## Troubleshooting

### Common Issues

1. **"permission denied"**
   ```bash
   # Solution: Run with sudo
   sudo ./ebee rmdetect
   ```

2. **"tracepoint not found"**
   ```bash
   # Check if tracepoint exists
   sudo cat /sys/kernel/debug/tracing/available_events | grep ext4_free_inode
   ```

3. **"no events showing"**
   ```bash
   # Test by creating and deleting a file
   touch testfile && rm testfile
   ```

### Debug Commands

```bash
# Check if eBPF program is loaded
sudo bpftool prog list | grep rmdetect

# Check tracepoint attachment
sudo cat /sys/kernel/debug/tracing/events/ext4/ext4_free_inode/enable

# Monitor kernel logs
dmesg | tail
```

## Extending rmdetect

### Adding More Information

You could extend the tool to capture additional information:

```c
struct data_t {
    u32 pid;
    char comm[16];
    char filename[256];    // Filename being deleted
    u64 timestamp;         // Event timestamp
    u32 uid;              // User ID
    u32 gid;              // Group ID
};
```

### Supporting Other Filesystems

To support other filesystems, you could:

1. **Add more tracepoints**:
   ```c
   SEC("tracepoint/xfs/xfs_free_inode")
   int trace_xfs_inode_free(struct trace_event_raw_xfs_free_inode *ctx);
   ```

2. **Use kprobes** for generic file deletion:
   ```c
   SEC("kprobe/vfs_unlink")
   int kprobe_vfs_unlink(struct pt_regs *ctx);
   ```

## Related Tools

- **execsnoop**: Monitor process executions
- **opensnoop**: Monitor file opens
- **filesnoop**: Monitor file operations

## References

- [eBPF Documentation](https://ebpf.io/)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [Linux Kernel Tracepoints](https://www.kernel.org/doc/html/latest/trace/events.html)
- [ext4 Filesystem Documentation](https://www.kernel.org/doc/html/latest/filesystems/ext4.html)
