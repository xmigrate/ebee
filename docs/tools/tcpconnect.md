# tcpconnect - TCP Connection Monitoring

## What it does

tcpconnect is an eBPF-based tool that monitors TCP connection attempts in real-time. It captures process information, source/destination IP addresses and ports for each TCP connection attempt.

### Use Cases

- **Security Monitoring**: Track which processes are making network connections and to which destinations
- **Network Debugging**: Identify connection patterns and troubleshoot connectivity issues
- **Application Analysis**: Monitor application network behavior and dependency mapping
- **Compliance Auditing**: Log network activity for security audits and compliance requirements
- **Performance Analysis**: Understand network connection patterns for optimization

## How it works

### Kernel Hook

The tool attaches to the `syscalls/sys_enter_connect` tracepoint, which is triggered whenever a process attempts to establish a TCP connection using the `connect()` system call.

```c
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_connect(struct trace_event_raw_sys_enter *ctx) {
    // Program logic here
    return 0;
}
```

### Data Flow

```
TCP connect() System Call
        ↓
sys_enter_connect tracepoint
        ↓
eBPF Program (tcpconnect.c)
        ↓
Ring Buffer (events map)
        ↓
Go Application (tcpconnect.go)
        ↓
Console Output
```

### eBPF Program Details

#### Data Structure
```c
struct tcp_connect_data_t {
    u32 pid;           // Process ID making the connection
    u32 tgid;          // Thread group ID
    char comm[16];     // Command name
    u32 saddr;         // Source IP address (IPv4)
    u32 daddr;         // Destination IP address (IPv4)
    u16 sport;         // Source port
    u16 dport;         // Destination port
    u64 timestamp;     // Connection timestamp
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
1. **Syscall Interception**: Capture connect() system call with sockaddr parameter
2. **Socket Validation**: Verify the socket address length and family (AF_INET)
3. **Data Extraction**: Read sockaddr_in structure from userspace to get destination IP/port
4. **Process Information**: Get current process ID, thread group ID, and command name
5. **Event Submission**: Send event data to userspace via ring buffer

## Implementation Details

### eBPF Program (`bpf/tcpconnect.c`)

```c
#include "common.h"

#define AF_INET 2

struct tcp_connect_data_t {
    u32 pid;           // Process ID making the connection
    u32 tgid;          // Thread group ID
    char comm[16];     // Command name
    u32 saddr;         // Source IP address (IPv4)
    u32 daddr;         // Destination IP address (IPv4)
    u16 sport;         // Source port
    u16 dport;         // Destination port
    u64 timestamp;     // Connection timestamp
};

// Define the ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB buffer
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_sys_connect(struct trace_event_raw_sys_enter *ctx) {
    // Check if this is a TCP socket by examining the sockaddr
    u64 fd = ctx->args[0];
    u64 sockaddr_ptr = ctx->args[1];
    u64 socklen = ctx->args[2];

    // Basic sanity checks
    if (socklen < 16) {  // sizeof(struct sockaddr_in)
        return 0;
    }

    // Reserve space in the ring buffer
    struct tcp_connect_data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct tcp_connect_data_t), 0);
    if (!data) {
        return 0;
    }

    // Get current process information
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid & 0xFFFFFFFF;
    data->tgid = pid_tgid >> 32;

    // Get command name
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    // Get timestamp
    data->timestamp = bpf_ktime_get_ns();

    // Try to read sockaddr_in structure from userspace
    struct sockaddr_in addr;
    if (bpf_probe_read_user(&addr, sizeof(addr), (void *)sockaddr_ptr) == 0) {
        // Check if it's AF_INET (IPv4)
        if (addr.sin_family == AF_INET) {
            data->daddr = addr.sin_addr.s_addr;
            data->dport = __builtin_bswap16(addr.sin_port);  // Convert from network byte order
        } else {
            // Not IPv4, discard
            bpf_ringbuf_discard(data, 0);
            return 0;
        }
    } else {
        // Failed to read sockaddr, set to 0
        data->daddr = 0;
        data->dport = 0;
    }

    // Source address/port are harder to get from syscall, set to 0 for now
    data->saddr = 0;
    data->sport = 0;

    // Submit data to userspace
    bpf_ringbuf_submit(data, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

### Go Application (`cmd/tcpconnect.go`)

The Go application:
1. **Loads the eBPF program** into the kernel using bpf2go generated bindings
2. **Attaches to the sys_enter_connect tracepoint** using the cilium/ebpf library
3. **Reads events** from the ring buffer in a background goroutine
4. **Applies filters** based on command-line options (PID, command, port, IP, hostname)
5. **Displays results** in a formatted table with timestamps

## Usage

### Basic Usage

```bash
# Monitor all TCP connections
sudo ./ebee tcpconnect
```

### Filtering Options

```bash
# Filter by process ID
sudo ./ebee tcpconnect --pid 1234

# Filter by command name
sudo ./ebee tcpconnect --comm curl

# Filter by destination port
sudo ./ebee tcpconnect --port 80

# Filter by destination IP address
sudo ./ebee tcpconnect --addr 192.168.1.1

# Filter by destination hostname (with DNS resolution)
sudo ./ebee tcpconnect --host google.com

# Combine multiple filters
sudo ./ebee tcpconnect --comm firefox --port 443
```

### Example Output

```
Monitoring TCP connections... Press Ctrl+C to stop
TIME       PID      TGID     SADDR          :SPORT  DADDR          :DPORT  COMMAND
----       ---      ----     -----          :-----  -----          :-----  -------
14:23:45   1234     1234     0.0.0.0        :0      172.217.14.174 :443   firefox
14:23:46   5678     5678     0.0.0.0        :0      140.82.112.3   :443   git
14:23:47   9012     9012     0.0.0.0        :0      54.230.87.15   :80    curl
```

## Technical Deep Dive

### Syscall Tracepoint Details

The `sys_enter_connect` tracepoint is defined in the Linux kernel and captures all connect() system calls:

```c
// From kernel source: include/trace/events/syscalls.h
TRACE_EVENT_FN(sys_enter_connect,
    TP_PROTO(struct pt_regs *regs, long id),
    TP_ARGS(regs, id),
    // Tracepoint definition
);
```

The tracepoint provides access to:
- `args[0]`: File descriptor (socket)
- `args[1]`: Pointer to sockaddr structure
- `args[2]`: Address length

### Performance Considerations

- **Ring Buffer Size**: 16MB buffer can handle high-frequency connection events
- **Zero-Copy**: Ring buffer provides efficient kernel-to-userspace communication
- **Minimal Overhead**: eBPF program executes quickly with minimal network impact
- **Filtering**: Most filtering is done in userspace to keep eBPF program simple

### Limitations

1. **Source Address/Port**: Currently shows 0.0.0.0:0 because source information is not easily available at connect() time
2. **IPv4 Only**: Only monitors IPv4 connections, IPv6 connections are filtered out
3. **Connect Attempts**: Shows connection attempts, not successful connections
4. **Userspace Filtering**: Some filtering is done in userspace, which could be optimized

## Troubleshooting

### Common Issues

1. **"permission denied"**
   ```bash
   # Solution: Run with sudo
   sudo ./ebee tcpconnect
   ```

2. **"panic: unable to redefine 'h' shorthand"**
   ```bash
   # This was fixed - the tool no longer uses 'h' shorthand for --host
   # Use the full --host flag instead
   sudo ./ebee tcpconnect --host google.com
   ```

3. **"no events showing"**
   ```bash
   # Test by making a connection in another terminal
   curl -s http://example.com > /dev/null

   # Check if you have network activity
   netstat -tulpn | grep ESTABLISHED
   ```

4. **"source addresses showing as 0.0.0.0:0"**
   ```bash
   # This is expected - source address/port are not captured at connect() time
   # The tool focuses on destination information which is more useful for monitoring
   ```

### Debug Commands

```bash
# Check if eBPF program is loaded
sudo bpftool prog list | grep tcpconnect

# Check tracepoint attachment
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/enable

# Monitor kernel logs for eBPF errors
dmesg | tail

# Test with verbose output
sudo ./ebee tcpconnect --comm test_program
```

## Extending tcpconnect

### Adding Source Address Information

You could extend the tool to capture source address information by hooking into additional kernel functions:

```c
// Hook into tcp_v4_connect to get source information
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    // Access socket structure to get source address
}
```

### Adding Connection State Tracking

Track successful vs failed connections:

```c
struct tcp_connect_data_t {
    // Existing fields
    u32 result;          // Connection result (success/failure)
    u32 error_code;      // Error code if failed
};
```

### Performance Optimization

Move filtering to eBPF program:

```c
// Add filtering logic in eBPF program
if (target_port != 0 && data->dport != target_port) {
    bpf_ringbuf_discard(data, 0);
    return 0;
}
```

## Related Tools

- **tcpaccept**: Monitor incoming TCP connections (server-side)
- **tcpretrans**: Track TCP retransmissions
- **execsnoop**: Monitor process execution (often used together for full picture)
- **rmdetect**: Monitor file operations (complementary for security monitoring)

## References

- [eBPF Documentation](https://ebpf.io/)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [Linux Kernel Syscall Tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
- [BCC tcpconnect Reference](https://github.com/iovisor/bcc/blob/master/tools/tcpconnect.py)
- [TCP Socket Programming](https://man7.org/linux/man-pages/man2/connect.2.html)