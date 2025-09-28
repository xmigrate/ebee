#include "common.h"

#define AF_INET 2

// Define PT_REGS_PARM1 for x86_64 (first function parameter is in RDI register)
#define PT_REGS_PARM1(x) ((x)->di)

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

// Alternative approach: Use syscall tracepoint which has structured data
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