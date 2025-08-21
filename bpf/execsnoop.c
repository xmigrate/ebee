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
    // In a production version, we could use a different approach
    data->ppid = 0;
    
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    // Store the command name in argv field for now
    bpf_probe_read_str(&data->argv, sizeof(data->argv), (void *)data->comm);
    
    bpf_ringbuf_submit(data, 0); // Submit data to ring buffer
    return 0;
}

char _license[] SEC("license") = "GPL";
