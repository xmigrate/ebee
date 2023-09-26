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
    // Populate data with other information relevant to the event
    
    bpf_ringbuf_submit(data, 0); // Submit data to ring buffer
    return 0;
}
char _license[] SEC("license") = "GPL";