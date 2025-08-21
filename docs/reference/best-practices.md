# Best Practices

Essential best practices for developing reliable, secure, and performant eBPF applications. Follow these guidelines to create production-ready eBPF tools.

## 🏗️ Program Architecture

### 1. Separation of Concerns

#### Keep eBPF Programs Focused
```c
// ✅ Good: Single responsibility
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_file_opens(struct trace_event_raw_sys_enter *ctx) {
    // Only collect file open events
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;
    
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), 
                           (void *)ctx->args[1]);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ❌ Bad: Mixing concerns
SEC("tracepoint/syscalls/sys_enter_openat")
int do_everything(struct trace_event_raw_sys_enter *ctx) {
    // File opens, network analysis, performance monitoring...
    // Too much in one program - hard to maintain and debug
}
```

#### Modular Design
```c
// ✅ Good: Helper functions for reusability
static __always_inline int should_monitor_process(void) {
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // Common filtering logic
    if (uid == 0) return 1; // Always monitor root
    
    u32 *monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    return monitored ? 1 : 0;
}

static __always_inline void record_event_stats(void) {
    u32 key = STAT_EVENTS_PROCESSED;
    u64 *counter = bpf_map_lookup_elem(&stats, &key);
    if (counter) (*counter)++;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    if (!should_monitor_process()) return 0;
    
    // Main logic here
    
    record_event_stats();
    return 0;
}
```

### 2. Error Handling

#### Always Handle Failures
```c
// ✅ Good: Comprehensive error handling
SEC("tracepoint/syscalls/sys_enter_openat")
int robust_file_monitor(struct trace_event_raw_sys_enter *ctx) {
    // Reserve space with error checking
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        // Track allocation failures
        increment_counter(STAT_RINGBUF_FULL);
        return 0;
    }
    
    // Safe memory operations with error checking
    long ret = bpf_probe_read_user_str(&event->filename, sizeof(event->filename),
                                      (void *)ctx->args[1]);
    if (ret < 0) {
        // Handle read failure - don't submit incomplete event
        bpf_ringbuf_discard(event, 0);
        increment_counter(STAT_READ_FAILURES);
        return 0;
    }
    
    // Fill remaining fields
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    if (bpf_get_current_comm(&event->comm, sizeof(event->comm)) != 0) {
        // Handle comm read failure - use placeholder
        __builtin_memcpy(event->comm, "unknown", 8);
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

#### Defensive Programming
```c
// ✅ Good: Validate inputs and assumptions
SEC("kprobe/vfs_open")
int defensive_vfs_monitor(struct pt_regs *ctx) {
    // Validate context pointer
    if (!ctx) return 0;
    
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    if (!file) return 0; // Null check
    
    // Validate pointers before use
    struct dentry *dentry = NULL;
    if (bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry) != 0) {
        return 0; // Failed to read dentry pointer
    }
    
    if (!dentry) return 0; // Null dentry
    
    // Now safe to proceed with dentry operations
    char filename[256];
    bpf_probe_read_kernel_str(&filename, sizeof(filename), &dentry->d_name.name);
    
    return 0;
}
```

## 🔒 Security Best Practices

### 1. Data Sanitization

#### Filter Sensitive Information
```c
// Configuration for sensitive data filtering
struct security_policy {
    u8 filter_system_paths;
    u8 filter_user_homes;
    u8 anonymize_pids;
    u32 max_path_len;
};

// Sensitive path prefixes to filter
static const char sensitive_paths[][32] = {
    "/etc/passwd",
    "/etc/shadow",
    "/root/",
    "/home/",
    "/var/log/",
    ".ssh/",
    ".gnupg/"
};

static __always_inline int is_sensitive_path(const char *path) {
    #pragma unroll
    for (int i = 0; i < 7; i++) {
        if (starts_with_prefix(path, sensitive_paths[i])) {
            return 1;
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int secure_file_monitor(struct trace_event_raw_sys_enter *ctx) {
    char filename[256];
    bpf_probe_read_user_str(&filename, sizeof(filename), (void *)ctx->args[1]);
    
    // Apply security filtering
    if (is_sensitive_path(filename)) {
        // Log security event but don't expose path
        log_security_violation("sensitive_path_access", filename[0] != 0 ? 1 : 0);
        return 0;
    }
    
    // Process non-sensitive paths normally
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        sanitize_and_copy_filename(event->filename, filename, sizeof(event->filename));
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}
```

#### Limit Data Exposure
```c
// ✅ Good: Expose only necessary data
struct minimal_process_event {
    u32 pid;           // Necessary for process tracking
    char comm[16];     // Process name only
    u8 event_type;     // Event classification
    // No sensitive data like memory addresses, full paths, etc.
};

// ❌ Bad: Exposing internal kernel data
struct dangerous_process_event {
    u32 pid;
    void *task_struct_ptr;    // Kernel address - information leak!
    void *mm_struct_ptr;      // Memory management internals
    u64 kernel_stack_ptr;     // Stack address
    char full_cmdline[4096];  // Potentially sensitive arguments
};
```

### 2. Resource Protection

#### Implement Rate Limiting
```c
// Per-process rate limiting to prevent DoS
struct rate_limit {
    u64 last_reset_time;
    u32 event_count;
    u32 max_events_per_second;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, struct rate_limit);
    __uint(max_entries, 10000);
} rate_limits SEC(".maps");

static __always_inline int check_rate_limit(u32 pid) {
    u64 now = bpf_ktime_get_ns();
    
    struct rate_limit *limit = bpf_map_lookup_elem(&rate_limits, &pid);
    if (!limit) {
        // New process - create rate limit entry
        struct rate_limit new_limit = {
            .last_reset_time = now,
            .event_count = 1,
            .max_events_per_second = 1000,
        };
        bpf_map_update_elem(&rate_limits, &pid, &new_limit, BPF_ANY);
        return 1; // Allow first event
    }
    
    // Check if we need to reset the counter (1 second passed)
    if (now - limit->last_reset_time > 1000000000UL) {
        limit->last_reset_time = now;
        limit->event_count = 1;
        return 1; // Allow after reset
    }
    
    // Check rate limit
    if (limit->event_count >= limit->max_events_per_second) {
        return 0; // Rate limited
    }
    
    limit->event_count++;
    return 1; // Allow event
}
```

#### Bound Resource Usage
```c
// ✅ Good: Bounded data structures
#define MAX_TRACKED_PROCESSES 10000
#define MAX_FILENAME_LEN 256
#define MAX_COMM_LEN 16

// Use LRU maps to automatically evict old entries
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, struct process_info);
    __uint(max_entries, MAX_TRACKED_PROCESSES);
} process_cache SEC(".maps");

// Limit event data size
struct bounded_event {
    u32 pid;
    char comm[MAX_COMM_LEN];
    u16 filename_len;                    // Actual length
    char filename[MAX_FILENAME_LEN];     // Fixed maximum
} __attribute__((packed));
```

## ⚡ Performance Best Practices

### 1. Optimize Hot Paths

#### Early Filtering
```c
// ✅ Good: Filter early to reduce processing
SEC("tracepoint/syscalls/sys_enter_openat")
int optimized_file_monitor(struct trace_event_raw_sys_enter *ctx) {
    // Quick PID check first (cheap operation)
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    if (pid < 100) return 0; // Skip kernel threads
    
    // Quick UID check (also cheap)
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (!should_monitor_uid(uid)) return 0;
    
    // Only do expensive operations after cheap filters pass
    char filename[256];
    long ret = bpf_probe_read_user_str(&filename, sizeof(filename), 
                                      (void *)ctx->args[1]);
    if (ret <= 0) return 0;
    
    // More expensive filtering on filename
    if (is_temporary_file(filename)) return 0;
    
    // Finally, process the event (most expensive)
    struct file_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    // ... process event
    
    return 0;
}
```

#### Minimize Map Operations
```c
// ❌ Bad: Multiple map operations
SEC("tracepoint/syscalls/sys_enter_openat")
int inefficient_stats(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Multiple map lookups - expensive
    increment_counter(&open_count, pid);
    increment_counter(&per_uid_count, bpf_get_current_uid_gid() & 0xFFFFFFFF);
    increment_counter(&total_syscalls, 0);
    
    return 0;
}

// ✅ Good: Batch operations, single data structure
struct process_stats {
    u64 open_count;
    u64 read_count;
    u64 write_count;
    u64 close_count;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int efficient_stats(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Single map lookup, multiple updates
    struct process_stats *stats = bpf_map_lookup_elem(&process_stats_map, &pid);
    if (!stats) {
        struct process_stats new_stats = {.open_count = 1};
        bpf_map_update_elem(&process_stats_map, &pid, &new_stats, BPF_ANY);
    } else {
        stats->open_count++;
    }
    
    return 0;
}
```

### 2. Data Structure Optimization

#### Use Appropriate Types
```c
// ✅ Good: Right-sized data types
struct efficient_event {
    u32 pid;           // u32 sufficient for PID
    u32 timestamp;     // Relative timestamp (u32 sufficient for deltas)
    u16 filename_len;  // u16 sufficient for length
    u8 event_type;     // u8 sufficient for event classification
    char comm[16];     // Fixed kernel size
    char filename[];   // Variable length (only actual size transmitted)
} __attribute__((packed));

// ❌ Bad: Oversized data types
struct wasteful_event {
    u64 pid;           // u64 wasteful for PID
    u64 timestamp;     // u64 might be overkill
    u64 filename_len;  // Definitely overkill
    u64 event_type;    // Very wasteful
    char comm[256];    // Much larger than kernel limit
    char filename[4096]; // Usually mostly empty
    char padding[1000];  // Pure waste
};
```

#### Memory-Efficient Maps
```c
// ✅ Good: Choose appropriate map types
// For small, known set of keys
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);    // O(1) access, no hash overhead
    __uint(max_entries, 256);            // CPUs, file descriptors, etc.
} small_indexed_data SEC(".maps");

// For dynamic keys with good distribution
struct {
    __uint(type, BPF_MAP_TYPE_HASH);     // Good for PID-based tracking
    __uint(max_entries, 10000);
} process_tracking SEC(".maps");

// For high-frequency counters
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // No locks, automatic aggregation
    __uint(max_entries, 64);             // Event type counters
} performance_counters SEC(".maps");
```

## 🧪 Testing and Quality

### 1. Comprehensive Testing

#### Unit Testing Patterns
```c
#ifdef TESTING
// Mock helper functions for testing
static u64 test_pid_tgid = (1234ULL << 32) | 5678ULL;
static char test_comm[] = "test_process";

#define bpf_get_current_pid_tgid() test_pid_tgid
#define bpf_get_current_comm(buf, size) \
    (__builtin_memcpy(buf, test_comm, sizeof(test_comm)), 0)

// Test-specific code
static int test_event_processing(void) {
    // Test your eBPF program logic here
    return 0;
}
#endif

// Production code
SEC("tracepoint/syscalls/sys_enter_openat")
int production_handler(struct trace_event_raw_sys_enter *ctx) {
    // Your actual implementation
    return 0;
}
```

#### Integration Testing
```go
func TestEventGeneration(t *testing.T) {
    // Load eBPF program
    objs := testObjects{}
    require.NoError(t, loadTestObjects(&objs, nil))
    defer objs.Close()
    
    // Attach to test tracepoint
    link, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TestHandler, nil)
    require.NoError(t, err)
    defer link.Close()
    
    // Generate test event
    f, err := os.Create("/tmp/test_file")
    require.NoError(t, err)
    f.Close()
    os.Remove("/tmp/test_file")
    
    // Verify event was captured
    // Read from ring buffer and validate
}
```

### 2. Monitoring and Observability

#### Built-in Metrics
```c
// Add observability to your eBPF programs
enum metric_keys {
    METRIC_EVENTS_PROCESSED = 0,
    METRIC_EVENTS_DROPPED,
    METRIC_ERRORS,
    METRIC_MAX_PROCESSING_TIME,
    METRIC_TOTAL_PROCESSING_TIME,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 16);
} metrics SEC(".maps");

static __always_inline void record_metric(u32 key, u64 value) {
    u64 *metric = bpf_map_lookup_elem(&metrics, &key);
    if (metric) {
        if (key == METRIC_MAX_PROCESSING_TIME) {
            if (value > *metric) *metric = value;
        } else {
            *metric += value;
        }
    }
}

SEC("tracepoint/syscalls/sys_enter_openat")
int monitored_handler(struct trace_event_raw_sys_enter *ctx) {
    u64 start = bpf_ktime_get_ns();
    
    // Your processing logic
    int result = process_event(ctx);
    
    u64 processing_time = bpf_ktime_get_ns() - start;
    
    // Record metrics
    record_metric(METRIC_EVENTS_PROCESSED, 1);
    record_metric(METRIC_TOTAL_PROCESSING_TIME, processing_time);
    record_metric(METRIC_MAX_PROCESSING_TIME, processing_time);
    
    if (result < 0) {
        record_metric(METRIC_ERRORS, 1);
    }
    
    return 0;
}
```

## 🚀 Deployment Best Practices

### 1. Configuration Management

#### Runtime Configuration
```c
// Configuration map for runtime tuning
struct runtime_config {
    u8 debug_enabled;
    u8 filter_temp_files;
    u32 max_events_per_second;
    u32 max_filename_length;
    char monitored_processes[16][16]; // Up to 16 process names
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct runtime_config);
    __uint(max_entries, 1);
} config SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int configurable_handler(struct trace_event_raw_sys_enter *ctx) {
    u32 key = 0;
    struct runtime_config *cfg = bpf_map_lookup_elem(&config, &key);
    if (!cfg) return 0; // No configuration available
    
    // Apply runtime configuration
    if (!cfg->debug_enabled && is_debug_event(ctx)) return 0;
    if (cfg->filter_temp_files && is_temp_file(ctx)) return 0;
    
    // Use configured limits
    char filename[256];
    u32 max_len = cfg->max_filename_length;
    if (max_len > sizeof(filename)) max_len = sizeof(filename);
    
    bpf_probe_read_user_str(&filename, max_len, (void *)ctx->args[1]);
    
    return 0;
}
```

#### Go Configuration Management
```go
type Config struct {
    DebugEnabled      bool   `yaml:"debug_enabled"`
    FilterTempFiles   bool   `yaml:"filter_temp_files"`
    MaxEventsPerSec   uint32 `yaml:"max_events_per_second"`
    MaxFilenameLength uint32 `yaml:"max_filename_length"`
    MonitoredProcs    []string `yaml:"monitored_processes"`
}

func UpdateBPFConfig(configMap *ebpf.Map, cfg *Config) error {
    runtimeConfig := RuntimeConfig{
        DebugEnabled:      boolToByte(cfg.DebugEnabled),
        FilterTempFiles:   boolToByte(cfg.FilterTempFiles),
        MaxEventsPerSec:   cfg.MaxEventsPerSec,
        MaxFilenameLength: cfg.MaxFilenameLength,
    }
    
    // Copy monitored processes
    for i, proc := range cfg.MonitoredProcs {
        if i >= 16 { break } // Limit in eBPF program
        copy(runtimeConfig.MonitoredProcesses[i][:], proc)
    }
    
    return configMap.Update(uint32(0), &runtimeConfig, ebpf.UpdateAny)
}
```

### 2. Graceful Shutdown

#### Proper Resource Cleanup
```go
func RunMonitor(ctx context.Context) error {
    // Load eBPF program
    objs := monitorObjects{}
    if err := loadMonitorObjects(&objs, nil); err != nil {
        return fmt.Errorf("loading objects: %w", err)
    }
    defer objs.Close() // Ensure cleanup
    
    // Attach to tracepoint
    l, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.MonitorOpenat, nil)
    if err != nil {
        return fmt.Errorf("attaching tracepoint: %w", err)
    }
    defer l.Close() // Ensure detachment
    
    // Set up ring buffer reader
    reader, err := ringbuf.NewReader(objs.Events)
    if err != nil {
        return fmt.Errorf("creating ring buffer reader: %w", err)
    }
    defer reader.Close() // Ensure cleanup
    
    // Graceful shutdown on context cancellation
    go func() {
        <-ctx.Done()
        reader.Close() // Trigger shutdown
    }()
    
    // Main event loop
    for {
        record, err := reader.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                log.Println("Shutting down gracefully...")
                return nil
            }
            return fmt.Errorf("reading from ring buffer: %w", err)
        }
        
        if err := processEvent(record.RawSample); err != nil {
            log.Printf("Error processing event: %v", err)
            // Continue processing other events
        }
    }
}
```

## 📋 Code Review Checklist

### eBPF Program Review
- [ ] **Error handling**: All map operations and helper calls checked
- [ ] **Memory safety**: Only safe helper functions used for memory access
- [ ] **Bounds checking**: Array accesses are bounded
- [ ] **Resource limits**: Maps have appropriate max_entries
- [ ] **Performance**: No unnecessary operations in hot paths
- [ ] **Security**: No sensitive data exposure
- [ ] **Termination**: No unbounded loops

### Go Application Review  
- [ ] **Resource cleanup**: All eBPF resources properly closed
- [ ] **Error handling**: Comprehensive error checking and logging
- [ ] **Graceful shutdown**: Context cancellation handled properly
- [ ] **Input validation**: User inputs sanitized and validated
- [ ] **Configuration**: Runtime configuration supported where appropriate
- [ ] **Testing**: Unit and integration tests included
- [ ] **Documentation**: Code is well-documented

Following these best practices will help you build robust, secure, and maintainable eBPF applications that perform well in production environments! 🚀