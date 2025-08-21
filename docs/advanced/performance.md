# Performance Optimization

Learn how to build high-performance eBPF tools that can handle production workloads with minimal overhead. This guide covers optimization techniques for both eBPF programs and userspace applications.

## 🎯 Performance Goals

Well-optimized eBPF tools should achieve:

- **< 1% CPU overhead** even under heavy load
- **< 10MB memory usage** for userspace components
- **< 100ns latency** added to monitored operations
- **> 1M events/second** processing capability

## 🔧 eBPF Program Optimizations

### 1. Minimize Program Complexity

#### Reduce Instructions
```c
// ❌ Inefficient: Multiple helper calls
int trace_exec(void *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid & 0xFFFFFFFF;
    u32 tgid = pid_tgid >> 32;
    
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) return 0;
    
    data->pid = pid;
    data->tgid = tgid;
    // ...
}

// ✅ Efficient: Single call, direct assignment
int trace_exec(void *ctx) {
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid & 0xFFFFFFFF;
    data->tgid = pid_tgid >> 32;
    // ...
}
```

#### Optimize Data Structures
```c
// ❌ Inefficient: Large, sparse structure
struct inefficient_data {
    u32 pid;
    char padding1[60];    // Wasted space
    u64 timestamp;
    char padding2[120];   // More waste
    char comm[16];
};

// ✅ Efficient: Packed, minimal structure
struct efficient_data {
    u32 pid;
    u32 tgid;            // Use all 32 bits
    u64 timestamp;
    char comm[16];
} __attribute__((packed));
```

### 2. Early Filtering

Filter events in kernel space to reduce userspace processing:

```c
// Configuration map for filters
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct filter_config);
    __uint(max_entries, 1);
} config SEC(".maps");

struct filter_config {
    u32 target_pid;      // 0 = no filter
    u8 target_comm[16];  // Empty = no filter
    u8 enable_filter;    // 0/1
};

SEC("tracepoint/sched/sched_process_exec")
int trace_exec_filtered(void *ctx) {
    // Get filter configuration
    u32 key = 0;
    struct filter_config *cfg = bpf_map_lookup_elem(&config, &key);
    if (!cfg || !cfg->enable_filter) {
        goto process_event;  // No filtering
    }
    
    // PID filtering
    if (cfg->target_pid != 0) {
        u32 current_pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
        if (current_pid != cfg->target_pid) {
            return 0;  // Skip this event
        }
    }
    
    // Command filtering
    if (cfg->target_comm[0] != '\0') {
        char current_comm[16];
        bpf_get_current_comm(&current_comm, sizeof(current_comm));
        
        // Simple string comparison
        bool match = true;
        for (int i = 0; i < 16; i++) {
            if (current_comm[i] != cfg->target_comm[i]) {
                match = false;
                break;
            }
            if (current_comm[i] == '\0') break;
        }
        
        if (!match) return 0;  // Skip this event
    }
    
process_event:
    // Process the event normally
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    // ... rest of processing
    return 0;
}
```

### 3. Efficient Memory Access

#### Use Appropriate Helper Functions
```c
// ❌ Slow: Multiple memory accesses
int get_process_info(struct data_t *data) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // These require multiple probe_read calls
    bpf_probe_read(&data->pid, sizeof(data->pid), &task->pid);
    bpf_probe_read(&data->tgid, sizeof(data->tgid), &task->tgid);
    bpf_probe_read(&data->comm, sizeof(data->comm), &task->comm);
    return 0;
}

// ✅ Fast: Use helper functions when available
int get_process_info_fast(struct data_t *data) {
    u64 pid_tgid = bpf_get_current_pid_tgid();  // Single helper call
    data->pid = pid_tgid & 0xFFFFFFFF;
    data->tgid = pid_tgid >> 32;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));  // Optimized helper
    return 0;
}
```

#### Minimize String Operations
```c
// ❌ Expensive: String operations in eBPF
int expensive_string_ops(char *filename) {
    char prefix[] = "/tmp/";
    
    // Avoid complex string operations
    if (my_strncmp(filename, prefix, 5) == 0) {
        // This is expensive in eBPF
    }
    return 0;
}

// ✅ Efficient: Simple byte comparisons
int efficient_path_check(char *filename) {
    // Direct byte comparison
    if (filename[0] == '/' && 
        filename[1] == 't' && 
        filename[2] == 'm' && 
        filename[3] == 'p' && 
        filename[4] == '/') {
        // Match found
    }
    return 0;
}
```

### 4. Optimize Map Operations

#### Choose Right Map Type
```c
// For frequent lookups with known keys
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);        // O(1) lookup
    __uint(max_entries, 1024);
} fast_array SEC(".maps");

// For dynamic keys with good distribution
struct {
    __uint(type, BPF_MAP_TYPE_HASH);         // O(1) average
    __uint(max_entries, 10000);
} dynamic_hash SEC(".maps");

// For ordered data or statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // Per-CPU, no locks
    __uint(max_entries, 256);
} stats_array SEC(".maps");
```

#### Batch Map Operations
```c
// ❌ Multiple individual updates
for (int i = 0; i < 10; i++) {
    bpf_map_update_elem(&counters, &keys[i], &values[i], BPF_ANY);
}

// ✅ Batch operation (when available)
bpf_map_update_batch(&counters, keys, values, &count, BPF_ANY);
```

## 📊 Ring Buffer Optimizations

### 1. Right-Size Your Buffers

```c
// Buffer sizing guidelines
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);    // 16MB - high-frequency events
} high_freq_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);    // 1MB - medium-frequency events
} medium_freq_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);    // 64KB - low-frequency events
} low_freq_events SEC(".maps");
```

### 2. Minimize Event Size

```c
// ❌ Large events (slow)
struct bloated_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 gid;
    char comm[16];
    char filename[4096];    // Often mostly empty
    u8 padding[512];        // Waste
};

// ✅ Compact events (fast)
struct compact_event {
    u32 pid;               // Most important data first
    u32 timestamp_delta;   // Delta from base time
    u16 filename_len;      // Actual length
    char comm[16];
    char filename[];       // Variable length
};
```

### 3. Efficient Ring Buffer Usage

```c
// ✅ Efficient event submission
int submit_compact_event(char *filename, u16 filename_len) {
    // Calculate actual size needed
    u32 event_size = sizeof(struct compact_event) + filename_len;
    
    struct compact_event *event = bpf_ringbuf_reserve(&events, event_size, 0);
    if (!event) return 0;
    
    // Fill data efficiently
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->timestamp_delta = get_time_delta();
    event->filename_len = filename_len;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Copy only needed bytes
    bpf_probe_read_user_str(&event->filename, filename_len, filename);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

## ⚡ Userspace Optimizations

### 1. Efficient Event Processing

```go
// ✅ Optimized event reader with batching
type OptimizedEventProcessor struct {
    reader        *ringbuf.Reader
    eventBuffer   []RawEvent
    processBuffer []ProcessedEvent
    batchSize     int
}

func (p *OptimizedEventProcessor) ProcessEvents(ctx context.Context) error {
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }
        
        // Read events in batches
        events, err := p.readEventBatch()
        if err != nil {
            return err
        }
        
        if len(events) == 0 {
            continue
        }
        
        // Process batch efficiently
        processed := p.processBatch(events)
        
        // Output batch
        p.outputBatch(processed)
    }
}

func (p *OptimizedEventProcessor) readEventBatch() ([]RawEvent, error) {
    p.eventBuffer = p.eventBuffer[:0] // Reuse slice
    
    for len(p.eventBuffer) < p.batchSize {
        record, err := p.reader.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                break
            }
            return nil, err
        }
        
        var event RawEvent
        if err := binary.Read(bytes.NewReader(record.RawSample), 
                             binary.LittleEndian, &event); err != nil {
            continue // Skip malformed events
        }
        
        p.eventBuffer = append(p.eventBuffer, event)
    }
    
    return p.eventBuffer, nil
}
```

### 2. Memory Pool for Events

```go
// Event pool to reduce GC pressure
var eventPool = sync.Pool{
    New: func() interface{} {
        return &ProcessedEvent{}
    },
}

type ProcessedEvent struct {
    PID       uint32
    Comm      string
    Filename  string
    Timestamp time.Time
}

func (p *OptimizedEventProcessor) processBatch(rawEvents []RawEvent) []*ProcessedEvent {
    processed := make([]*ProcessedEvent, 0, len(rawEvents))
    
    for _, raw := range rawEvents {
        // Get from pool instead of allocating
        event := eventPool.Get().(*ProcessedEvent)
        
        // Reset and populate
        *event = ProcessedEvent{
            PID:       raw.PID,
            Comm:      nullTerminatedString(raw.Comm[:]),
            Filename:  nullTerminatedString(raw.Filename[:]),
            Timestamp: time.Unix(0, int64(raw.Timestamp)),
        }
        
        processed = append(processed, event)
    }
    
    return processed
}

// Return events to pool when done
func (p *OptimizedEventProcessor) cleanup(events []*ProcessedEvent) {
    for _, event := range events {
        eventPool.Put(event)
    }
}
```

### 3. Efficient String Handling

```go
// ✅ Optimized string conversion
func nullTerminatedString(b []byte) string {
    // Find null terminator without allocation
    for i, c := range b {
        if c == 0 {
            return string(b[:i])
        }
    }
    return string(b)
}

// ✅ String interning for repeated values
type StringInterner struct {
    mu      sync.RWMutex
    strings map[string]string
}

func (s *StringInterner) Intern(str string) string {
    s.mu.RLock()
    if interned, exists := s.strings[str]; exists {
        s.mu.RUnlock()
        return interned
    }
    s.mu.RUnlock()
    
    s.mu.Lock()
    defer s.mu.Unlock()
    
    // Double-check after acquiring write lock
    if interned, exists := s.strings[str]; exists {
        return interned
    }
    
    s.strings[str] = str
    return str
}
```

## 📈 Performance Monitoring

### 1. Measure eBPF Program Performance

```c
// Add performance counters
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 16);
} perf_stats SEC(".maps");

enum {
    STAT_EVENTS_PROCESSED = 0,
    STAT_EVENTS_DROPPED,
    STAT_TOTAL_PROCESSING_TIME,
    STAT_MAX_PROCESSING_TIME,
};

SEC("tracepoint/sched/sched_process_exec")
int trace_exec_with_stats(void *ctx) {
    u64 start_time = bpf_ktime_get_ns();
    
    // Increment event counter
    u32 key = STAT_EVENTS_PROCESSED;
    u64 *counter = bpf_map_lookup_elem(&perf_stats, &key);
    if (counter) {
        (*counter)++;
    }
    
    // Your event processing here
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) {
        // Increment drop counter
        key = STAT_EVENTS_DROPPED;
        counter = bpf_map_lookup_elem(&perf_stats, &key);
        if (counter) {
            (*counter)++;
        }
        return 0;
    }
    
    // Process event...
    bpf_ringbuf_submit(data, 0);
    
    // Record processing time
    u64 processing_time = bpf_ktime_get_ns() - start_time;
    key = STAT_TOTAL_PROCESSING_TIME;
    counter = bpf_map_lookup_elem(&perf_stats, &key);
    if (counter) {
        (*counter) += processing_time;
    }
    
    return 0;
}
```

### 2. Monitor Userspace Performance

```go
type PerformanceMetrics struct {
    EventsProcessed   uint64
    EventsDropped     uint64
    ProcessingTimeNs  uint64
    MemoryUsage       uint64
    GCPauses          uint64
}

func (p *OptimizedEventProcessor) GetMetrics() PerformanceMetrics {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    
    return PerformanceMetrics{
        EventsProcessed:  atomic.LoadUint64(&p.eventsProcessed),
        EventsDropped:    atomic.LoadUint64(&p.eventsDropped),
        ProcessingTimeNs: atomic.LoadUint64(&p.processingTimeNs),
        MemoryUsage:      m.Alloc,
        GCPauses:         m.NumGC,
    }
}
```

## 🎯 Benchmarking

### 1. Create Performance Tests

```go
func BenchmarkEventProcessing(b *testing.B) {
    processor := NewOptimizedEventProcessor()
    
    // Generate test events
    events := generateTestEvents(1000)
    
    b.ResetTimer()
    b.ReportAllocs()
    
    for i := 0; i < b.N; i++ {
        processor.processBatch(events)
    }
}

func BenchmarkStringConversion(b *testing.B) {
    testData := []byte("test_process_name\x00\x00\x00")
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _ = nullTerminatedString(testData)
    }
}
```

### 2. Production Monitoring

```bash
#!/bin/bash
# Monitor eBPF program performance

echo "eBPF Program Statistics:"
bpftool prog show | grep your_program

echo "Ring Buffer Usage:"
bpftool map show | grep events

echo "System Impact:"
top -p $(pgrep your_tool) -n 1

echo "Memory Usage:"
ps -o pid,vsz,rss,comm -p $(pgrep your_tool)
```

## 🔧 Optimization Checklist

### eBPF Program
- [ ] Minimize program instructions
- [ ] Use efficient data structures
- [ ] Implement early filtering
- [ ] Choose appropriate map types
- [ ] Minimize string operations
- [ ] Use helper functions when available

### Ring Buffers
- [ ] Right-size buffers for workload
- [ ] Minimize event structure size
- [ ] Use variable-length events when appropriate
- [ ] Batch operations when possible

### Userspace Application
- [ ] Process events in batches
- [ ] Use memory pools for frequent allocations
- [ ] Implement string interning for repeated values
- [ ] Monitor GC pressure and tune accordingly

### Monitoring
- [ ] Add performance counters to eBPF programs
- [ ] Monitor ring buffer utilization
- [ ] Track processing latency and throughput
- [ ] Monitor system resource usage

## 📊 Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| **CPU Overhead** | < 1% | Under normal load |
| **Memory Usage** | < 10MB | Userspace component |
| **Event Latency** | < 100ns | Added to monitored operations |
| **Throughput** | > 1M events/sec | On modern hardware |
| **Ring Buffer Utilization** | < 80% | Prevent drops |
| **GC Pauses** | < 1ms | Go application |

Following these optimization techniques will help you build eBPF tools that can handle production workloads efficiently! 🚀