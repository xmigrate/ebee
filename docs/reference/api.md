# API Reference

Complete reference for eBPF helper functions, data structures, and APIs used in this project.

## 🔧 eBPF Helper Functions

### Process Information

#### `bpf_get_current_pid_tgid()`
**Signature**: `u64 bpf_get_current_pid_tgid(void)`  
**Returns**: Combined PID/TGID value (upper 32 bits: TGID, lower 32 bits: PID)  
**Available since**: Linux 3.19

```c
u64 pid_tgid = bpf_get_current_pid_tgid();
u32 pid = pid_tgid & 0xFFFFFFFF;        // Process ID
u32 tgid = pid_tgid >> 32;              // Thread Group ID
```

#### `bpf_get_current_uid_gid()`
**Signature**: `u64 bpf_get_current_uid_gid(void)`  
**Returns**: Combined UID/GID value (upper 32 bits: GID, lower 32 bits: UID)  
**Available since**: Linux 4.2

```c
u64 uid_gid = bpf_get_current_uid_gid();
u32 uid = uid_gid & 0xFFFFFFFF;         // User ID
u32 gid = uid_gid >> 32;                // Group ID
```

#### `bpf_get_current_comm()`
**Signature**: `long bpf_get_current_comm(void *buf, u32 size_of_buf)`  
**Parameters**:
- `buf`: Buffer to store command name
- `size_of_buf`: Size of buffer (typically 16)

**Returns**: 0 on success, negative on error  
**Available since**: Linux 3.19

```c
char comm[16];
if (bpf_get_current_comm(&comm, sizeof(comm)) == 0) {
    // comm now contains process name
}
```

#### `bpf_get_current_task()`
**Signature**: `u64 bpf_get_current_task(void)`  
**Returns**: Pointer to current task_struct  
**Available since**: Linux 4.8

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
// Use with bpf_probe_read_kernel() to access fields safely
```

### Memory Access

#### `bpf_probe_read_kernel()`
**Signature**: `long bpf_probe_read_kernel(void *dst, u32 size, const void *unsafe_ptr)`  
**Parameters**:
- `dst`: Destination buffer
- `size`: Number of bytes to read
- `unsafe_ptr`: Source kernel pointer

**Returns**: 0 on success, negative on error  
**Available since**: Linux 5.5

```c
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
u32 pid;
if (bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid) == 0) {
    // pid is now safely read from kernel memory
}
```

#### `bpf_probe_read_user()`
**Signature**: `long bpf_probe_read_user(void *dst, u32 size, const void *unsafe_ptr)`  
**Parameters**:
- `dst`: Destination buffer
- `size`: Number of bytes to read  
- `unsafe_ptr`: Source user pointer

**Returns**: 0 on success, negative on error  
**Available since**: Linux 5.5

```c
char user_buffer[256];
char *user_ptr = (char *)ctx->args[1];
if (bpf_probe_read_user(&user_buffer, sizeof(user_buffer), user_ptr) == 0) {
    // user_buffer contains data from user space
}
```

#### `bpf_probe_read_user_str()`
**Signature**: `long bpf_probe_read_user_str(void *dst, u32 size, const void *unsafe_ptr)`  
**Parameters**:
- `dst`: Destination buffer
- `size`: Maximum bytes to read
- `unsafe_ptr`: Source user string pointer

**Returns**: String length on success (including null terminator), negative on error  
**Available since**: Linux 4.11

```c
char filename[256];
char *user_filename = (char *)ctx->args[1];
long len = bpf_probe_read_user_str(&filename, sizeof(filename), user_filename);
if (len > 0) {
    // filename contains null-terminated string
}
```

### Time Functions

#### `bpf_ktime_get_ns()`
**Signature**: `u64 bpf_ktime_get_ns(void)`  
**Returns**: Current kernel time in nanoseconds since boot  
**Available since**: Linux 4.1

```c
u64 timestamp = bpf_ktime_get_ns();
// timestamp contains nanoseconds since boot
```

#### `bpf_ktime_get_boot_ns()`
**Signature**: `u64 bpf_ktime_get_boot_ns(void)`  
**Returns**: Current time in nanoseconds since boot (including suspend time)  
**Available since**: Linux 5.8

```c
u64 boot_time = bpf_ktime_get_boot_ns();
// Includes time spent in suspend
```

### Map Operations

#### `bpf_map_lookup_elem()`
**Signature**: `void *bpf_map_lookup_elem(void *map, const void *key)`  
**Parameters**:
- `map`: Map to lookup in
- `key`: Key to search for

**Returns**: Pointer to value if found, NULL if not found  
**Available since**: Linux 3.19

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1024);
} counters SEC(".maps");

u32 pid = 1234;
u64 *counter = bpf_map_lookup_elem(&counters, &pid);
if (counter) {
    (*counter)++;
}
```

#### `bpf_map_update_elem()`
**Signature**: `long bpf_map_update_elem(void *map, const void *key, const void *value, u64 flags)`  
**Parameters**:
- `map`: Map to update
- `key`: Key to update
- `value`: New value
- `flags`: Update flags (BPF_ANY, BPF_NOEXIST, BPF_EXIST)

**Returns**: 0 on success, negative on error  
**Available since**: Linux 3.19

```c
u32 pid = 1234;
u64 count = 1;
long ret = bpf_map_update_elem(&counters, &pid, &count, BPF_ANY);
if (ret == 0) {
    // Update successful
}
```

#### `bpf_map_delete_elem()`
**Signature**: `long bpf_map_delete_elem(void *map, const void *key)`  
**Parameters**:
- `map`: Map to delete from
- `key`: Key to delete

**Returns**: 0 on success, negative on error  
**Available since**: Linux 3.19

```c
u32 pid = 1234;
long ret = bpf_map_delete_elem(&counters, &pid);
if (ret == 0) {
    // Key deleted successfully
}
```

### Ring Buffer Operations

#### `bpf_ringbuf_reserve()`
**Signature**: `void *bpf_ringbuf_reserve(void *ringbuf, u64 size, u64 flags)`  
**Parameters**:
- `ringbuf`: Ring buffer map
- `size`: Size to reserve
- `flags`: Reservation flags (usually 0)

**Returns**: Pointer to reserved space, NULL on failure  
**Available since**: Linux 5.8

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event_data *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
if (data) {
    // Fill data structure
    data->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    // Must call bpf_ringbuf_submit() or bpf_ringbuf_discard()
}
```

#### `bpf_ringbuf_submit()`
**Signature**: `void bpf_ringbuf_submit(void *data, u64 flags)`  
**Parameters**:
- `data`: Data pointer from bpf_ringbuf_reserve()
- `flags`: Submission flags (usually 0)

**Available since**: Linux 5.8

```c
// After filling reserved data
bpf_ringbuf_submit(data, 0);
// Data is now available to userspace
```

#### `bpf_ringbuf_discard()`
**Signature**: `void bpf_ringbuf_discard(void *data, u64 flags)`  
**Parameters**:
- `data`: Data pointer from bpf_ringbuf_reserve()
- `flags`: Discard flags (usually 0)

**Available since**: Linux 5.8

```c
// If you decide not to submit the reserved data
bpf_ringbuf_discard(data, 0);
// Reserved space is freed without sending to userspace
```

### Utility Functions

#### `bpf_get_smp_processor_id()`
**Signature**: `u32 bpf_get_smp_processor_id(void)`  
**Returns**: Current CPU number  
**Available since**: Linux 4.1

```c
u32 cpu = bpf_get_smp_processor_id();
// cpu contains current CPU number (0-based)
```

#### `bpf_trace_printk()`
**Signature**: `long bpf_trace_printk(const char *fmt, u32 fmt_size, ...)`  
**Parameters**:
- `fmt`: Format string
- `fmt_size`: Length of format string
- `...`: Arguments

**Returns**: Number of bytes written, negative on error  
**Available since**: Linux 4.1  
**Note**: For debugging only, not for production

```c
bpf_trace_printk("Process %d opened file\n", 25, pid);
// Output appears in /sys/kernel/debug/tracing/trace_pipe
```

## 📊 eBPF Data Structures

### Common Event Structures

#### Basic Process Event
```c
struct process_event {
    u32 pid;                    // Process ID
    u32 ppid;                   // Parent process ID
    u32 uid;                    // User ID
    u32 gid;                    // Group ID
    char comm[16];              // Process name (kernel limit)
    u64 timestamp;              // Event timestamp (nanoseconds)
} __attribute__((packed));
```

#### File Operation Event
```c
struct file_event {
    u32 pid;                    // Process ID performing operation
    u32 fd;                     // File descriptor (if applicable)
    u32 flags;                  // Open flags
    char comm[16];              // Process name
    char filename[256];         // File path
    u64 timestamp;              // Event timestamp
} __attribute__((packed));
```

#### Network Event
```c
struct network_event {
    u32 pid;                    // Process ID
    u32 src_ip;                 // Source IP (network byte order)
    u32 dst_ip;                 // Destination IP (network byte order)
    u16 src_port;               // Source port (network byte order)
    u16 dst_port;               // Destination port (network byte order)
    u8 protocol;                // Protocol (TCP=6, UDP=17)
    char comm[16];              // Process name
    u64 timestamp;              // Event timestamp
} __attribute__((packed));
```

### Map Definitions

#### Hash Map
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);                    // Key type
    __type(value, struct counter);       // Value type
    __uint(max_entries, 10000);         // Maximum entries
    __uint(map_flags, BPF_F_NO_PREALLOC); // Optional flags
} process_counters SEC(".maps");
```

#### Array Map
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);                    // Index (0 to max_entries-1)
    __type(value, u64);                  // Value type
    __uint(max_entries, 256);            // Array size
} statistics SEC(".maps");
```

#### Ring Buffer Map
```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);        // 16MB buffer
} events SEC(".maps");
```

#### Per-CPU Array
```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);              // One entry per CPU
} per_cpu_stats SEC(".maps");
```

### Program Section Names

#### Tracepoint Programs
```c
SEC("tracepoint/syscalls/sys_enter_openat")    // System call entry
SEC("tracepoint/syscalls/sys_exit_openat")     // System call exit
SEC("tracepoint/sched/sched_process_exec")     // Process execution
SEC("tracepoint/sched/sched_process_exit")     // Process exit
SEC("tracepoint/ext4/ext4_free_inode")         // Filesystem events
```

#### Kprobe Programs
```c
SEC("kprobe/do_sys_openat2")                   // Kernel function entry
SEC("kretprobe/do_sys_openat2")                // Kernel function return
SEC("kprobe/vfs_open")                         // VFS layer function
```

#### Network Programs
```c
SEC("xdp")                                     // XDP program
SEC("tc")                                      // Traffic control
SEC("socket")                                  // Socket filter
SEC("sk_msg")                                  // Socket message
```

## 🔗 Go eBPF Library (Cilium)

### Loading Programs

#### Basic Loading
```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native program ../bpf/program.c

func loadProgram() error {
    objs := programObjects{}
    if err := loadProgramObjects(&objs, nil); err != nil {
        return fmt.Errorf("loading eBPF objects: %w", err)
    }
    defer objs.Close()
    
    // Use objs.ProgramName and objs.MapName
    return nil
}
```

#### Advanced Loading Options
```go
func loadProgramWithOptions() error {
    spec, err := loadProgramSpecs()
    if err != nil {
        return err
    }
    
    // Customize before loading
    spec.Maps["events"].MaxEntries = 32 * 1024 * 1024  // 32MB ring buffer
    
    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        return err
    }
    defer coll.Close()
    
    return nil
}
```

### Map Operations

#### Reading from Maps
```go
func readFromMap(m *ebpf.Map) error {
    var key uint32 = 1234
    var value uint64
    
    if err := m.Lookup(key, &value); err != nil {
        if errors.Is(err, ebpf.ErrKeyNotExist) {
            // Key doesn't exist
            return nil
        }
        return fmt.Errorf("map lookup: %w", err)
    }
    
    fmt.Printf("Value for key %d: %d\n", key, value)
    return nil
}
```

#### Writing to Maps
```go
func writeToMap(m *ebpf.Map) error {
    var key uint32 = 1234
    var value uint64 = 5678
    
    if err := m.Update(key, value, ebpf.UpdateAny); err != nil {
        return fmt.Errorf("map update: %w", err)
    }
    
    return nil
}
```

#### Iterating Maps
```go
func iterateMap(m *ebpf.Map) error {
    var key uint32
    var value uint64
    
    iter := m.Iterate()
    for iter.Next(&key, &value) {
        fmt.Printf("Key: %d, Value: %d\n", key, value)
    }
    
    return iter.Err()
}
```

### Ring Buffer Operations

#### Reading Events
```go
func readRingBuffer(rb *ebpf.Map) error {
    reader, err := ringbuf.NewReader(rb)
    if err != nil {
        return err
    }
    defer reader.Close()
    
    for {
        record, err := reader.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                break
            }
            return err
        }
        
        // Process record.RawSample
        var event ProcessEvent
        if err := binary.Read(bytes.NewReader(record.RawSample), 
                             binary.LittleEndian, &event); err != nil {
            continue
        }
        
        fmt.Printf("Event: PID=%d, Comm=%s\n", 
                  event.PID, nullTerminatedString(event.Comm[:]))
    }
    
    return nil
}
```

### Program Attachment

#### Tracepoint Attachment
```go
func attachTracepoint(prog *ebpf.Program) error {
    l, err := link.Tracepoint("syscalls", "sys_enter_openat", prog, nil)
    if err != nil {
        return fmt.Errorf("attaching tracepoint: %w", err)
    }
    defer l.Close()
    
    // Keep program running
    return nil
}
```

#### Kprobe Attachment
```go
func attachKprobe(prog *ebpf.Program) error {
    l, err := link.Kprobe("do_sys_openat2", prog, nil)
    if err != nil {
        return fmt.Errorf("attaching kprobe: %w", err)
    }
    defer l.Close()
    
    return nil
}
```

## 🔧 Utility Functions

### String Processing
```go
// Convert null-terminated byte array to Go string
func nullTerminatedString(b []byte) string {
    for i, c := range b {
        if c == 0 {
            return string(b[:i])
        }
    }
    return string(b)
}

// Convert Go string to fixed-size byte array
func stringToBytes(s string, size int) []byte {
    b := make([]byte, size)
    copy(b, s)
    return b
}
```

### Time Conversion
```go
// Convert eBPF timestamp (nanoseconds since boot) to Go time
func ebpfTimeToGoTime(ns uint64) time.Time {
    // This is approximate - real implementation would need boot time
    return time.Unix(0, int64(ns))
}

// Get current timestamp in eBPF format
func currentEBPFTime() uint64 {
    return uint64(time.Now().UnixNano())
}
```

### Network Byte Order
```go
// Convert network byte order to host byte order
func ntohl(n uint32) uint32 {
    return binary.BigEndian.Uint32((*[4]byte)(unsafe.Pointer(&n))[:])
}

func ntohs(n uint16) uint16 {
    return binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&n))[:])
}

// Convert host byte order to network byte order
func htonl(h uint32) uint32 {
    b := make([]byte, 4)
    binary.BigEndian.PutUint32(b, h)
    return *(*uint32)(unsafe.Pointer(&b[0]))
}

func htons(h uint16) uint16 {
    b := make([]byte, 2)
    binary.BigEndian.PutUint16(b, h)
    return *(*uint16)(unsafe.Pointer(&b[0]))
}
```

## 📝 Error Codes

### Common eBPF Errors
| Error Code | Description | Common Causes |
|------------|-------------|---------------|
| `-EACCES` | Permission denied | Missing capabilities, wrong program type |
| `-EINVAL` | Invalid argument | Invalid program, map type mismatch |
| `-E2BIG` | Program too large | Exceeds instruction or complexity limits |
| `-ENOENT` | No such entry | Map key doesn't exist, attachment point invalid |
| `-EEXIST` | Entry exists | BPF_NOEXIST flag with existing key |
| `-ENOMEM` | Out of memory | Map full, ring buffer full |
| `-EPERM` | Operation not permitted | Insufficient privileges |

### Verifier Errors
- **R1 invalid mem access**: Direct memory access without helper
- **invalid indirect read from stack**: Uninitialized stack access
- **back-edge from insn X to Y**: Unbounded loop detected
- **unreachable insn**: Dead code after terminating instruction

## 🔍 Debugging Commands

### bpftool Commands
```bash
# List programs and maps
sudo bpftool prog list
sudo bpftool map list

# Show program details
sudo bpftool prog show id <id>
sudo bpftool map show id <id>

# Dump program instructions
sudo bpftool prog dump xlated id <id>
sudo bpftool prog dump jited id <id>

# Dump map contents
sudo bpftool map dump id <id>

# Program statistics
sudo bpftool prog show id <id> --json | jq '.run_cnt, .run_time_ns'
```

### Trace Commands
```bash
# View debug prints
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Clear trace buffer
echo > /sys/kernel/debug/tracing/trace

# Enable/disable tracing
echo 1 > /sys/kernel/debug/tracing/tracing_on
echo 0 > /sys/kernel/debug/tracing/tracing_on
```

This API reference provides comprehensive documentation for all the key functions and data structures used in eBPF development. Use it as a quick reference when building your own eBPF tools! 📚