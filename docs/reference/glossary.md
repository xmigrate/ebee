# eBPF Glossary

Comprehensive glossary of eBPF terms, concepts, and acronyms. Use this as a quick reference when learning eBPF development.

## 📚 Core Concepts

### **eBPF (extended Berkeley Packet Filter)**
A revolutionary technology that allows running sandboxed programs in the Linux kernel without changing kernel source code. Originally designed for packet filtering, now used for observability, security, networking, and more.

### **BPF Virtual Machine**
The in-kernel virtual machine that executes eBPF programs. It provides a safe execution environment with its own instruction set, register model, and memory management.

### **Verifier**
The kernel component that analyzes eBPF programs before loading to ensure they are safe to run in kernel space. It performs static analysis to prevent crashes, infinite loops, and unauthorized memory access.

### **JIT (Just-In-Time) Compilation**
The process of compiling eBPF bytecode to native machine code for better performance. Most modern kernels include eBPF JIT compilers for various architectures.

### **BTF (BPF Type Format)**
A metadata format that provides type information for eBPF programs and kernel data structures. Enables type-aware debugging, pretty printing, and safe access to kernel data.

## 🗺️ Maps and Data Structures

### **eBPF Map**
A data structure that allows sharing data between eBPF programs and userspace applications, or between multiple eBPF programs. Maps persist beyond individual program invocations.

### **Hash Map (BPF_MAP_TYPE_HASH)**
Key-value store with O(1) average lookup time. Good for dynamic keys with unknown size at compile time.
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1024);
} my_hash SEC(".maps");
```

### **Array Map (BPF_MAP_TYPE_ARRAY)**
Fixed-size indexed array with O(1) lookup time. Keys are indices from 0 to max_entries-1.
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 256);
} my_array SEC(".maps");
```

### **Ring Buffer (BPF_MAP_TYPE_RINGBUF)**
High-performance, zero-copy mechanism for streaming data from kernel to userspace. Preferred over perf buffers for most use cases.

### **Per-CPU Map**
Map type that maintains separate instances per CPU core, avoiding locking overhead. Values are automatically aggregated when read from userspace.

### **LRU (Least Recently Used) Map**
Map that automatically evicts oldest entries when full. Useful for caching scenarios where you want bounded memory usage.

### **Perf Buffer (Deprecated)**
Older mechanism for kernel-to-userspace communication, largely replaced by ring buffers. Still supported but ring buffers are preferred.

## 🔗 Program Types and Attachment

### **Program Type**
Defines what kind of kernel events an eBPF program can attach to and what helper functions it can use. Examples: BPF_PROG_TYPE_TRACEPOINT, BPF_PROG_TYPE_XDP, BPF_PROG_TYPE_KPROBE.

### **Tracepoint**
Static instrumentation points in the kernel that provide stable ABI for observing kernel events. Defined using TRACE_EVENT() macro in kernel source.
```c
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    return 0;
}
```

### **Kprobe (Kernel Probe)**
Dynamic instrumentation that can attach to (almost) any kernel function. More flexible than tracepoints but less stable across kernel versions.
```c
SEC("kprobe/do_sys_openat2")
int kprobe_openat(struct pt_regs *ctx) {
    return 0;
}
```

### **Kretprobe (Kernel Return Probe)**
Kprobe variant that triggers when a function returns, allowing access to return values.
```c
SEC("kretprobe/do_sys_openat2")
int kretprobe_openat(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx); // Get return value
    return 0;
}
```

### **Uprobe (User Probe)**
Dynamic instrumentation for userspace functions. Allows tracing application functions without modifying the application.

### **Raw Tracepoint**
More efficient tracepoint variant that provides direct access to tracepoint arguments without additional processing overhead.

### **XDP (eXpress Data Path)**
Program type for high-performance packet processing at the driver level, before the packet enters the network stack.

### **TC (Traffic Control)**
Program type for packet processing at the traffic control layer, allowing packet modification, redirection, or dropping.

### **LSM (Linux Security Module)**
Program type for implementing custom security policies by hooking into LSM framework.

### **Seccomp**
Program type for filtering system calls in a process, allowing fine-grained control over what system calls a process can make.

### **Cgroup**
Program types for implementing per-cgroup policies for device access, socket operations, and other resource controls.

## 🛠️ Development Tools

### **bpftool**
The primary tool for inspecting and manipulating eBPF programs and maps. Part of the Linux kernel source tree.
```bash
sudo bpftool prog list        # List loaded programs
sudo bpftool map dump id 1    # Dump map contents
```

### **bpf2go**
Code generation tool from Cilium's eBPF library that generates Go bindings from eBPF C programs.
```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native program ../bpf/program.c
```

### **LLVM/Clang**
Compiler toolchain used to compile eBPF C programs to eBPF bytecode. Clang with BPF target support is required.
```bash
clang -O2 -target bpf -c program.c -o program.o
```

### **bpftrace**
High-level tracing language and tool for ad-hoc eBPF program creation. Good for quick debugging and exploration.
```bash
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("open: %s\n", str(args->filename)); }'
```

### **BCC (BPF Compiler Collection)**
Python and C++ framework for creating eBPF applications. Includes many pre-built tools for system analysis.

## 🔧 Helper Functions

### **Helper Function**
Kernel functions that eBPF programs can call to interact with the kernel safely. Each program type has access to different sets of helpers.

### **bpf_get_current_pid_tgid()**
Returns combined PID and thread group ID of the current process.
```c
u64 pid_tgid = bpf_get_current_pid_tgid();
u32 pid = pid_tgid & 0xFFFFFFFF;
u32 tgid = pid_tgid >> 32;
```

### **bpf_probe_read_kernel()**
Safely reads data from kernel memory addresses. Required for accessing kernel data structures.
```c
int value;
bpf_probe_read_kernel(&value, sizeof(value), kernel_ptr);
```

### **bpf_probe_read_user()**
Safely reads data from user space memory addresses.
```c
char buffer[256];
bpf_probe_read_user(&buffer, sizeof(buffer), user_ptr);
```

### **bpf_get_current_comm()**
Gets the command name (process name) of the current process.
```c
char comm[16];
bpf_get_current_comm(&comm, sizeof(comm));
```

### **bpf_ktime_get_ns()**
Returns current kernel time in nanoseconds since system boot.
```c
u64 timestamp = bpf_ktime_get_ns();
```

### **bpf_trace_printk() / bpf_printk()**
Debugging function that prints to kernel trace buffer. Only for development, not production.
```c
bpf_printk("Debug: PID %d\n", pid);
```

## 🎯 Contexts and Events

### **Program Context**
The input parameter passed to eBPF programs, containing information about the event that triggered the program. Type depends on program type.

### **pt_regs**
Structure containing CPU register values at the time of a kprobe/uprobe event. Used to access function arguments and return values.
```c
SEC("kprobe/sys_openat")
int kprobe_openat(struct pt_regs *ctx) {
    int dfd = PT_REGS_PARM1(ctx);        // First argument
    char *filename = PT_REGS_PARM2(ctx);  // Second argument
    return 0;
}
```

### **Tracepoint Context**
Structure specific to each tracepoint, containing the arguments passed to that tracepoint.
```c
struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long args[6];  // System call arguments
};
```

### **XDP Context**
Structure containing packet data and metadata for XDP programs.
```c
struct xdp_md {
    __u32 data;         // Start of packet data
    __u32 data_end;     // End of packet data
    __u32 data_meta;    // Metadata area
    __u32 ingress_ifindex;  // Incoming interface
    __u32 rx_queue_index;   // RX queue number
};
```

## 🔍 Verification and Safety

### **Static Analysis**
The process of analyzing eBPF programs at load time to ensure safety. The verifier performs control flow analysis, bounds checking, and type checking.

### **Bounded Loops**
eBPF programs cannot contain unbounded loops. The verifier ensures all loops have a maximum iteration count that can be determined at verification time.

### **Stack Limit**
eBPF programs have a limited stack size (512 bytes). Large data structures must be allocated in maps or the heap.

### **Instruction Limit**
eBPF programs are limited to approximately 1 million instructions to ensure they complete in bounded time.

### **Memory Safety**
The verifier ensures eBPF programs cannot access arbitrary memory addresses. All memory access must go through helper functions or verified safe operations.

## 🌐 Networking Terms

### **Socket Filter**
eBPF program type that can filter packets on sockets, similar to tcpdump filters but more powerful.

### **Traffic Control (TC)**
Linux subsystem for controlling network traffic. eBPF programs can be attached as TC classifiers or actions.

### **Network Namespace**
Kernel feature that provides network isolation. eBPF programs can be namespace-aware.

### **Packet Parsing**
The process of examining packet headers (Ethernet, IP, TCP, etc.) in networking eBPF programs.

### **Direct Packet Access**
Feature allowing eBPF programs to directly read/write packet data for high performance.

## 🔐 Security Terms

### **Capability**
Linux security feature that divides root privileges into discrete units. eBPF requires CAP_BPF (Linux 5.8+) or CAP_SYS_ADMIN.

### **LSM Hook**
Linux Security Module attachment point where eBPF programs can implement custom security policies.

### **Privileged Mode**
Mode where eBPF programs have access to additional helper functions and capabilities. Requires higher privileges.

### **Unprivileged eBPF**
Mode where regular users can load certain types of eBPF programs with restricted functionality. Often disabled by default.

## 📊 Performance Terms

### **Zero-Copy**
Data transfer mechanism that avoids copying data between kernel and userspace, improving performance.

### **Per-CPU**
Data structures that maintain separate instances per CPU core to avoid locking and improve performance.

### **Lock-Free**
Programming technique that avoids locks for better performance in concurrent scenarios.

### **Ring Buffer Overhead**
The additional CPU and memory cost of transferring data from kernel to userspace via ring buffers.

### **JIT Compilation**
Converting eBPF bytecode to native machine instructions for better runtime performance.

## 🔄 Program Lifecycle

### **Load**
The process of uploading eBPF bytecode to the kernel and passing verification.

### **Attach**
Connecting a loaded eBPF program to a specific kernel hook (tracepoint, kprobe, etc.).

### **Detach**
Disconnecting an eBPF program from its attachment point.

### **Unload**
Removing an eBPF program from the kernel, freeing its resources.

### **Pin**
Making an eBPF program or map persistent in the filesystem so it survives beyond the loading process.

### **Link**
Kernel object that represents the attachment between an eBPF program and its hook point.

## 🏗️ Architecture Terms

### **Userspace**
The portion of the system where regular applications run, outside the kernel.

### **Kernel Space**
The privileged portion of the system where the operating system kernel runs.

### **System Call (Syscall)**
Interface between userspace applications and the kernel for requesting services.

### **Kernel Module**
Loadable code that extends kernel functionality. eBPF provides an alternative to kernel modules for many use cases.

### **Driver**
Kernel code that manages hardware devices. XDP programs can run at the driver level.

### **Network Stack**
The kernel subsystem responsible for processing network packets.

## 📝 File and Data Formats

### **ELF (Executable and Linkable Format)**
Binary file format used for eBPF programs. eBPF programs are compiled to ELF files containing BPF sections.

### **BTF Section**
ELF section containing BPF Type Format information for type-aware operations.

### **Maps Section**
ELF section defining eBPF maps used by the program.

### **License Section**
ELF section specifying the license of the eBPF program (usually "GPL").

### **vmlinux.h**
Generated header file containing all kernel type definitions, created from BTF information.

## 🎛️ Configuration and Tuning

### **Map Flags**
Options that control map behavior, such as BPF_F_NO_PREALLOC for lazy allocation.

### **Program Flags**
Options that control program loading and behavior.

### **Update Flags**
Options for map update operations: BPF_ANY, BPF_NOEXIST, BPF_EXIST.

### **Attach Flags**
Options that control how programs attach to their hooks.

## 📈 Monitoring and Debugging

### **Trace Pipe**
Kernel interface for reading debug output from bpf_printk() calls.
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### **Verifier Log**
Detailed output from the eBPF verifier showing why a program failed to load.

### **Program Statistics**
Runtime statistics about eBPF program execution collected by the kernel.

### **Map Statistics**
Information about map usage, including current size and access patterns.

## 🔤 Common Abbreviations

- **ABI**: Application Binary Interface
- **API**: Application Programming Interface  
- **BPF**: Berkeley Packet Filter
- **BTF**: BPF Type Format
- **CPU**: Central Processing Unit
- **eBPF**: extended Berkeley Packet Filter
- **ELF**: Executable and Linkable Format
- **GID**: Group ID
- **IP**: Internet Protocol
- **JIT**: Just-In-Time (compilation)
- **LSM**: Linux Security Module
- **LRU**: Least Recently Used
- **PID**: Process ID
- **QoS**: Quality of Service
- **SKB**: Socket Buffer
- **TCP**: Transmission Control Protocol
- **TGID**: Thread Group ID
- **UDP**: User Datagram Protocol
- **UID**: User ID
- **VFS**: Virtual File System
- **VM**: Virtual Machine
- **XDP**: eXpress Data Path

## 📚 Related Technologies

### **Cilium**
Kubernetes networking and security platform built on eBPF.

### **Falco**
Runtime security monitoring tool that uses eBPF for system call monitoring.

### **Katran**
Facebook's load balancer built on XDP.

### **Pixie**
Kubernetes observability platform using eBPF for automatic data collection.

### **Tetragon**
Security observability and runtime enforcement platform using eBPF.

## 🎓 Learning Resources

Use this glossary alongside:
- [eBPF Fundamentals](../fundamentals/concepts.md) - Core concepts explained
- [API Reference](api.md) - Detailed function documentation  
- [Best Practices](best-practices.md) - Production guidelines
- [Troubleshooting Guide](troubleshooting.md) - Problem solving

This glossary serves as your quick reference guide to eBPF terminology. Bookmark it and refer back when you encounter unfamiliar terms! 📖