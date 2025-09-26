# ebee - eBPF the Hard Way!

This repository contains various eBPF tools originally from the BCC project, reimplemented from scratch to help users learn eBPF development step by step.

## 🎯 Project Goal

The idea for this project is to help users learn creating eBPF tools with a comprehensive step-by-step guide. Each tool includes detailed documentation explaining the underlying concepts, kernel hooks, data structures, and implementation details.

## 🧠 What is eBPF?

eBPF (extended Berkeley Packet Filter) is a revolutionary technology that allows you to run sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules. It enables:

- **Real-time system monitoring** - Track processes, files, network activity
- **Performance analysis** - Measure latency, throughput, resource usage  
- **Security monitoring** - Detect malicious behavior and policy violations
- **Custom debugging** - Create tailored debugging tools for your applications

## 🎓 What You'll Learn

By working through this project, you'll gain hands-on experience with:

- **eBPF fundamentals** - Understanding the eBPF virtual machine and verifier
- **Kernel programming** - Writing C programs that run in kernel space
- **Tracepoints and kprobes** - Hooking into kernel events and functions
- **Data structures** - Using eBPF maps for efficient data sharing
- **Go integration** - Building userspace applications with the Cilium eBPF library
- **Performance optimization** - Creating efficient monitoring tools
- **Security analysis** - Building tools for system security and compliance

## ⚙️ Prerequisites

### System Requirements
- **Linux Kernel**: 4.18+ (5.0+ recommended for full feature support)
- **Architecture**: x86_64, arm64
- **BTF Support**: Required for modern eBPF development
- **Root Access**: Required for loading eBPF programs

## 🚀 Quick Start

### Prerequisites Setup

#### Linux
```bash
# Install all requirements using the Makefile
make install
```

#### macOS
Since eBPF development requires Linux kernel headers and tools, we use Lima to run Ubuntu:

```bash
# Install/upgrade Lima + guest agents
brew install lima lima-additional-guestagents || brew upgrade lima lima-additional-guestagents

# Start Ubuntu VM with our configuration
limactl start scripts/default.yaml --name=default --timeout 30m

# Connect to the VM
limactl shell default

# Now run the Linux setup
make install
```

### Build ebee

```bash
# Generate kernel headers (required for eBPF development)
make gen_vmlinux

# Install dependencies and build
make deps
make build
```

## 🔧 Quick Examples

```bash
# Monitor all process executions
sudo ./ebee execsnoop

# Monitor file deletions  
sudo ./ebee rmdetect

# Filter by specific process
sudo ./ebee execsnoop --comm bash
```

## 📚 Available Tools

| Tool | Status | Category | Description | Kernel Hook |
|------|--------|----------|-------------|-------------|
| **execsnoop** | ✅ Available | Process Monitoring | Monitor process executions in real-time | `sched_process_exec` tracepoint |
| **rmdetect** | ✅ Available | File System | Monitor file deletions in real-time | `ext4_free_inode` tracepoint |
| **opensnoop** | 🚧 Planned | File System | Monitor file opens in real-time | `vfs_open` kprobe |
| **tcpconnect** | 🚧 Planned | Network | Monitor TCP connections | `tcp_connect` kprobe |
| **tcpaccept** | 🚧 Planned | Network | Monitor TCP accepts | `tcp_accept` kprobe |
| **biolatency** | 🚧 Planned | Storage | Monitor block I/O latency | `block_rq_insert/complete` |
| **syscount** | 🚧 Planned | System | Count system calls by process | syscall tracepoints |
| **funclatency** | 🚧 Planned | Performance | Measure function latency | kprobes/kretprobes |
| **stackcount** | 🚧 Planned | Performance | Count stack traces | perf events |
| **profile** | 🚧 Planned | Performance | CPU profiling | perf events |

### Tool Categories

- **Process Monitoring** - Track process lifecycle and execution
- **File System** - Monitor file operations and changes  
- **Network** - Analyze network connections and traffic
- **Storage** - Monitor disk I/O and storage performance
- **System** - Track system calls and kernel events
- **Performance** - Measure latency, throughput, and resource usage

Each tool includes comprehensive documentation in the `docs/` folder with implementation details, usage examples, and troubleshooting guides.

## 🛠️ Development

### Adding New Commands

1. **Create the eBPF C program** in `bpf/your_tool.c`
2. **Create the Go command** in `cmd/your_tool.go`
3. **Update Makefile** generate target to include your C file
4. **Add documentation** in `docs/your_tool.md` following the template
5. **Update this README** to include your new tool

### Documentation Structure

Each tool should include:
- **What it does** - Purpose and use cases
- **How it works** - Technical implementation details
- **Kernel hooks used** - Which tracepoints/kprobes are attached
- **Data structures** - eBPF maps and event structures
- **Step-by-step guide** - Implementation walkthrough
- **Usage examples** - Command-line examples

## 📖 Documentation

Comprehensive documentation covering everything from basics to advanced production deployment:

### 📚 **Learning Materials**
- **[Complete Documentation](docs/)** - Full learning guide
- **[Getting Started](docs/getting-started/what-is-ebpf.md)** - Environment setup and eBPF introduction
- **[Core Concepts](docs/fundamentals/concepts.md)** - eBPF fundamentals and architecture
- **[First Tool Tutorial](docs/first-tool/architecture.md)** - Step-by-step tool creation

### 🚀 **Advanced Topics**
- **[CO-RE & BTF](docs/advanced/core-btf.md)** - Portable eBPF development with CO-RE
- **[Network Programming](docs/advanced/network-ebpf.md)** - XDP, TC, packet processing
- **[Security Monitoring](docs/advanced/security-monitoring.md)** - LSM hooks, security events
- **[Testing Strategies](docs/advanced/testing.md)** - Unit/integration testing frameworks
- **[Performance Optimization](docs/advanced/performance.md)** - Production optimization techniques

### 🛠️ **Tool Documentation**
- **[execsnoop](docs/tools/execsnoop.md)** - Process execution monitoring
- **[rmdetect](docs/tools/rmdetect.md)** - File deletion detection
- **[Network Tools](docs/advanced/network-ebpf.md)** - DDoS protection, load balancing
- **[Security Tools](docs/advanced/security-monitoring.md)** - File access, process monitoring

### 📋 **Reference & Troubleshooting**
- **[Troubleshooting Guide](docs/reference/troubleshooting.md)** - Debug techniques, common issues
- **[Best Practices](docs/reference/best-practices.md)** - Production deployment patterns
- **[API Reference](docs/reference/api.md)** - Helper functions and APIs

## 🏗️ Project Structure

```
ebee/
├── cmd/                    # CLI commands
├── bpf/                   # eBPF C programs
│   └── headers/           # BPF headers
├── docs/                  # Documentation
│   ├── tools/            # Tool-specific docs
│   └── development-setup.md
├── scripts/              # Setup scripts
├── main.go               # Application entry point
└── Makefile              # Build and development tasks
```

## 🤝 Contributing

We welcome contributions! Whether you're fixing bugs, adding new tools, or improving documentation, your help makes this project better for everyone.

### 🚀 Quick Start for Contributors

1. **Fork and clone** the repository
2. **Set up your development environment** following our [Development Setup Guide](docs/development-setup.md)
3. **Pick an issue** or propose a new tool from our [planned tools table](#-available-tools)
4. **Follow our contribution guidelines** below

### 📋 Contribution Types

#### 🔧 Adding New eBPF Tools
Perfect for learning eBPF development:

**Step-by-step process:**
1. **Choose a tool** from our planned tools table or propose a new one
2. **Create an issue** describing the tool's purpose and implementation approach
3. **Implement the tool** following our patterns:
   ```bash
   # 1. Create eBPF C program
   touch bpf/yourtool.c
   
   # 2. Create Go command
   mkdir -p cmd
   touch cmd/yourtool.go
   
   # 3. Add to Makefile generate target
   # 4. Create documentation
   touch docs/tools/yourtool.md
   ```
4. **Test thoroughly** on multiple kernel versions
5. **Submit a pull request** with comprehensive documentation

#### 📖 Documentation Improvements
Great for first-time contributors:
- Fix typos or unclear explanations
- Add more examples and use cases
- Improve troubleshooting guides
- Translate documentation

#### 🐛 Bug Fixes
Help make the project more reliable:
- Fix compilation issues
- Resolve runtime errors
- Improve error handling
- Fix documentation inconsistencies

#### ⚡ Performance Optimizations
For advanced contributors:
- Optimize eBPF program efficiency
- Improve memory usage
- Reduce kernel/userspace communication overhead

### 📝 Code Standards

#### eBPF C Code
```c
// File header with purpose
#include "common.h"

// Clear data structures with comments
struct data_t {
    u32 pid;        // Process ID
    char comm[16];  // Command name
};

// Descriptive function names
SEC("tracepoint/category/event")
int trace_event_name(struct trace_event_raw_event *ctx) {
    // Error handling first
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(struct data_t), 0);
    if (!data) {
        return 0;
    }
    
    // Clear logic with safe memory access
    data->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    bpf_ringbuf_submit(data, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

#### Go Code
```go
// Follow Go conventions
var toolCmd = &cobra.Command{
    Use:   "toolname",
    Short: "Brief description",
    Long: `Detailed description with examples:

Examples:
  ebee toolname                    # Basic usage
  ebee toolname --pid 1234        # Filter by PID
  ebee toolname --comm bash       # Filter by command`,
    Run: runTool,
}

// Clear error handling
func runTool(cmd *cobra.Command, args []string) {
    if err := doSomething(); err != nil {
        log.Fatalf("Error: %v", err)
    }
}
```

### 🧪 Testing Requirements

#### Before Submitting
```bash
# 1. Build and test
make clean
make gen_vmlinux
make deps
make build

# 2. Test your tool
sudo ./ebee yourtool

# 3. Test with different filters
sudo ./ebee yourtool --pid $$
sudo ./ebee yourtool --comm bash

# 4. Test on different kernel versions (if possible)
```

#### Documentation Testing
- Verify all links work
- Test all code examples
- Check formatting renders correctly
- Ensure examples produce expected output

### 🔄 Pull Request Process

#### Before Opening a PR
- [ ] **Code compiles** without warnings
- [ ] **Tool works** as documented
- [ ] **Documentation is complete** (following [template](docs/tools/template.md))
- [ ] **Examples are tested** and produce expected output
- [ ] **Commit messages** are clear and descriptive

#### PR Description Template
```markdown
## Summary
Brief description of changes

## Type of Change
- [ ] New eBPF tool
- [ ] Bug fix
- [ ] Documentation improvement
- [ ] Performance optimization

## Testing
- [ ] Tested on Linux (kernel version: X.X.X)
- [ ] Tested on macOS via Lima
- [ ] All examples work as documented
- [ ] No regression in existing tools

## Documentation
- [ ] Updated tool table in README
- [ ] Created/updated tool documentation
- [ ] Included usage examples
- [ ] Added troubleshooting section
```

### 📚 Resources for Contributors

#### Learning eBPF
- [eBPF Fundamentals](docs/ebpf-fundamentals.md) - Start here!
- [Development Setup](docs/development-setup.md) - Environment setup
- [Existing tools](docs/tools/) - Learn from working examples

#### External Resources
- [Cilium eBPF Library](https://github.com/cilium/ebpf) - Go eBPF library we use
- [BCC Tools](https://github.com/iovisor/bcc) - Reference implementations
- [eBPF.io](https://ebpf.io/) - Comprehensive eBPF resources
- [Linux Kernel Documentation](https://www.kernel.org/doc/html/latest/)

### 🆘 Getting Help

- **Documentation questions**: Open an issue with the `documentation` label
- **Development help**: Open an issue with the `help wanted` label  
- **Bug reports**: Use the bug report template
- **Feature requests**: Use the feature request template

### 🌟 Recognition

Contributors will be:
- Listed in our contributors section
- Mentioned in release notes for significant contributions
- Invited to review related PRs
- Given credit in tool documentation they create

**Thank you for contributing to ebee! Every contribution helps others learn eBPF development.** 🚀

## 📄 License

This project is licensed under the same license as the original project.