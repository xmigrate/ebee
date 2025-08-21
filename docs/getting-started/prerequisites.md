# Prerequisites

Before diving into eBPF development, let's ensure you have everything you need to succeed with this guide.

## 🖥️ System Requirements

### Linux Kernel Version
!!! warning "Minimum Requirements"
    - **Linux Kernel**: 4.18+ (5.0+ strongly recommended)
    - **Architecture**: x86_64 or arm64
    - **Root Access**: Required for loading eBPF programs

### Check Your Kernel Version
```bash
# Check kernel version
uname -r

# Check kernel config for eBPF support
grep -i ebpf /boot/config-$(uname -r)

# Check if BTF is available (recommended)
ls /sys/kernel/btf/vmlinux
```

!!! tip "BTF Support"
    BTF (BPF Type Format) provides type information that makes eBPF development much easier. Most modern distributions enable it by default.

### Supported Distributions

=== "Ubuntu/Debian"
    ```bash
    # Ubuntu 20.04+ or Debian 11+ recommended
    lsb_release -a
    ```

=== "RHEL/CentOS/Fedora"
    ```bash
    # RHEL 8+, CentOS 8+, or Fedora 30+ recommended
    cat /etc/os-release
    ```

=== "Arch Linux"
    ```bash
    # Latest kernel is usually available
    pacman -Q linux
    ```

## 🧠 Knowledge Prerequisites

### Required Knowledge
- **Basic C Programming**: You should be comfortable with:
  - Pointers and memory management
  - Structs and data types
  - Function calls and return values
  - Basic understanding of compilation

### Helpful Knowledge (Not Required)
- **Go Programming**: We use Go for userspace applications, but examples are clear
- **Linux Systems Programming**: Understanding of processes, files, and networking
- **Kernel Concepts**: Basic knowledge of system calls and kernel/userspace interaction

!!! info "Don't Worry!"
    We'll teach you all the eBPF-specific concepts. If you can write basic C programs, you're ready to start!

## 🛠️ Development Tools

### Required Tools
You'll need these tools installed:

- **clang/llvm**: For compiling eBPF programs
- **golang**: For userspace applications (1.19+ recommended)
- **make**: For build automation
- **git**: For version control

### Development Environment Options

=== "Native Linux"
    Best performance and compatibility
    ```bash
    # Will be covered in development-setup.md
    make install
    ```

=== "Linux VM"
    If you're on macOS or Windows
    ```bash
    # We provide Lima configuration for macOS
    limactl start scripts/default.yaml
    ```

=== "Container"
    For isolated development
    ```bash
    # Docker setup (advanced)
    docker run -it --privileged ubuntu:22.04
    ```

## 📚 Learning Prerequisites

### What You Should Know Before Starting

!!! success "Ready to Start"
    - [ ] Can write basic C programs
    - [ ] Understand what pointers are
    - [ ] Know how to use a terminal
    - [ ] Have Linux system with kernel 4.18+
    - [ ] Have root/sudo access

!!! warning "Need to Learn First"
    If you're completely new to C programming, consider taking a basic C course first. Here are some resources:
    
    - [Learn C - Free Interactive C Tutorial](https://www.learn-c.org/)
    - [C Programming at Codecademy](https://www.codecademy.com/learn/learn-c)
    - [The C Programming Language (Book)](https://www.amazon.com/Programming-Language-2nd-Brian-Kernighan/dp/0131103628)

### Learning Style
This guide assumes you:

- **Learn by doing** - We provide complete working examples
- **Want to understand** - We explain not just "what" but "why"
- **Like to experiment** - We encourage you to modify examples
- **Ask questions** - Use GitHub discussions for help

## 🎯 Learning Objectives

After completing this guide, you'll be able to:

### Beginner Level
- [ ] Understand what eBPF is and how it works
- [ ] Write basic eBPF programs in C
- [ ] Compile and load eBPF programs
- [ ] Create simple monitoring tools

### Intermediate Level
- [ ] Use different eBPF program types (tracepoints, kprobes, etc.)
- [ ] Work with eBPF maps for data storage
- [ ] Build complete userspace applications
- [ ] Debug eBPF programs effectively

### Advanced Level
- [ ] Optimize eBPF programs for performance
- [ ] Handle complex kernel data structures
- [ ] Create production-ready monitoring tools
- [ ] Contribute to eBPF projects

## ⏱️ Time Commitment

### Realistic Expectations

| Phase | Time Estimate | What You'll Accomplish |
|-------|--------------|------------------------|
| **Setup** | 30-60 minutes | Development environment ready |
| **Fundamentals** | 2-4 hours | Understand eBPF concepts |
| **First Tool** | 3-6 hours | Complete working eBPF tool |
| **Tool Tutorials** | 1-2 weeks | Multiple real-world tools |
| **Advanced Topics** | Ongoing | Production-ready skills |

!!! tip "Learn at Your Own Pace"
    This guide is designed to be self-paced. Take breaks, experiment with the code, and don't hesitate to revisit concepts.

## 🆘 Getting Help

### When You're Stuck
- **Read error messages carefully** - They're usually helpful
- **Check the troubleshooting section** - Common issues are documented
- **Search existing issues** - Someone might have faced the same problem
- **Ask in discussions** - Our community is helpful and welcoming

### Resources for Extra Learning
- **[eBPF.io](https://ebpf.io/)** - Official eBPF documentation
- **[Cilium eBPF Library](https://github.com/cilium/ebpf)** - Go library we use
- **[BCC Tools](https://github.com/iovisor/bcc)** - Reference implementations
- **[Linux Kernel Docs](https://www.kernel.org/doc/)** - Kernel documentation

## ✅ Ready Check

Before proceeding to the next section, make sure you have:

- [ ] Linux system with kernel 4.18+ (check with `uname -r`)
- [ ] Root/sudo access (test with `sudo whoami`)
- [ ] Basic C programming knowledge
- [ ] Enthusiasm to learn! 🚀

!!! success "All Set?"
    Great! Let's [set up your development environment](development-setup.md) and start building!

!!! question "Not quite ready?"
    That's okay! Take time to set up what you need. This guide will be here when you're ready.