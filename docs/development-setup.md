# Development Setup Guide

This guide covers setting up your development environment for eBPF development with the ebee project.

## Prerequisites

### Linux Development Environment

For Linux users, the setup is straightforward:

```bash
# Install all requirements using the Makefile
make install
```

This will install:
- **clang** - C compiler for eBPF programs
- **llvm** - Low Level Virtual Machine (required for eBPF compilation)
- **golang** - Go programming language
- **bpftool** - eBPF introspection and manipulation tool
- **bpftrace** - High-level tracing language for Linux eBPF

### macOS Development Environment

Since eBPF development requires Linux kernel headers and tools, we use Lima to run Ubuntu:

#### 1. Install Lima

```bash
# Install/upgrade Lima + guest agents
brew install lima lima-additional-guestagents || brew upgrade lima lima-additional-guestagents
```

#### 2. Start Ubuntu VM

```bash
# Start Ubuntu VM with our configuration
limactl start scripts/default.yaml --name=default --timeout 30m
```

#### 3. Connect to VM and Setup

```bash
# Connect to the VM
limactl shell default

# Now run the Linux setup
make install
```

## Building the Application

Once your environment is set up:

### 1. Generate Kernel Headers

Before building, you need to generate the `vmlinux.h` file which contains kernel type definitions:

```bash
# Generate vmlinux.h for the current kernel
make gen_vmlinux
```

This command uses `bpftool` to extract BTF (BPF Type Format) information from the running kernel and generate a header file with all kernel type definitions. This is essential for eBPF programs to access kernel data structures.

**Note**: This step requires root privileges and must be run on the target kernel where you'll be running the eBPF programs.

### 2. Build the Application

```bash
# Install Go dependencies
make deps

# Generate eBPF Go bindings and build
make build
```

## Development Workflow

### 1. Adding New Tools

When adding a new eBPF tool:

1. **Create eBPF C program** in `bpf/your_tool.c`
2. **Create Go command** in `cmd/your_tool.go`
3. **Update Makefile** generate target to include your C file
4. **Add documentation** in `docs/tools/your_tool.md`
5. **Test thoroughly** on both Linux and macOS (via Lima)

### 2. Development Commands

```bash
# Generate eBPF bindings
make generate

# Build the application
make build

# Clean generated files
make clean

# Run specific tools (requires sudo)
sudo ./ebee rmdetect
sudo ./ebee execsnoop
```

### 3. Debugging

#### Common Issues

1. **Permission Denied**: Always run eBPF tools with `sudo`
2. **Compilation Errors**: Check kernel headers and eBPF program syntax
3. **Load Errors**: Verify eBPF program verifier passes

#### Debug Commands

```bash
# Check eBPF program with bpftool
sudo bpftool prog list

# Verify eBPF program loading
sudo bpftool prog load bpf/your_tool.o /sys/fs/bpf/your_tool

# Check tracepoints
sudo cat /sys/kernel/debug/tracing/available_events | grep sched
```

## Kernel Requirements

- **Linux Kernel**: 4.18+ (for most eBPF features)
- **BPF Type Format (BTF)**: Required for modern eBPF development
- **Kernel Headers**: Must match your running kernel version

## Understanding vmlinux.h

The `vmlinux.h` file is a crucial component for eBPF development. It contains:

### What is vmlinux.h?
- **Kernel Type Definitions**: All kernel data structures and types
- **BTF Information**: BPF Type Format data extracted from the kernel
- **Compile-time Safety**: Enables type checking for eBPF programs

### Why is it needed?
eBPF programs need to access kernel data structures (like `task_struct`, `inode`, etc.). The `vmlinux.h` file provides:
- **Type Safety**: Ensures eBPF programs use correct data types
- **Field Access**: Allows safe access to kernel structure fields
- **Compilation**: Enables eBPF programs to compile with kernel types

### How it's generated
```bash
# The gen_vmlinux target runs this command:
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./bpf/headers/vmlinux.h
```

This command:
1. **Reads BTF data** from `/sys/kernel/btf/vmlinux`
2. **Extracts type information** from the running kernel
3. **Generates C header file** with all kernel type definitions
4. **Saves to** `./bpf/headers/vmlinux.h`

### When to regenerate
You should regenerate `vmlinux.h` when:
- **Kernel is updated** to a new version
- **Switching systems** with different kernels
- **BTF data changes** (rare, but possible)
- **Compilation errors** related to missing kernel types

## Tools and Utilities

### Essential Tools

- **bpftool**: eBPF introspection and manipulation
- **bpftrace**: High-level tracing language
- **clang/llvm**: eBPF program compilation
- **golang**: Application development

### Useful Commands

```bash
# Check kernel version
uname -r

# Check eBPF support
cat /sys/kernel/debug/bpf/verifier_log

# List available tracepoints
sudo cat /sys/kernel/debug/tracing/available_events

# Check BTF support
ls /sys/kernel/btf/vmlinux

# Generate vmlinux.h (extracts kernel type definitions)
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./bpf/headers/vmlinux.h
```

## IDE Setup

### VS Code Extensions

- **C/C++**: For eBPF C development
- **Go**: For Go application development
- **eBPF**: For eBPF syntax highlighting (if available)

### Recommended Settings

```json
{
    "go.buildOnSave": true,
    "go.lintOnSave": true,
    "files.associations": {
        "*.c": "c",
        "*.h": "c"
    }
}
```

## Testing

### Unit Testing

```bash
# Run Go tests
go test ./...

# Test eBPF programs
make test
```

### Integration Testing

```bash
# Test on different kernel versions
# Test with different workloads
# Test error conditions
```

## Troubleshooting

### Common Problems

1. **"permission denied"**: Run with sudo
2. **"invalid mem access"**: Check eBPF program memory access patterns
3. **"unknown field"**: Verify kernel headers match running kernel
4. **"verifier failed"**: Check eBPF program logic and bounds
5. **"vmlinux.h not found"**: Run `make gen_vmlinux` to generate kernel headers
6. **"BTF not found"**: Ensure your kernel supports BTF (check with `ls /sys/kernel/btf/vmlinux`)

### Getting Help

- Check kernel logs: `dmesg | tail`
- Check eBPF verifier logs: `cat /sys/kernel/debug/bpf/verifier_log`
- Use bpftool for debugging: `sudo bpftool prog list`

## Next Steps

After setting up your environment:

1. Read [eBPF Fundamentals](ebpf-fundamentals.md)
2. Explore the [tool documentation](tools/)
3. Try building and running existing tools
4. Start developing your own eBPF tools
