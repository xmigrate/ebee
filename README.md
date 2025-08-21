# ebee - eBPF the Hard Way!

This repository contains various eBPF tools originally from the BCC project, reimplemented from scratch to help users learn eBPF development step by step.

## 🎯 Project Goal

The idea for this project is to help users learn creating eBPF tools with a comprehensive step-by-step guide. Each tool includes detailed documentation explaining the underlying concepts, kernel hooks, data structures, and implementation details.

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

## 📚 Available Tools

- **rmdetect** - Monitor file deletions in real-time
- **execsnoop** - Monitor process executions in real-time

Each tool includes comprehensive documentation in the `docs/` folder.

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

Detailed documentation for each tool and eBPF concepts can be found in the `docs/` folder:

- [Development Setup](docs/development-setup.md)
- [eBPF Fundamentals](docs/ebpf-fundamentals.md)
- [Tool Documentation](docs/tools/)
  - [rmdetect](docs/tools/rmdetect.md)
  - [execsnoop](docs/tools/execsnoop.md)

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

When adding new tools:
1. Follow the existing code structure
2. Include comprehensive documentation
3. Test on both Linux and macOS (via Lima)
4. Update the Makefile and README

## 📄 License

This project is licensed under the same license as the original project.