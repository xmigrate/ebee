# How to Contribute

We welcome contributions! Whether you're fixing bugs, adding new tools, or improving documentation, your help makes this project better for everyone learning eBPF.

## 🚀 Quick Start for Contributors

1. **Fork and clone** the repository
2. **Set up your development environment** following our [Development Setup Guide](../getting-started/development-setup.md)
3. **Pick an issue** or propose a new tool from our [planned tools table](../index.md#-tools-youll-build)
4. **Follow our contribution guidelines** below

## 📋 Types of Contributions

### 🔧 Adding New eBPF Tools
Perfect for learning eBPF development!

#### Step-by-step Process
1. **Choose a tool** from our planned tools or propose a new one
2. **Create an issue** describing the tool's purpose and implementation approach
3. **Implement the tool** following our patterns:
   ```bash
   # 1. Create eBPF C program
   touch bpf/yourtool.c
   
   # 2. Create Go command
   touch cmd/yourtool.go
   
   # 3. Add to Makefile generate target
   # 4. Create documentation
   touch docs/tools/yourtool.md
   ```
4. **Test thoroughly** on multiple kernel versions if possible
5. **Submit a pull request** with comprehensive documentation

#### Tool Ideas
- **opensnoop** - Monitor file opens
- **tcpconnect** - Monitor TCP connections
- **biolatency** - Block I/O latency distribution
- **funclatency** - Function latency tracing
- **stackcount** - Stack trace counting

### 📖 Documentation Improvements
Great for first-time contributors!

- Fix typos or unclear explanations
- Add more examples and use cases
- Improve troubleshooting guides
- Create translations
- Add diagrams and visualizations

### 🐛 Bug Fixes
Help make the project more reliable:

- Fix compilation issues on different platforms
- Resolve runtime errors
- Improve error handling and messages
- Fix documentation inconsistencies

### ⚡ Performance Optimizations
For advanced contributors:

- Optimize eBPF program efficiency
- Improve memory usage
- Reduce kernel/userspace communication overhead
- Add performance benchmarks

## 📝 Code Standards

### eBPF C Code Style
```c
// File header with clear purpose
#include "common.h"

// Well-commented data structures
struct data_t {
    u32 pid;        // Process ID
    char comm[16];  // Command name (kernel limit)
    u64 timestamp;  // Event timestamp in nanoseconds
};

// Descriptive section and function names
SEC("tracepoint/category/event_name")
int trace_meaningful_name(struct trace_event_raw_event *ctx) {
    // Always check for allocation failures
    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data) {
        return 0;
    }
    
    // Use safe helper functions for all memory access
    data->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->timestamp = bpf_ktime_get_ns();
    
    bpf_ringbuf_submit(data, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
```

### Go Code Style
```go
// Follow standard Go conventions
var toolCmd = &cobra.Command{
    Use:   "toolname",
    Short: "Brief description of what the tool does",
    Long: `Detailed description with examples:

Monitor [specific events] in real-time using eBPF tracepoints.
This tool attaches to [kernel hook] and captures [data types].

Examples:
  ebee toolname                    # Basic usage
  ebee toolname --pid 1234        # Filter by PID
  ebee toolname --comm bash       # Filter by command name`,
    Run: runTool,
}

func init() {
    // Clear flag descriptions
    toolCmd.Flags().Uint32Var(&pidFilter, "pid", 0, "Filter events by process ID")
    toolCmd.Flags().StringVar(&commFilter, "comm", "", "Filter events by command name")
    rootCmd.AddCommand(toolCmd)
}

func runTool(cmd *cobra.Command, args []string) {
    // Proper error handling with context
    if err := setupEnvironment(); err != nil {
        log.Fatalf("Failed to setup environment: %v", err)
    }
    
    // Resource cleanup
    defer cleanup()
    
    // Clear program flow
    if err := runMainLoop(); err != nil {
        log.Fatalf("Runtime error: %v", err)
    }
}
```

### Documentation Style
- Use clear, concise language
- Include practical examples that work
- Explain both "what" and "why"
- Add troubleshooting for common issues
- Use consistent formatting and structure

## 🧪 Testing Requirements

### Before Submitting Any PR
```bash
# 1. Clean build from scratch
make clean
make gen_vmlinux
make deps
make build

# 2. Test your specific tool
sudo ./ebee yourtool

# 3. Test with different filters
sudo ./ebee yourtool --pid $$
sudo ./ebee yourtool --comm bash

# 4. Verify no regression in existing tools
sudo ./ebee execsnoop
sudo ./ebee rmdetect

# 5. Check documentation builds (if using MkDocs)
mkdocs serve
```

### Documentation Testing
- Verify all links work correctly
- Test all code examples produce expected output
- Check formatting renders correctly in MkDocs
- Ensure examples are up-to-date with current code

### Platform Testing
If possible, test on:
- Different Linux distributions (Ubuntu, RHEL, Arch)
- Different kernel versions (4.18+, 5.0+, latest)
- Different architectures (x86_64, arm64)

## 🔄 Pull Request Process

### Before Opening a PR

Create a checklist and ensure all items are completed:

- [ ] **Code compiles** without warnings on clean build
- [ ] **Tool functionality works** as documented
- [ ] **Documentation is complete** following our [template](template.md)
- [ ] **All examples tested** and produce expected output
- [ ] **Commit messages** are clear and descriptive
- [ ] **No regression** in existing functionality

### PR Description Template

Use this template for your pull request description:

```markdown
## Summary
Brief description of what this PR adds, fixes, or improves.

## Type of Change
- [ ] New eBPF tool
- [ ] Bug fix
- [ ] Documentation improvement
- [ ] Performance optimization
- [ ] Refactoring/code cleanup

## Implementation Details
- Brief overview of your approach
- Any design decisions worth explaining
- Known limitations or trade-offs

## Testing
- [ ] Tested on Linux (specify kernel version)
- [ ] Tested on macOS via Lima (if applicable)
- [ ] All examples work as documented
- [ ] No regression in existing tools
- [ ] Added/updated tests if applicable

## Documentation
- [ ] Updated tool table in README if adding new tool
- [ ] Created/updated tool documentation in docs/tools/
- [ ] Included usage examples in documentation
- [ ] Added troubleshooting section for common issues

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation is clear and complete
```

### Review Process

1. **Automated checks** run (if configured)
2. **Maintainer review** for code quality and design
3. **Community feedback** on approach and usability
4. **Revisions** based on feedback
5. **Final approval** and merge

## 📚 Learning Resources

### For eBPF Development
- **[eBPF Fundamentals](../fundamentals/concepts.md)** - Start here for eBPF basics
- **[Development Setup](../getting-started/development-setup.md)** - Environment setup
- **[Existing Tools](../tools/execsnoop.md)** - Learn from working examples
- **[Your First Tool](../first-tool/architecture.md)** - Step-by-step tutorial

### External Resources
- **[Cilium eBPF Library](https://github.com/cilium/ebpf)** - Go eBPF library documentation
- **[BCC Tools](https://github.com/iovisor/bcc)** - Reference implementations in Python
- **[eBPF.io](https://ebpf.io/)** - Comprehensive eBPF learning resources
- **[Linux Kernel Documentation](https://www.kernel.org/doc/html/latest/)**

### For Documentation
- **[MkDocs Material](https://squidfunk.github.io/mkdocs-material/)** - Documentation framework
- **[Mermaid](https://mermaid-js.github.io/)** - Diagram creation
- **[GitHub Markdown](https://github.github.com/gfm/)** - Markdown formatting

## 🆘 Getting Help

### Communication Channels
- **📚 Documentation questions**: Open issue with `documentation` label
- **🔧 Development help**: Open issue with `help wanted` label  
- **🐛 Bug reports**: Use our bug report template
- **💡 Feature requests**: Use our feature request template
- **💬 General discussion**: Use GitHub Discussions

### Response Times
- **Bug reports**: Within 48 hours
- **Documentation issues**: Within 1 week
- **Feature requests**: Within 1 week for initial response
- **Pull requests**: Within 1 week for first review

### What to Include When Asking for Help
- **Environment details**: OS, kernel version, distribution
- **Error messages**: Full error output with context
- **Steps to reproduce**: Minimal example that demonstrates the issue
- **Expected vs actual behavior**: What you expected vs what happened

## 🌟 Recognition

### Contributors Get
- **Credit in documentation** for tools they create
- **Mention in release notes** for significant contributions
- **Reviewer privileges** for related areas after consistent contributions
- **Maintainer consideration** for long-term, high-quality contributors

### Hall of Fame
We maintain a contributors section highlighting:
- Tool creators
- Documentation improvers
- Bug fixers
- Community helpers

## 🏷️ Issue Labels

We use these labels to organize work:

- **`good first issue`** - Perfect for newcomers
- **`help wanted`** - Community help needed
- **`bug`** - Something isn't working
- **`enhancement`** - New feature request
- **`documentation`** - Documentation improvements
- **`tool-request`** - Request for new eBPF tool
- **`priority-high`** - Important issues
- **`priority-low`** - Nice to have improvements

## 🎯 Roadmap

### Short Term (Next 3 months)
- Complete all basic monitoring tools
- Improve documentation coverage
- Add more troubleshooting guides

### Medium Term (Next 6 months)
- Advanced eBPF program types (XDP, TC)
- Performance analysis tools
- Security monitoring tools

### Long Term (Next year)
- Interactive tutorials
- Video walkthroughs
- Multi-language support

## 📄 Code of Conduct

We follow a simple code of conduct:

- **Be respectful** to all community members
- **Be constructive** in feedback and criticism  
- **Be inclusive** and welcoming to newcomers
- **Be patient** with those learning eBPF
- **Be collaborative** in discussions and reviews

Violations can be reported to project maintainers.

---

**Thank you for contributing to eBPF the Hard Way!** Every contribution helps others learn eBPF development and builds a better monitoring ecosystem. 🚀

*Happy coding!* 💻