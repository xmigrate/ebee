# eBPF Tools Documentation

This directory contains detailed documentation for each eBPF tool in the ebee project. Each tool includes comprehensive information about its purpose, implementation, usage, and technical details.

## Available Tools

### Core Tools

- **[rmdetect](rmdetect.md)** - Monitor file deletions in real-time
  - Attaches to `ext4_free_inode` tracepoint
  - Captures process ID and command name
  - Useful for security monitoring and audit trails

- **[execsnoop](execsnoop.md)** - Monitor process executions in real-time
  - Attaches to `sched_process_exec` tracepoint
  - Captures process ID, command name, and arguments
  - Useful for security monitoring and process analysis

- **[tcpconnect](tcpconnect.md)** - Monitor TCP connections in real-time
  - Attaches to `sys_enter_connect` tracepoint
  - Captures process ID, command name, and destination IP/port
  - Useful for network monitoring and security analysis

### Template

- **[template](template.md)** - Template for creating new tool documentation
  - Use this template when adding new eBPF tools
  - Includes all required sections and examples

## Tool Categories

### File System Monitoring
Tools that monitor file system operations:
- **rmdetect** - File deletion monitoring

### Process Monitoring
Tools that monitor process lifecycle events:
- **execsnoop** - Process execution monitoring

### Network Monitoring
Tools that monitor network operations:
- **tcpconnect** - TCP connection monitoring
- **tcpaccept** - TCP accept monitoring (future)

### System Monitoring
Tools that monitor system-level events (future):
- **biolatency** - Block I/O latency monitoring
- **syscount** - System call counting

## Adding New Tools

When adding a new eBPF tool to the project:

1. **Create the eBPF C program** in `bpf/your_tool.c`
2. **Create the Go command** in `cmd/your_tool.go`
3. **Generate documentation** using the template:
   ```bash
   make create-tool
   ```
4. **Update the Makefile** generate target to include your C file
5. **Add the command** to `cmd/root.go`
6. **Customize the documentation** in `docs/tools/your_tool.md`
7. **Update this index** to include your new tool

## Documentation Standards

Each tool documentation should include:

### Required Sections
- **What it does** - Purpose and use cases
- **How it works** - Technical implementation details
- **Implementation Details** - Code examples and explanations
- **Usage** - Command-line examples and options
- **Technical Deep Dive** - Kernel internals and performance
- **Troubleshooting** - Common issues and solutions
- **Extending** - How to enhance the tool
- **References** - Links to relevant documentation

### Optional Sections
- **Advanced Features** - Complex use cases
- **Performance Tuning** - Optimization tips
- **Integration** - How to integrate with other tools

## Common Patterns

### eBPF Program Structure
```c
#include "common.h"

struct data_t {
    // Event data structure
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/category/event")
int trace_event(struct trace_event_raw_event *ctx) {
    // Program logic
    return 0;
}

char _license[] SEC("license") = "GPL";
```

### Go Command Structure
```go
var toolCmd = &cobra.Command{
    Use:   "toolname",
    Short: "Brief description",
    Long:  `Detailed description with examples`,
    Run:   runTool,
}

func init() {
    toolCmd.Flags().StringVar(&option, "option", "", "Option description")
    rootCmd.AddCommand(toolCmd)
}

func runTool(cmd *cobra.Command, args []string) {
    // Implementation
}
```

## Best Practices

### Documentation
- Use clear, concise language
- Include practical examples
- Explain both "what" and "why"
- Provide troubleshooting guidance
- Keep examples up-to-date

### Code
- Follow existing patterns
- Include proper error handling
- Use meaningful variable names
- Add comments for complex logic
- Test thoroughly

### Performance
- Minimize kernel/userspace communication
- Use efficient data structures
- Consider filtering in kernel space
- Monitor resource usage

## Contributing

When contributing new tools or documentation:

1. **Follow the established patterns**
2. **Test on multiple kernel versions**
3. **Include comprehensive documentation**
4. **Update this index file**
5. **Add appropriate tests**

## Resources

- [eBPF Fundamentals](../ebpf-fundamentals.md)
- [Development Setup](../development-setup.md)
- [Cilium eBPF Library](https://github.com/cilium/ebpf)
- [BCC Tools Reference](https://github.com/iovisor/bcc)
- [Linux Kernel Documentation](https://www.kernel.org/doc/)
