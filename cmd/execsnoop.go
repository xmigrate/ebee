package cmd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native execsnoop ../bpf/execsnoop.c -- -I../bpf/headers

type exec_data_t struct {
	Pid  uint32
	Ppid uint32
	Comm [16]byte
	Argv [256]byte
}

var execsnoopCmd = &cobra.Command{
	Use:   "execsnoop",
	Short: "Monitor process executions in real-time",
	Long: `execsnoop monitors process executions by attaching to the sched_process_exec tracepoint.
It captures the process ID, command name, and arguments of executed processes.

Examples:
  ebee execsnoop                    # Monitor all process executions
  ebee execsnoop --pid 1234         # Monitor executions by specific PID
  ebee execsnoop --comm "bash"      # Monitor executions by specific command`,
	Run: runExecsnoop,
}

var (
	execPidFilter  uint32
	execCommFilter string
)

func init() {
	execsnoopCmd.Flags().Uint32Var(&execPidFilter, "pid", 0, "Filter by process ID")
	execsnoopCmd.Flags().StringVar(&execCommFilter, "comm", "", "Filter by command name")
	rootCmd.AddCommand(execsnoopCmd)
}

func runExecsnoop(cmd *cobra.Command, args []string) {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := execsnoopObjects{}
	if err := loadExecsnoopObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach to tracepoints
	tpEnterLink, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceExec, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %s", err)
	}
	defer tpEnterLink.Close()

	fmt.Println("Monitoring process executions... Press Ctrl+C to stop")
	fmt.Println("PID\tCommand\t\tArguments")
	fmt.Println("---\t-------\t\t----------")

	// Initialize ring buffer
	events := objs.Events
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Handle incoming events
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("Error reading from buffer: %s", err)
				continue
			}

			var data exec_data_t
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &data); err != nil {
				log.Printf("Error decoding event: %s", err)
				continue
			}

			comm := string(bytes.Trim(data.Comm[:], "\x00"))
			argv := string(bytes.Trim(data.Argv[:], "\x00"))

			// Apply filters
			if execPidFilter != 0 && data.Pid != execPidFilter {
				continue
			}
			if execCommFilter != "" && comm != execCommFilter {
				continue
			}

			fmt.Printf("%d\t%s\t\t%s\n", data.Pid, comm, argv)
		}
	}()

	// Wait for interrupt
	<-stopper
	fmt.Println("\nStopping process execution monitor...")
}
