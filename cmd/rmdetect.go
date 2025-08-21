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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native rmdetect ../bpf/rmdetect.c -- -I../bpf/headers

type data_t struct {
	Pid  uint32
	Comm [16]byte
}

var rmdetectCmd = &cobra.Command{
	Use:   "rmdetect",
	Short: "Monitor file deletions in real-time",
	Long: `rmdetect monitors file deletions by attaching to the ext4_free_inode tracepoint.
It captures the process ID and command name of processes that delete files.

Examples:
  ebee rmdetect                    # Monitor all file deletions
  ebee rmdetect --pid 1234         # Monitor deletions by specific PID
  ebee rmdetect --comm "rm"        # Monitor deletions by specific command`,
	Run: runRmdetect,
}

var (
	pidFilter  uint32
	commFilter string
)

func init() {
	rmdetectCmd.Flags().Uint32Var(&pidFilter, "pid", 0, "Filter by process ID")
	rmdetectCmd.Flags().StringVar(&commFilter, "comm", "", "Filter by command name")
	rootCmd.AddCommand(rmdetectCmd)
}

func runRmdetect(cmd *cobra.Command, args []string) {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := rmdetectObjects{}
	if err := loadRmdetectObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach to tracepoints
	tpEnterLink, err := link.Tracepoint("ext4", "ext4_free_inode", objs.TraceInodeFree, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %s", err)
	}
	defer tpEnterLink.Close()

	fmt.Println("Monitoring file deletions... Press Ctrl+C to stop")
	fmt.Println("PID\tCommand")
	fmt.Println("---\t-------")

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

			var data data_t
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &data); err != nil {
				log.Printf("Error decoding event: %s", err)
				continue
			}

			comm := string(bytes.Trim(data.Comm[:], "\x00"))

			// Apply filters
			if pidFilter != 0 && data.Pid != pidFilter {
				continue
			}
			if commFilter != "" && comm != commFilter {
				continue
			}

			fmt.Printf("%d\t%s\n", data.Pid, comm)
		}
	}()

	// Wait for interrupt
	<-stopper
	fmt.Println("\nStopping file deletion monitor...")
}
