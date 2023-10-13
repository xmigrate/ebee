package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native bpf filegone.c -- -I../bpf/headers

type data_t struct {
	Pid  uint32
	Comm [16]byte
}

func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach to tracepoints
	tpEnterLink, err := link.Tracepoint("ext4", "ext4_free_inode", objs.TraceInodeFree, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %s", err)
	}
	defer tpEnterLink.Close()

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
			log.Printf("Event received: PID: %d, Comm: %s\n", data.Pid, comm)
		}
	}()

	// Wait for interrupt
	<-stopper
}
