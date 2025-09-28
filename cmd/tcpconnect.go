//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native tcpconnect ../bpf/tcpconnect.c -- -I../bpf/headers

package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/spf13/cobra"
)

// This must match the C structure exactly
type tcpConnectData struct {
	Pid       uint32
	Tgid      uint32
	Comm      [16]byte
	Saddr     uint32
	Daddr     uint32
	Sport     uint16
	Dport     uint16
	Timestamp uint64
}

var (
	targetPid   uint32
	targetComm  string
	targetPort  uint16
	targetAddr  string
	targetHost  string
)

var tcpconnectCmd = &cobra.Command{
	Use:   "tcpconnect",
	Short: "Monitor TCP connections",
	Long: `Monitor TCP connections in real-time using eBPF.

This tool traces TCP connection attempts by attaching to the tcp_v4_connect kernel function.
It shows process information, source/destination IPs and ports for each connection.

Examples:
  ebee tcpconnect                          # Monitor all TCP connections
  ebee tcpconnect --pid 1234              # Monitor connections from specific PID
  ebee tcpconnect --comm curl             # Monitor connections from specific command
  ebee tcpconnect --port 80               # Monitor connections to specific port
  ebee tcpconnect --addr 192.168.1.1     # Monitor connections to specific IP
  ebee tcpconnect --host google.com       # Monitor connections to specific hostname`,
	Run: runTcpconnect,
}

func init() {
	tcpconnectCmd.Flags().Uint32VarP(&targetPid, "pid", "p", 0, "Filter by process ID")
	tcpconnectCmd.Flags().StringVarP(&targetComm, "comm", "c", "", "Filter by command name")
	tcpconnectCmd.Flags().Uint16VarP(&targetPort, "port", "", 0, "Filter by destination port")
	tcpconnectCmd.Flags().StringVarP(&targetAddr, "addr", "a", "", "Filter by destination IP address")
	tcpconnectCmd.Flags().StringVarP(&targetHost, "host", "", "", "Filter by destination hostname (resolves to IP)")
	rootCmd.AddCommand(tcpconnectCmd)
}

func runTcpconnect(cmd *cobra.Command, args []string) {
	// Resolve hostname to IP if provided
	var targetIPs []uint32
	if targetHost != "" {
		ips, err := net.LookupIP(targetHost)
		if err != nil {
			log.Fatalf("Failed to resolve hostname %s: %v", targetHost, err)
		}
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				targetIPs = append(targetIPs, ipToUint32(ipv4))
			}
		}
		if len(targetIPs) == 0 {
			log.Fatalf("No IPv4 addresses found for hostname %s", targetHost)
		}
		log.Printf("Resolved %s to %d IPv4 address(es)", targetHost, len(targetIPs))
	}

	// Validate target address if provided
	if targetAddr != "" {
		ip := net.ParseIP(targetAddr)
		if ip == nil {
			log.Fatalf("Invalid IP address: %s", targetAddr)
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			log.Fatalf("Only IPv4 addresses are supported: %s", targetAddr)
		}
	}

	// Load the eBPF program
	objs := tcpconnectObjects{}
	if err := loadTcpconnectObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach to the syscall tracepoint
	l, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceSysConnect, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %v", err)
	}
	defer l.Close()

	log.Println("Successfully loaded and attached eBPF program to sys_enter_connect")

	// Create ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Print header
	fmt.Println("Monitoring TCP connections... Press Ctrl+C to stop")
	fmt.Printf("%-10s %-8s %-8s %-15s:%-6s %-15s:%-6s %-15s %s\n",
		"TIME", "PID", "TGID", "SADDR", "SPORT", "DADDR", "DPORT", "COMMAND", "")
	fmt.Printf("%-10s %-8s %-8s %-15s:%-6s %-15s:%-6s %-15s\n",
		"----", "---", "----", "-----", "-----", "-----", "-----", "-------")

	// Handle graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Read events in a goroutine
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := rd.Read()
				if err != nil {
					// Check if context is cancelled
					if ctx.Err() != nil {
						return
					}
					// Only log actual errors, not shutdown-related ones
					if err.Error() != "ringbuffer: file already closed" {
						log.Printf("reading from reader: %v", err)
					}
					continue
				}

				// Parse the event
				var event tcpConnectData
				if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
					log.Printf("parsing event: %v", err)
					continue
				}

				// Apply filters
				if shouldFilterEvent(&event) {
					continue
				}

				// Display the event
				displayEvent(&event)
			}
		}
	}()

	// Wait for signal
	<-sig
	log.Println("Received signal, exiting...")

	// Cancel context to stop goroutine
	cancel()

	// Give goroutine a moment to exit
	time.Sleep(100 * time.Millisecond)
}

func shouldFilterEvent(event *tcpConnectData) bool {
	// Filter by PID
	if targetPid != 0 && event.Pid != targetPid {
		return true
	}

	// Filter by command name
	if targetComm != "" {
		comm := nullTerminatedString(event.Comm[:])
		if !strings.Contains(strings.ToLower(comm), strings.ToLower(targetComm)) {
			return true
		}
	}

	// Filter by destination port
	if targetPort != 0 && event.Dport != targetPort {
		return true
	}

	// Filter by destination IP address
	if targetAddr != "" {
		var targetAddrUint32 uint32
		if ip := net.ParseIP(targetAddr); ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				targetAddrUint32 = ipToUint32(ipv4)
				if event.Daddr != targetAddrUint32 {
					return true
				}
			}
		}
	}

	// Filter by hostname (resolved IPs)
	if targetHost != "" {
		var targetIPs []uint32
		if ips, err := net.LookupIP(targetHost); err == nil {
			for _, ip := range ips {
				if ipv4 := ip.To4(); ipv4 != nil {
					targetIPs = append(targetIPs, ipToUint32(ipv4))
				}
			}
		}

		// Check if event destination matches any of the resolved IPs
		matched := false
		for _, targetIP := range targetIPs {
			if event.Daddr == targetIP {
				matched = true
				break
			}
		}
		if !matched {
			return true
		}
	}

	return false
}

func displayEvent(event *tcpConnectData) {
	// Convert timestamp to readable time
	timestamp := time.Unix(0, int64(event.Timestamp))
	timeStr := timestamp.Format("15:04:05")

	// Convert IP addresses to readable format
	saddr := intToIP(event.Saddr)
	daddr := intToIP(event.Daddr)

	// Get command name
	comm := nullTerminatedString(event.Comm[:])

	// Print the event
	fmt.Printf("%-10s %-8d %-8d %-15s:%-6d %-15s:%-6d %s\n",
		timeStr,
		event.Pid,
		event.Tgid,
		saddr,
		event.Sport,
		daddr,
		event.Dport,
		comm)
}

// Helper function to convert null-terminated byte array to string
func nullTerminatedString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Helper function to convert uint32 IP to string
func intToIP(ip uint32) string {
	return net.IPv4(
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24),
	).String()
}

// Helper function to convert IPv4 to uint32
func ipToUint32(ip net.IP) uint32 {
	ipv4 := ip.To4()
	return uint32(ipv4[0]) | uint32(ipv4[1])<<8 | uint32(ipv4[2])<<16 | uint32(ipv4[3])<<24
}