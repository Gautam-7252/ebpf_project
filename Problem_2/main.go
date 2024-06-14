package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("Usage: %s <interface> <port> <process_name>\n", os.Args[0])
		os.Exit(1)
	}

	ifaceName := os.Args[1]
	portStr := os.Args[2]
	processName := os.Args[3]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid port: %v\n", err)
		os.Exit(1)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to remove memlock limit: %v\n", err)
		os.Exit(1)
	}

	spec, err := ebpf.LoadCollectionSpec("filter.o")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load collection spec: %v\n", err)
		os.Exit(1)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create collection: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get interface by name: %v\n", err)
		os.Exit(1)
	}

	xdpProg := coll.Programs["filter"]
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: iface.Index,
		Flags:     unix.XDP_FLAGS_SKB_MODE,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to attach XDP program: %v\n", err)
		os.Exit(1)
	}
	defer xdpLink.Close()

	fmt.Printf("Attached XDP program to iface \"%s\" (index %d)\n", iface.Name, iface.Index)
	fmt.Printf("Blocking TCP packets on port %d for process \"%s\"\n", port, processName)
	fmt.Println("Press Ctrl-C to exit and remove the program")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("Removing XDP program and exiting...")
}
