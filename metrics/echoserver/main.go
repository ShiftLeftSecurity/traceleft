package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc"

	"github.com/ShiftLeftSecurity/traceleft/tracer"
)

var (
	addr        = flag.String("addr", "127.0.0.1:50051", "grpc server addr [ip]:port (ignored with -tls enabled)")
	tlsDomain   = flag.String("tls-domain", "", "domain to use for certificate")
	tlsCacheDir = flag.String("tls-cache-dir", "./.acme", "directory to cache obtained certificates")
	tlsEnable   = flag.Bool("tls", false, "obtain and use lets encrypt certificate (requires -domain option)")
)

type server struct{}

var (
	syscallCount      map[string]uint64
	syscallCountMutex sync.Mutex
)

func init() {
	syscallCount = make(map[string]uint64)
}

func (s *server) Process(stream tracer.MetricCollector_ProcessServer) error {
	syscallCountMutex.Lock()
	defer syscallCountMutex.Unlock()
	for {
		metric, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&tracer.Empty{})
		}
		if err != nil {
			return err
		}
		syscallCount[string(metric.CommonEvent.Name)] += metric.Count
	}
	return nil
}

func printSyscallCount() {
	for {
		time.Sleep(5 * time.Second)
		fmt.Print("\033[H\033[2J")
		fmt.Println()
		if len(syscallCount) == 0 {
			fmt.Println("  no events received")
			continue
		}
		fmt.Printf("  %-20s : %-10s\n", "syscall", "count")
		syscallCountMutex.Lock()
		for syscall, count := range syscallCount {
			fmt.Printf("  %-20s : %-10d %s\n", syscall, count, strings.Repeat("|", int(min(count, 50))))
		}
		syscallCount = make(map[string]uint64)
		syscallCountMutex.Unlock()
	}
}

func main() {
	flag.Parse()

	grpcServer := grpc.NewServer()

	tracer.RegisterMetricCollectorServer(grpcServer, &server{})

	go printSyscallCount()

	var (
		err      error
		listener net.Listener
	)
	if *tlsEnable {
		if *tlsDomain == "" {
			fmt.Fprintf(os.Stderr, "-domain is required with tls enabled\n")
			os.Exit(1)
		}

		manager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*tlsDomain),
			Cache:      autocert.DirCache(*tlsCacheDir),
		}

		listener = manager.Listener()
	} else {
		listener, err = net.Listen("tcp", *addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get listener: %v\n", err)
			os.Exit(1)
		}
	}

	if err := grpcServer.Serve(listener); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to serve: %v\n", err)
		os.Exit(1)
	}
}

func min(x, y uint64) uint64 {
	if x < y {
		return x
	}
	return y
}
