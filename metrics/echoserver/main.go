package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/ShiftLeftSecurity/traceleft/tracer"
)

var addr = flag.String("addr", ":50051", "grpc server addr [host]:port")

type server struct{}

var syscallCount map[string]uint64

func init() {
	syscallCount = make(map[string]uint64)
}

func min(x, y uint64) uint64 {
	if x < y {
		return x
	}
	return y
}

func (s *server) Process(ctx context.Context, in *tracer.MetricCollection) (*tracer.Empty, error) {
	for _, metric := range in.Metrics {
		syscallCount[string(metric.CommonEvent.Name)] += metric.Count
		// fmt.Printf("syscall: %s count: %d\n", metric.CommonEvent.Syscall, metric.Count)
	}
	return &tracer.Empty{}, nil
}

func main() {
	flag.Parse()

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen: %v\n", err)
		os.Exit(1)
	}
	s := grpc.NewServer()
	tracer.RegisterMetricCollectorServer(s, &server{})
	go func() {
		for {
			time.Sleep(5 * time.Second)
			if len(syscallCount) == 0 {
				continue
			}
			fmt.Print("\033[H\033[2J")
			fmt.Println()
			fmt.Printf("  %-20s : %-10s\n", "syscall", "count")
			for syscall, count := range syscallCount {
				fmt.Printf("  %-20s : %-10d %s\n", syscall, count, strings.Repeat("|", int(min(count, 50))))
			}
			syscallCount = make(map[string]uint64)
		}
	}()
	if err := s.Serve(lis); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to serve: %v\n", err)
		os.Exit(1)
	}
}
