package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	ui "github.com/gizak/termui"
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

const sizeGaugeList = 10

func initUI(quitChan chan bool) {
	ui.DefaultEvtStream.Merge("timer", ui.NewTimerCh(5*time.Second))

	spark := ui.Sparkline{}
	spark.Data = make([]int, ui.TermWidth()-2)
	spark.Height = 8
	spark.LineColor = ui.ColorGreen
	spark.TitleColor = ui.ColorWhite

	sp := ui.NewSparklines(spark)
	sp.Height = 11
	sp.BorderLabel = " syscalls total "

	quit := ui.NewPar(":PRESS q TO QUIT DEMO")
	quit.Height = 1
	quit.Border = false

	syscallNameList := ui.NewList()
	syscallNameList.Border = false
	syscallNameList.Items = make([]string, sizeGaugeList)
	syscallNameList.Height = sizeGaugeList

	syscallGaugeList := make([]*ui.Gauge, sizeGaugeList)
	for i := 0; i < sizeGaugeList; i++ {
		syscallGaugeList[i] = ui.NewGauge()
		syscallGaugeList[i].Height = 1
		syscallGaugeList[i].Border = false
		syscallGaugeList[i].BarColor = ui.ColorBlue
		syscallGaugeList[i].Label = ""
	}

	ui.Body.AddRows(
		ui.NewRow(
			ui.NewCol(12, 0, sp)),
		ui.NewRow(
			ui.NewCol(6, 0, syscallNameList),
			ui.NewCol(6, 0,
				syscallGaugeList[0],
				syscallGaugeList[1],
				syscallGaugeList[2],
				syscallGaugeList[3],
				syscallGaugeList[4],
				syscallGaugeList[5],
				syscallGaugeList[6],
				syscallGaugeList[7],
				syscallGaugeList[8],
				syscallGaugeList[9])),
		ui.NewRow(
			ui.NewCol(12, 0, quit)),
	)

	ui.Body.Align()
	ui.Render(ui.Body)

	ui.Handle("/sys/kbd/q", func(ui.Event) {
		ui.StopLoop()
		quitChan <- true
	})

	ui.Handle("/timer/5s", func(ui.Event) {

		// get current count
		syscallCountMutex.Lock()
		currentCount := syscallCount
		syscallCount = make(map[string]uint64)
		syscallCountMutex.Unlock()

		sortedSyscalls := make([]string, 0, len(currentCount))
		for k := range currentCount {
			sortedSyscalls = append(sortedSyscalls, k)
		}
		sort.Strings(sortedSyscalls)

		var totalSyscalls uint64
		for _, c := range currentCount {
			totalSyscalls += c
		}

		for i := 0; i < sizeGaugeList; i++ {
			syscallGaugeList[i].Percent = 0
			syscallGaugeList[i].Label = ""
			syscallGaugeList[i].BarColor = ui.ColorBlue
			syscallNameList.Items[i] = ""
		}

		for i := 0; i < sizeGaugeList && i < len(sortedSyscalls); i++ {
			name := sortedSyscalls[i]
			count := currentCount[name]
			percent := float64(count) * 100 / float64(totalSyscalls)
			syscallGaugeList[i].Percent = int(percent)
			syscallGaugeList[i].Label = fmt.Sprintf("%.2f %%", percent)
			syscallNameList.Items[i] = name
		}

		sp.Lines[0].Data = append(sp.Lines[0].Data[1:], int(totalSyscalls))
		sp.BorderLabel = fmt.Sprintf(" syscalls total (last count: %d) ", totalSyscalls)

		ui.Render(ui.Body)
	})

	ui.Handle("/sys/wnd/resize", func(e ui.Event) {
		ui.Body.Width = ui.TermWidth()
		ui.Body.Align()
		ui.Clear()
		ui.Render(ui.Body)
	})

	ui.Loop()
}

func main() {
	flag.Parse()

	grpcServer := grpc.NewServer()

	tracer.RegisterMetricCollectorServer(grpcServer, &server{})

	if err := ui.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init UI: %v\n", err)
		os.Exit(1)
	}
	defer ui.Close()

	quitChan := make(chan bool)
	go initUI(quitChan)

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

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to serve: %v\n", err)
			os.Exit(1)
		}
	}()

	<-quitChan
}

func min(x, y uint64) uint64 {
	if x < y {
		return x
	}
	return y
}
