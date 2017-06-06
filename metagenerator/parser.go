// Based on Syscall event parsing developed by Iago López Galeiras

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/ShiftLeftSecurity/traceleft/generator"
)

// TODO: make slice sizes fixed so we can decode it with binary.Read(),
// for now it's fine since we're not using any of these yet.
const kernelStructs = `package tracer

import (
	"encoding/binary"
	"bytes"
	"fmt"
	"syscall"
	"unsafe"
)

import "C"

// kernel structures

type CapUserHeader struct {
	Version uint32
	Pid     int64
}

type CapUserData struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}

type SigSet struct {
	Sig []uint64
}

type Stack struct {
	SsSp    []byte // size?
	SsFlags int64
	SsSize  int64
}

type Itimerspec struct {
	ItInterval syscall.Timespec
	ItValue    syscall.Timespec
}

type MqAttr struct {
	MqFlags   int64
	MqMaxmsg  int64
	MqMsgsize int64
	MqCurmsgs int64
	Reserved  [4]int64
}

type Sigaction struct {
	SaHandler  unsafe.Pointer
	SaRestorer unsafe.Pointer
	SaMask     SigSet
}

type Sigval struct {
	SivalInt int64
	SivalPtr unsafe.Pointer
}

type Sigevent struct {
	SigevValue  Sigval
	SigevSigno  int64
	SigevNotify int64
	Pad         [13]int // (64 - 3*4) / 4
}

type FileHandle struct {
	HandleBytes uint32
	HandleType  int64
	FHandle     []uint8
}

type GetCPUCache struct {
	Blob [16]uint64
}

type IoCb struct {
	AioData      uint64
	Padding      uint32
	AioLioOpcode uint16
	AioReqPrio   int16
	AioFilDes    uint32
	AioBuf       uint64
	AioNbytes    uint64
	AioOffset    int64
	AioReserved2 uint64
	AioFlags     uint32
	AioResfd     uint32
}

type IoEvent struct {
	Data uint64
	Obj  uint64
	Res  int64
	Res2 int64
}

type KexecSegment struct {
	Buf   unsafe.Pointer
	Bufsz int64
	Mem   unsafe.Pointer
	Memsz int64
}

type Msgbuf struct {
	Mtype int64
	Mtext [1]byte
}

type Pollfd struct {
	Fd      int64
	Events  int16
	Revents int16
}

type RobustList struct {
	Next unsafe.Pointer
}

type RobustListHead struct {
	List          RobustList
	FutexOffset   int64
	ListOpPending unsafe.Pointer
}

type SysctlArgs struct {
	Name    []int64
	Nlen    int64
	Oldval  unsafe.Pointer
	OldLenp int64
	Newval  unsafe.Pointer
	Newlen  int64
}

type Timezone struct {
	TzMinuteswest int64
	TzDsttime     int64
}

type BpfAttr struct {
	Data [48]byte
}

type UserMsghdr struct {
	MsgName       unsafe.Pointer
	MsgNamelen    int64
	MsgIov        syscall.Iovec
	MsgIovlen     int64
	MsgControl    unsafe.Pointer
	MsgControllen int64
	MsgFlags      uint64
}

// syscall data
`

const maxBufferSize = 256

var (
	goTypeConversions = map[string]string{
		"aio_context_t *":             "uint64",
		"aio_context_t":               "uint64",
		"cap_user_data_t":             "CapUserData",
		"cap_user_header_t":           "CapUserHeader",
		"char *":                      fmt.Sprintf("[%d]byte", maxBufferSize),
		"const cap_user_data_t":       "CapUserData",
		"const char *":                fmt.Sprintf("[%d]byte", maxBufferSize),
		"const clockid_t":             "uint32",
		"const int *":                 "int64",
		"const sigset_t *":            "SigSet",
		"const stack_t *":             "Stack",
		"const struct iovec *":        "syscall.Iovec",
		"const struct itimerspec *":   "Itimerspec",
		"const struct mq_attr *":      "MqAttr",
		"const struct rlimit64 *":     "syscall.Rlimit",
		"const struct sigaction *":    "Sigaction",
		"const struct sigevent *":     "Sigevent",
		"const struct timespec *":     "syscall.Timespec",
		"const unsigned long *":       "uint64",
		"const void * *":              "unsafe.Pointer",
		"const void *":                "unsafe.Pointer",
		"fd_set *":                    "syscall.FdSet",
		"gid_t *":                     "int64",
		"gid_t":                       "int64",
		"int *":                       "int64",
		"int":                         "int64",
		"key_serial_t":                "int32",
		"key_t":                       "int64",
		"loff_t *":                    "int64",
		"loff_t":                      "int64",
		"long":                        "int64",
		"mqd_t":                       "int64",
		"off_t":                       "int64",
		"pid_t":                       "int64",
		"qid_t":                       "uint32",
		"__s32":                       "uint32",
		"siginfo_t *":                 "unsafe.Pointer", // unknown
		"sigset_t *":                  "SigSet",
		"size_t *":                    "int64",
		"size_t":                      "int64",
		"stack_t *":                   "Stack",
		"struct epoll_event *":        "syscall.EpollEvent",
		"struct file_handle *":        "FileHandle",
		"struct getcpu_cache *":       "GetCPUCache",
		"struct iocb * *":             "IoCb",
		"struct iocb *":               "[]IoCb",
		"struct io_event *":           "IoEvent",
		"struct itimerspec *":         "Itimerspec",
		"struct itimerval *":          "Itimerspec",
		"struct kexec_segment *":      "KexecSegment",
		"struct linux_dirent64 *":     "syscall.Dirent",
		"struct linux_dirent *":       "syscall.Dirent",
		"struct mmsghdr *":            "syscall.Msghdr",
		"struct mq_attr *":            "MqAttr",
		"struct msgbuf *":             "Msgbuf",
		"struct msqid_ds *":           "unsafe.Pointer", // obsolete
		"struct new_utsname *":        "syscall.Utsname",
		"struct perf_event_attr *":    "unsafe.Pointer", // too big
		"struct pollfd *":             "Pollfd",
		"struct rlimit64 *":           "syscall.Rlimit",
		"struct rlimit *":             "syscall.Rlimit",
		"struct robust_list_head * *": "[]RobustListHead",
		"struct robust_list_head *":   "RobustListHead",
		"struct rusage *":             "syscall.Rusage",
		"struct sched_attr *":         "unsafe.Pointer", // unknown
		"struct sched_param *":        "unsafe.Pointer", // unknown
		"struct sembuf *":             "unsafe.Pointer", // unknown
		"struct shmid_ds *":           "unsafe.Pointer", // unknown
		"struct sigaction *":          "unsafe.Pointer", // unknown
		"struct sigevent *":           "unsafe.Pointer", // unknown
		"struct siginfo *":            "unsafe.Pointer", // unknown
		"struct sockaddr *":           "syscall.Sockaddr",
		"struct stat *":               "syscall.Stat_t",
		"struct statfs *":             "syscall.Statfs_t",
		"struct __sysctl_args *":      "SysctlArgs",
		"struct sysinfo *":            "syscall.Sysinfo_t",
		"struct timespec *":           "syscall.Timespec",
		"struct timeval *":            "syscall.Timeval",
		"struct timex *":              "syscall.Timex",
		"struct timezone *":           "Timezone",
		"struct tms *":                "syscall.Tms",
		"struct user_msghdr *":        "unsafe.Pointer", // unknown
		"struct ustat *":              "syscall.Ustat_t",
		"struct utimbuf *":            "syscall.Utimbuf",
		"timer_t *":                   "int64",
		"timer_t":                     "int64",
		"time_t *":                    "int64",
		"u32 *":                       "uint32",
		"u32":                         "uint32",
		"u64":                         "uint64",
		"__u64":                       "uint64",
		"uid_t *":                     "int64",
		"uid_t":                       "int64",
		"umode_t":                     "uint64",
		"union bpf_attr *":            "BpfAttr",
		"unsigned char *":             fmt.Sprintf("[%d]byte", maxBufferSize),
		"unsigned *":                  "uint64",
		"unsigned":                    "uint64",
		"unsigned int *":              "uint64",
		"unsigned int":                "uint64",
		"unsigned long *":             "uint64",
		"unsigned long":               "uint64",
		"void *":                      "unsafe.Pointer",
	}

	cTypeConversions = map[string]string{
		"aio_context_t *":             "u64",
		"aio_context_t":               "aio_context_t",
		"cap_user_data_t":             "cap_user_data_t",
		"cap_user_header_t":           "cap_user_header_t",
		"char *":                      "char",
		"const cap_user_data_t":       "cap_user_data_t",
		"const char *":                "char",
		"const clockid_t":             "u32",
		"const int *":                 "s64",
		"const sigset_t *":            "u64",
		"const stack_t *":             "u64",
		"const struct iovec *":        "u64",
		"const struct itimerspec *":   "u64",
		"const struct mq_attr *":      "u64",
		"const struct rlimit64 *":     "u64",
		"const struct sigaction *":    "u64",
		"const struct sigevent *":     "u64",
		"const struct timespec *":     "u64",
		"const unsigned long *":       "u64",
		"const void * *":              "u64",
		"const void *":                "u64",
		"fd_set *":                    "u64",
		"gid_t *":                     "u64",
		"gid_t":                       "gid_t",
		"int *":                       "u64",
		"int":                         "s64",
		"key_serial_t":                "key_serial_t",
		"key_t":                       "key_t",
		"loff_t *":                    "s64",
		"loff_t":                      "loff_t",
		"long":                        "s64",
		"mqd_t":                       "mdq_t",
		"off_t":                       "off_t",
		"pid_t":                       "pid_t",
		"qid_t":                       "qid_t",
		"__s32":                       "s32",
		"siginfo_t *":                 "u64",
		"sigset_t *":                  "u64",
		"size_t *":                    "u64",
		"size_t":                      "int64_t", // varies in kernel
		"stack_t *":                   "u64",
		"struct epoll_event *":        "u64",
		"struct file_handle *":        "u64",
		"struct getcpu_cache *":       "u64",
		"struct iocb * *":             "u64",
		"struct iocb *":               "u64",
		"struct io_event *":           "u64",
		"struct itimerspec *":         "u64",
		"struct itimerval *":          "u64",
		"struct kexec_segment *":      "u64",
		"struct linux_dirent64 *":     "u64",
		"struct linux_dirent *":       "u64",
		"struct mmsghdr *":            "u64",
		"struct mq_attr *":            "u64",
		"struct msgbuf *":             "u64",
		"struct msqid_ds *":           "u64",
		"struct new_utsname *":        "u64",
		"struct perf_event_attr *":    "u64",
		"struct pollfd *":             "u64",
		"struct rlimit64 *":           "u64",
		"struct rlimit *":             "u64",
		"struct robust_list_head * *": "u64",
		"struct robust_list_head *":   "u64",
		"struct rusage *":             "u64",
		"struct sched_attr *":         "u64",
		"struct sched_param *":        "u64",
		"struct sembuf *":             "u64",
		"struct shmid_ds *":           "u64",
		"struct sigaction *":          "u64",
		"struct sigevent *":           "u64",
		"struct siginfo *":            "u64",
		"struct sockaddr *":           "u64",
		"struct stat *":               "u64",
		"struct statfs *":             "u64",
		"struct __sysctl_args *":      "u64",
		"struct sysinfo *":            "u64",
		"struct timespec *":           "u64",
		"struct timeval *":            "u64",
		"struct timex *":              "u64",
		"struct timezone *":           "u64",
		"struct tms *":                "u64",
		"struct user_msghdr *":        "u64",
		"struct ustat *":              "u64",
		"struct utimbuf *":            "u64",
		"timer_t *":                   "u64",
		"timer_t":                     "timer_t",
		"time_t *":                    "u64",
		"u32 *":                       "s64",
		"u32":                         "u32",
		"u64":                         "u64",
		"__u64":                       "u64",
		"uid_t *":                     "u64",
		"uid_t":                       "uid_t",
		"umode_t":                     "u64",
		"union bpf_attr *":            "u64",
		"unsigned char *":             "char",
		"unsigned *":                  "u64",
		"unsigned":                    "unsigned",
		"unsigned int *":              "u64",
		"unsigned int":                "u64",
		"unsigned long *":             "u64",
		"unsigned long":               "unsigned long",
		"void *":                      "u64",
	}
)

const goStructTemplate = `
type {{ .Name }} struct {
	{{- range $index, $param := .Params }}
	{{ $param.Name }} {{ $param.Type }}
	{{- end }}
}
`

const cStructTemplate = `
typedef struct {
	u64 timestamp;
	int64_t pid;
	long ret;
	char syscall[64];
	{{- range $index, $param := .Params}}
	{{ $param.Type }} {{ $param.Name }}{{ $param.Suffix }};
	{{- end }}
} {{ .Name }}_event_t;
`

const helpers = `
// helpers for events

func min(x, y int) int {
	if x > y {
		return y
	}
	return x
}

// Assume buffer truncates at 0
func bufLen(buf [256]byte) int {
	for idx := 0; idx < len(buf); idx++ {
		if buf[idx] == 0 {
			return idx
		}
	}
	return len(buf)
}

type Printable interface {
	String(ret int64) string
}

type DefaultEvent struct{}

func (w DefaultEvent) String(ret int64) string {
	return ""
}
`

// TODO: Use template functions for parameter types & names, make buffer len decision generic for other syscalls
const eventStringsTemplate = `
func (e {{ .Name }}) String(ret int64) string {
	{{- $name := .Name }}
	{{- range $index, $param := .Params }}
		{{- if or (eq $param.Name "Buf") (eq $param.Name "Filename") (eq $param.Name "Pathname") }}
	buffer := (*C.char)(unsafe.Pointer(&e.{{ $param.Name }}))
	length := C.int(0)
			{{- if or (eq $name "ReadEvent") (eq $name "WriteEvent") }}
	if ret > 0 {
		length = C.int(min(int(ret), len(e.{{ $param.Name }})))
	}
			{{- else}}
	length = C.int(bufLen(e.{{ $param.Name }}))
			{{- end}}
	bufferGo := C.GoStringN(buffer, length)
		{{- end }}
	{{- end }}

	return fmt.Sprintf("{{- range $index, $param := .Params -}}
	{{ $param.Name }}
	{{- if or (eq $param.Type "uint64") (eq $param.Type "int64") }} %d {{else}} %s {{ end -}}
	{{- end }}",
	{{- range $index, $param := .Params -}}
		{{ if $index }},{{ end }}
		{{- if or (eq $param.Name "Buf") (eq $param.Name "Filename") (eq $param.Name "Pathname") -}}
			 bufferGo
			{{- else -}}
			 e.{{ $param.Name }}
		{{- end -}}
	{{- end -}})
}
`

const getStructPreamble = `
func GetStruct(syscall string, buf *bytes.Buffer) (Printable, error) {
	switch syscall {
`

const getStructTemplate = `
	case "{{ .RawName }}":
		ev := {{ .Name }}{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		return ev, nil
`

const getStructEpilogue = `
	default:
		return DefaultEvent{}, nil
	}
}
`

type Param struct {
	Position int
	Name     string
	Type     string
	Suffix   string
}

type Syscall struct {
	Name    string
	RawName string
	Params  []Param
}

var consideredSyscalls = map[string]struct{}{
	"open":     {},
	"close":    {},
	"read":     {},
	"write":    {},
	"mkdir":    {},
	"mkdirat":  {},
	"chmod":    {},
	"fchmod":   {},
	"fchmodat": {},
	"chown":    {},
	"fchown":   {},
	"fchownat": {},
}

// Converts a string to CamelCase
func ToCamel(s string) string {
	s = strings.Trim(s, " ")
	n := ""
	capNext := true
	for _, v := range s {
		if v >= 'A' && v <= 'Z' || v >= '0' && v <= '9' {
			n += string(v)
		}
		if v >= 'a' && v <= 'z' {
			if capNext {
				n += strings.ToUpper(string(v))
			} else {
				n += string(v)
			}
		}
		if v == '_' || v == ' ' {
			capNext = true
		} else {
			capNext = false
		}
	}
	return n
}

var re = regexp.MustCompile(`\s+field:(?P<type>.*?) (?P<name>[a-z_0-9]+);.*`)

func parseLine(l string, idx int) (*Param, *Param, error) {
	n1 := re.SubexpNames()

	r := re.FindAllStringSubmatch(l, -1)
	if len(r) == 0 {
		return nil, nil, nil
	}
	res := r[0]

	mp := map[string]string{}
	for i, n := range res {
		mp[n1[i]] = n
	}

	if _, ok := mp["type"]; !ok {
		return nil, nil, nil
	}
	if _, ok := mp["name"]; !ok {
		return nil, nil, nil
	}

	// ignore
	if mp["name"] == "__syscall_nr" {
		return nil, nil, nil
	}

	var goParam Param
	goParam.Name = ToCamel(mp["name"])
	goParam.Type = goTypeConversions[mp["type"]]
	goParam.Suffix = ""
	goParam.Position = 0

	var cParam Param
	cParam.Name = mp["name"]
	cParam.Type = cTypeConversions[mp["type"]]

	// TODO: Separate this function when types to check start increasing
	// Build suffix here for expected char pointer. Consider all chars need suffix
	if cTypeConversions[mp["type"]] == "char" {
		cParam.Suffix = fmt.Sprintf("[%d]", maxBufferSize)
	} else {
		cParam.Suffix = ""
	}
	// The position is calculated based on the event format. The actual parameters
	// start from 8th index, hence we subtract that from idx to get position
	// of the parameter to the syscall
	cParam.Position = idx - 8
	// TODO: Add position info here and use the Param struct to populate parameter reading in kretprobe handler

	return &goParam, &cParam, nil
}

func parseSyscall(name, format string) (*Syscall, *Syscall, error) {
	syscallParts := strings.Split(format, "\n")
	var skipped bool

	var cParams []Param
	var goParams []Param
	for idx, line := range syscallParts {
		if !skipped {
			if len(line) != 0 {
				continue
			} else {
				skipped = true
			}
		}
		gp, cp, err := parseLine(line, idx)
		if err != nil {
			return nil, nil, err
		}
		if gp != nil {
			goParams = append(goParams, *gp)
		}
		if cp != nil {
			cParams = append(cParams, *cp)
		}
	}

	return &Syscall{
			Name:    fmt.Sprintf("%s%s", ToCamel(name), "Event"),
			RawName: name,
			Params:  goParams,
		},
		&Syscall{
			Name:    fmt.Sprintf("%s", name),
			RawName: name,
			Params:  cParams,
		}, nil
}

func gatherSyscalls(syscallsPath string) ([]Syscall, []Syscall, error) {
	var goSyscalls []Syscall
	var cSyscalls []Syscall

	err := filepath.Walk(syscallsPath, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if path == "syscalls" {
			return nil
		}

		if !f.IsDir() {
			return nil
		}

		eventName := f.Name()
		if strings.HasPrefix(eventName, "sys_exit") {
			return nil
		}

		syscallName := strings.TrimPrefix(eventName, "sys_enter_")

		if _, ok := consideredSyscalls[syscallName]; !ok {
			return nil
		}

		formatFilePath := filepath.Join(syscallsPath, eventName, "format")
		formatFile, err := os.Open(formatFilePath)
		if err != nil {
			return nil
		}
		defer formatFile.Close()

		formatBytes, err := ioutil.ReadAll(formatFile)
		if err != nil {
			return err
		}

		goSyscall, cSyscall, err := parseSyscall(syscallName, string(formatBytes))
		if err != nil {
			return err
		}

		goSyscalls = append(goSyscalls, *goSyscall)
		cSyscalls = append(cSyscalls, *cSyscall)

		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error walking %q: %v", err)
	}
	return goSyscalls, cSyscalls, nil
}

func getMatchingEvent(event *generator.Event, syscall []Syscall) (*Syscall, error) {
	for _, sc := range syscall {
		if event.Name == sc.Name {
			return &sc, nil
		}
	}
	return nil, fmt.Errorf("no matching event in config")
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s GO_OUT_FILE H_OUT_FILE CONFIG_FILE\n", os.Args[0])
		os.Exit(1)
	}

	syscallsPath := `/sys/kernel/debug/tracing/events/syscalls/`
	goSyscalls, cSyscalls, err := gatherSyscalls(syscallsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error gathering syscalls: %v\n", err)
	}

	// Add args to input JSON file
	file, err := ioutil.ReadFile(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading config: %v\n", err)
	}

	cfg := &generator.Config{}
	if err := json.Unmarshal(file, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error reading config: %v\n", err)
	}

	for _, evt := range cfg.Event {
		sc, err := getMatchingEvent(evt, cSyscalls)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			continue
		}

		// Convert to Event_Args type for JSON and add args
		evt.Args = []*generator.Event_Args{}
		for _, param := range sc.Params {
			arg := generator.Event_Args{
				Position: uint32(param.Position),
				Name:     param.Name,
				Type:     param.Type,
				Suffix:   param.Suffix,
			}
			evt.Args = append(evt.Args, &arg)
		}
	}

	newCfg, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshalling JSON config: %v\n", err)
		os.Exit(1)
	}

	if err := ioutil.WriteFile(os.Args[3], newCfg, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write updated config: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Create(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	cf, err := os.Create(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer cf.Close()

	if _, err = f.WriteString(kernelStructs); err != nil {
		fmt.Fprintf(os.Stderr, "error writing to file: %v\n", err)
		os.Exit(1)
	}

	for _, sc := range goSyscalls {
		goTmpl, err := template.New("go").Parse(goStructTemplate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error templating Go: %v\n", err)
			os.Exit(1)
		}
		goTmpl.Execute(f, sc)

	}

	if _, err = f.WriteString(helpers); err != nil {
		fmt.Fprintf(os.Stderr, "error writing to file: %v\n", err)
		os.Exit(1)
	}

	for _, sc := range goSyscalls {
		goTmpl, err := template.New("go_ev").Parse(eventStringsTemplate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error templating Go event String functions: %v\n", err)
			os.Exit(1)
		}
		goTmpl.Execute(f, sc)
	}

	if _, err = f.WriteString(getStructPreamble); err != nil {
		fmt.Fprintf(os.Stderr, "error writing to file: %v\n", err)
		os.Exit(1)
	}

	for _, sc := range goSyscalls {
		goTmpl, err := template.New("go_getStruct").Parse(getStructTemplate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error templating Go getStruct function: %v\n", err)
			os.Exit(1)
		}
		goTmpl.Execute(f, sc)
	}

	if _, err = f.WriteString(getStructEpilogue); err != nil {
		fmt.Fprintf(os.Stderr, "error writing to file: %v\n", err)
		os.Exit(1)
	}

	for _, sc := range cSyscalls {
		cTmpl, err := template.New("C").Parse(cStructTemplate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error templating C: %v\n", err)
			os.Exit(1)
		}
		cTmpl.Execute(cf, sc)
	}
}
