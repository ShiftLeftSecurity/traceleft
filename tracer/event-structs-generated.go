// Generated file, do not edit.
// Source: metagenerator.go

package tracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

import "C"

type FdInfo struct {
	Path  string
	Ino   uint64
	Major uint64
	Minor uint64
}

// Pid -> Fd -> FdInfo
type FdMap struct {
	sync.RWMutex
	items map[uint32]map[uint32]FdInfo
}

func NewFdMap() *FdMap {
	return &FdMap{
		items: make(map[uint32]map[uint32]FdInfo),
	}
}

func (f *FdMap) Get(pid, fd uint32) (*FdInfo, bool) {
	f.RLock()
	defer f.RUnlock()

	inner, ok := f.items[pid]
	if !ok {
		return nil, ok
	}

	info, ok := inner[fd]
	return &info, ok
}

func (f *FdMap) Put(pid, fd uint32, info FdInfo) {
	f.Lock()
	defer f.Unlock()

	if _, ok := f.items[pid]; !ok {
		f.items[pid] = make(map[uint32]FdInfo)
	}

	f.items[pid][fd] = info
}

func (f *FdMap) Delete(pid, fd uint32) {
	f.Lock()
	defer f.Unlock()

	if m, ok := f.items[pid]; ok {
		delete(m, fd)
	}
}

func (f *FdMap) DeletePid(pid uint32) {
	f.Lock()
	defer f.Unlock()

	delete(f.items, pid)
}

func (f *FdMap) Clear() {
	f.Lock()
	defer f.Unlock()

	f.items = make(map[uint32]map[uint32]FdInfo)
}

type Context struct {
	Fds *FdMap
}

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

func (e FileEvent) String(ret int64) string {

	return fmt.Sprintf("Fd %d ", e.Fd)
}

// FileEvent is not meant to be seen by the users
func (e FileEvent) Metric() *Metric {
	return nil
}

// syscall data

type ChmodEvent struct {
	Filename [256]byte
	Mode     uint64
}

type ChownEvent struct {
	Filename [256]byte
	User     uint32
	Group    uint32
}

type CloseEvent struct {
	Fd     uint64
	FdPath string
}

type FchmodEvent struct {
	Fd     uint64
	FdPath string
	Mode   uint64
}

type FchmodatEvent struct {
	Dfd      int64
	Filename [256]byte
	Mode     uint64
}

type FchownEvent struct {
	Fd     uint64
	FdPath string
	User   uint32
	Group  uint32
}

type FchownatEvent struct {
	Dfd      int64
	Filename [256]byte
	User     uint32
	Group    uint32
	Flag     int64
}

type MkdirEvent struct {
	Pathname [256]byte
	Mode     uint64
}

type MkdiratEvent struct {
	Dfd      int64
	Pathname [256]byte
	Mode     uint64
}

type OpenEvent struct {
	Filename [256]byte
	Flags    int64
	Mode     uint64
}

type ReadEvent struct {
	Fd     uint64
	FdPath string
	Buf    [256]byte
	Count  int64
}

type WriteEvent struct {
	Fd     uint64
	FdPath string
	Buf    [256]byte
	Count  int64
}

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

type Event interface {
	String(ret int64) string
	Metric() *Metric
}

func procLookupPath(pid, fd uint32) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
}

type DefaultEvent struct{}

func (w DefaultEvent) String(ret int64) string {
	return ""
}

func (w DefaultEvent) Metric() *Metric {
	return nil
}

func (e ChmodEvent) String(ret int64) string {
	buffer := (*C.char)(unsafe.Pointer(&e.Filename))
	length := C.int(0)
	length = C.int(bufLen(e.Filename))
	bufferGo := C.GoStringN(buffer, length)
	return fmt.Sprintf("Filename %q Mode %d ", bufferGo, e.Mode)
}

func (e ChownEvent) String(ret int64) string {
	buffer := (*C.char)(unsafe.Pointer(&e.Filename))
	length := C.int(0)
	length = C.int(bufLen(e.Filename))
	bufferGo := C.GoStringN(buffer, length)
	return fmt.Sprintf("Filename %q User %d Group %d ", bufferGo, e.User, e.Group)
}

func (e CloseEvent) String(ret int64) string {
	return fmt.Sprintf("Fd %d<%s> ", e.Fd, e.FdPath)
}

func (e FchmodEvent) String(ret int64) string {
	return fmt.Sprintf("Fd %d<%s> Mode %d ", e.Fd, e.FdPath, e.Mode)
}

func (e FchmodatEvent) String(ret int64) string {
	buffer := (*C.char)(unsafe.Pointer(&e.Filename))
	length := C.int(0)
	length = C.int(bufLen(e.Filename))
	bufferGo := C.GoStringN(buffer, length)
	return fmt.Sprintf("Dfd %d Filename %q Mode %d ", e.Dfd, bufferGo, e.Mode)
}

func (e FchownEvent) String(ret int64) string {
	return fmt.Sprintf("Fd %d<%s> User %d Group %d ", e.Fd, e.FdPath, e.User, e.Group)
}

func (e FchownatEvent) String(ret int64) string {
	buffer := (*C.char)(unsafe.Pointer(&e.Filename))
	length := C.int(0)
	length = C.int(bufLen(e.Filename))
	bufferGo := C.GoStringN(buffer, length)
	return fmt.Sprintf("Dfd %d Filename %q User %d Group %d Flag %d ", e.Dfd, bufferGo, e.User, e.Group, e.Flag)
}

func (e MkdirEvent) String(ret int64) string {
	buffer := (*C.char)(unsafe.Pointer(&e.Pathname))
	length := C.int(0)
	length = C.int(bufLen(e.Pathname))
	bufferGo := C.GoStringN(buffer, length)
	return fmt.Sprintf("Pathname %q Mode %d ", bufferGo, e.Mode)
}

func (e MkdiratEvent) String(ret int64) string {
	buffer := (*C.char)(unsafe.Pointer(&e.Pathname))
	length := C.int(0)
	length = C.int(bufLen(e.Pathname))
	bufferGo := C.GoStringN(buffer, length)
	return fmt.Sprintf("Dfd %d Pathname %q Mode %d ", e.Dfd, bufferGo, e.Mode)
}

func (e OpenEvent) String(ret int64) string {
	buffer := (*C.char)(unsafe.Pointer(&e.Filename))
	length := C.int(0)
	length = C.int(bufLen(e.Filename))
	bufferGo := C.GoStringN(buffer, length)
	return fmt.Sprintf("Filename %q Flags %d Mode %d ", bufferGo, e.Flags, e.Mode)
}

func (e ReadEvent) String(ret int64) string {
	buffer := (*C.char)(unsafe.Pointer(&e.Buf))
	length := C.int(0)
	if ret > 0 {
		length = C.int(min(int(ret), len(e.Buf)))
	}
	bufferGo := C.GoStringN(buffer, length)
	return fmt.Sprintf("Fd %d<%s> Buf %q Count %d ", e.Fd, e.FdPath, bufferGo, e.Count)
}

func (e WriteEvent) String(ret int64) string {
	buffer := (*C.char)(unsafe.Pointer(&e.Buf))
	length := C.int(0)
	if ret > 0 {
		length = C.int(min(int(ret), len(e.Buf)))
	}
	bufferGo := C.GoStringN(buffer, length)
	return fmt.Sprintf("Fd %d<%s> Buf %q Count %d ", e.Fd, e.FdPath, bufferGo, e.Count)
}

func GetStruct(ce *CommonEvent, ctx Context, buf *bytes.Buffer) (Event, error) {
	switch ce.Name {

	case "chmod":
		ev := ChmodEvent{}
		copy(ev.Filename[:], buf.Next(256))
		ev.Mode = uint64(binary.LittleEndian.Uint64(buf.Next(8)))

		return ev, nil

	case "chown":
		ev := ChownEvent{}
		copy(ev.Filename[:], buf.Next(256))
		ev.User = uint32(binary.LittleEndian.Uint32(buf.Next(4)))
		ev.Group = uint32(binary.LittleEndian.Uint32(buf.Next(4)))

		return ev, nil

	case "close":
		ev := CloseEvent{}
		ev.Fd = uint64(binary.LittleEndian.Uint64(buf.Next(8)))
		fileName := "unknown"
		info, ok := ctx.Fds.Get(uint32(ce.Pid), uint32(ev.Fd))
		if ok {
			var stat syscall.Stat_t
			path := filepath.Join("/proc", strconv.FormatInt(int64(ce.Pid), 10), "root", info.Path)
			err := syscall.Stat(path, &stat)
			if err != nil {
				if err == syscall.ENOENT {
					// the file doesn't exist anymore, it's probably "info.Path"
					// but we're not sure
					fileName = fmt.Sprintf("[deleted] (%q)?", info.Path)
				}
			}
			if info.Ino == stat.Ino &&
				info.Major == stat.Dev>>8 &&
				info.Minor == stat.Dev&0xff {
				fileName = info.Path
			}
		}
		ev.FdPath = fileName
		ctx.Fds.Delete(uint32(ce.Pid), uint32(ev.Fd))

		return ev, nil

	case "fchmod":
		ev := FchmodEvent{}
		ev.Fd = uint64(binary.LittleEndian.Uint64(buf.Next(8)))
		fileName := "unknown"
		info, ok := ctx.Fds.Get(uint32(ce.Pid), uint32(ev.Fd))
		if ok {
			var stat syscall.Stat_t
			path := filepath.Join("/proc", strconv.FormatInt(int64(ce.Pid), 10), "root", info.Path)
			err := syscall.Stat(path, &stat)
			if err != nil {
				if err == syscall.ENOENT {
					// the file doesn't exist anymore, it's probably "info.Path"
					// but we're not sure
					fileName = fmt.Sprintf("[deleted] (%q)?", info.Path)
				}
			}
			if info.Ino == stat.Ino &&
				info.Major == stat.Dev>>8 &&
				info.Minor == stat.Dev&0xff {
				fileName = info.Path
			}
		}
		ev.FdPath = fileName
		ev.Mode = uint64(binary.LittleEndian.Uint64(buf.Next(8)))

		return ev, nil

	case "fchmodat":
		ev := FchmodatEvent{}
		ev.Dfd = int64(binary.LittleEndian.Uint64(buf.Next(8)))
		copy(ev.Filename[:], buf.Next(256))
		ev.Mode = uint64(binary.LittleEndian.Uint64(buf.Next(8)))

		return ev, nil

	case "fchown":
		ev := FchownEvent{}
		ev.Fd = uint64(binary.LittleEndian.Uint64(buf.Next(8)))
		fileName := "unknown"
		info, ok := ctx.Fds.Get(uint32(ce.Pid), uint32(ev.Fd))
		if ok {
			var stat syscall.Stat_t
			path := filepath.Join("/proc", strconv.FormatInt(int64(ce.Pid), 10), "root", info.Path)
			err := syscall.Stat(path, &stat)
			if err != nil {
				if err == syscall.ENOENT {
					// the file doesn't exist anymore, it's probably "info.Path"
					// but we're not sure
					fileName = fmt.Sprintf("[deleted] (%q)?", info.Path)
				}
			}
			if info.Ino == stat.Ino &&
				info.Major == stat.Dev>>8 &&
				info.Minor == stat.Dev&0xff {
				fileName = info.Path
			}
		}
		ev.FdPath = fileName
		ev.User = uint32(binary.LittleEndian.Uint32(buf.Next(4)))
		ev.Group = uint32(binary.LittleEndian.Uint32(buf.Next(4)))

		return ev, nil

	case "fchownat":
		ev := FchownatEvent{}
		ev.Dfd = int64(binary.LittleEndian.Uint64(buf.Next(8)))
		copy(ev.Filename[:], buf.Next(256))
		ev.User = uint32(binary.LittleEndian.Uint32(buf.Next(4)))
		ev.Group = uint32(binary.LittleEndian.Uint32(buf.Next(4)))
		ev.Flag = int64(binary.LittleEndian.Uint64(buf.Next(8)))

		return ev, nil

	case "mkdir":
		ev := MkdirEvent{}
		copy(ev.Pathname[:], buf.Next(256))
		ev.Mode = uint64(binary.LittleEndian.Uint64(buf.Next(8)))

		return ev, nil

	case "mkdirat":
		ev := MkdiratEvent{}
		ev.Dfd = int64(binary.LittleEndian.Uint64(buf.Next(8)))
		copy(ev.Pathname[:], buf.Next(256))
		ev.Mode = uint64(binary.LittleEndian.Uint64(buf.Next(8)))

		return ev, nil

	case "open":
		ev := OpenEvent{}
		copy(ev.Filename[:], buf.Next(256))
		ev.Flags = int64(binary.LittleEndian.Uint64(buf.Next(8)))
		ev.Mode = uint64(binary.LittleEndian.Uint64(buf.Next(8)))

		return ev, nil

	case "read":
		ev := ReadEvent{}
		ev.Fd = uint64(binary.LittleEndian.Uint64(buf.Next(8)))
		fileName := "unknown"
		info, ok := ctx.Fds.Get(uint32(ce.Pid), uint32(ev.Fd))
		if ok {
			var stat syscall.Stat_t
			path := filepath.Join("/proc", strconv.FormatInt(int64(ce.Pid), 10), "root", info.Path)
			err := syscall.Stat(path, &stat)
			if err != nil {
				if err == syscall.ENOENT {
					// the file doesn't exist anymore, it's probably "info.Path"
					// but we're not sure
					fileName = fmt.Sprintf("[deleted] (%q)?", info.Path)
				}
			}
			if info.Ino == stat.Ino &&
				info.Major == stat.Dev>>8 &&
				info.Minor == stat.Dev&0xff {
				fileName = info.Path
			}
		}
		ev.FdPath = fileName
		copy(ev.Buf[:], buf.Next(256))
		ev.Count = int64(binary.LittleEndian.Uint64(buf.Next(8)))

		return ev, nil

	case "write":
		ev := WriteEvent{}
		ev.Fd = uint64(binary.LittleEndian.Uint64(buf.Next(8)))
		fileName := "unknown"
		info, ok := ctx.Fds.Get(uint32(ce.Pid), uint32(ev.Fd))
		if ok {
			var stat syscall.Stat_t
			path := filepath.Join("/proc", strconv.FormatInt(int64(ce.Pid), 10), "root", info.Path)
			err := syscall.Stat(path, &stat)
			if err != nil {
				if err == syscall.ENOENT {
					// the file doesn't exist anymore, it's probably "info.Path"
					// but we're not sure
					fileName = fmt.Sprintf("[deleted] (%q)?", info.Path)
				}
			}
			if info.Ino == stat.Ino &&
				info.Major == stat.Dev>>8 &&
				info.Minor == stat.Dev&0xff {
				fileName = info.Path
			}
		}
		ev.FdPath = fileName
		copy(ev.Buf[:], buf.Next(256))
		ev.Count = int64(binary.LittleEndian.Uint64(buf.Next(8)))

		return ev, nil

	// file events
	case "fd_install":
		ev := FileEvent{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		name, err := procLookupPath(uint32(ce.Pid), uint32(ev.Fd))
		if err != nil {
			name = "unknown"
		}

		fdInfo := FdInfo{Path: name, Ino: ev.Ino, Major: ev.Major, Minor: ev.Minor}

		// ignore entries not backed by files, like sockets or anonymous inodes
		if strings.HasPrefix(fdInfo.Path, "/") {
			ctx.Fds.Put(uint32(ce.Pid), uint32(ev.Fd), fdInfo)
		}

		return ev, nil
	// network events
	case "close_v4":
		fallthrough
	case "accept_v4":
		fallthrough
	case "connect_v4":
		ev := ConnectV4Event{}
		ev.Saddr = binary.LittleEndian.Uint32(buf.Next(4))
		ev.Daddr = binary.LittleEndian.Uint32(buf.Next(4))
		ev.Sport = binary.LittleEndian.Uint16(buf.Next(2))
		ev.Dport = binary.LittleEndian.Uint16(buf.Next(2))
		ev.Netns = binary.LittleEndian.Uint32(buf.Next(4))
		return ev, nil
	case "close_v6":
		fallthrough
	case "accept_v6":
		fallthrough
	case "connect_v6":
		ev := ConnectV6Event{}
		copy(ev.Saddr[:], buf.Next(16))
		copy(ev.Daddr[:], buf.Next(16))
		ev.Sport = binary.LittleEndian.Uint16(buf.Next(2))
		ev.Dport = binary.LittleEndian.Uint16(buf.Next(2))
		ev.Netns = binary.LittleEndian.Uint32(buf.Next(4))
		return ev, nil
	default:
		return DefaultEvent{}, nil
	}
}

// network events structs

type ConnectV4Event struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
	Netns uint32
}

type ConnectV6Event struct {
	Saddr [16]byte
	Daddr [16]byte
	Sport uint16
	Dport uint16
	Netns uint32
}

// network events string functions

func (e ConnectV4Event) String(ret int64) string {
	return fmt.Sprintf("Saddr %s Daddr %s Sport %d Dport %d Netns %d ", inet_ntoa(e.Saddr),
		inet_ntoa(e.Daddr), e.Sport, e.Dport, e.Netns)
}

func (e ConnectV6Event) String(ret int64) string {
	return fmt.Sprintf("Saddr %s Daddr %s Sport %d Dport %d Netns %d ", inet_ntoa6(e.Saddr),
		inet_ntoa6(e.Daddr), e.Sport, e.Dport, e.Netns)
}

func (e ConnectV4Event) Metric() *Metric {
	return &Metric{
		ConnectV4Event: &ProtobufConnectV4Event{
			Saddr: e.Saddr,
			Daddr: e.Daddr,
			Sport: uint32(e.Sport),
			Dport: uint32(e.Dport),
			Netns: e.Netns,
		},
	}
}

func (e ConnectV6Event) Metric() *Metric {
	return &Metric{
		ConnectV6Event: &ProtobufConnectV6Event{
			Saddr: inet_ntoa6(e.Saddr),
			Daddr: inet_ntoa6(e.Daddr),
			Sport: uint32(e.Sport),
			Dport: uint32(e.Dport),
			Netns: e.Netns,
		},
	}
}

// network helper functions

func inet_ntoa(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func inet_ntoa6(ip [16]byte) string {
	return fmt.Sprintf("%v", net.IP(ip[:]))
}

func (e ChmodEvent) Metric() *Metric {
	return &Metric{
		ChmodEvent: &ProtobufChmodEvent{
			Filename: e.Filename[:],
			Mode:     e.Mode,
		},
	}
}

func (e ChownEvent) Metric() *Metric {
	return &Metric{
		ChownEvent: &ProtobufChownEvent{
			Filename: e.Filename[:],
			User:     e.User,
			Group:    e.Group,
		},
	}
}

func (e CloseEvent) Metric() *Metric {
	return &Metric{
		CloseEvent: &ProtobufCloseEvent{
			Fd: e.Fd,
		},
	}
}

func (e FchmodEvent) Metric() *Metric {
	return &Metric{
		FchmodEvent: &ProtobufFchmodEvent{
			Fd:   e.Fd,
			Mode: e.Mode,
		},
	}
}

func (e FchmodatEvent) Metric() *Metric {
	return &Metric{
		FchmodatEvent: &ProtobufFchmodatEvent{
			Dfd:      e.Dfd,
			Filename: e.Filename[:],
			Mode:     e.Mode,
		},
	}
}

func (e FchownEvent) Metric() *Metric {
	return &Metric{
		FchownEvent: &ProtobufFchownEvent{
			Fd:    e.Fd,
			User:  e.User,
			Group: e.Group,
		},
	}
}

func (e FchownatEvent) Metric() *Metric {
	return &Metric{
		FchownatEvent: &ProtobufFchownatEvent{
			Dfd:      e.Dfd,
			Filename: e.Filename[:],
			User:     e.User,
			Group:    e.Group,
			Flag:     e.Flag,
		},
	}
}

func (e MkdirEvent) Metric() *Metric {
	return &Metric{
		MkdirEvent: &ProtobufMkdirEvent{
			Pathname: e.Pathname[:],
			Mode:     e.Mode,
		},
	}
}

func (e MkdiratEvent) Metric() *Metric {
	return &Metric{
		MkdiratEvent: &ProtobufMkdiratEvent{
			Dfd:      e.Dfd,
			Pathname: e.Pathname[:],
			Mode:     e.Mode,
		},
	}
}

func (e OpenEvent) Metric() *Metric {
	return &Metric{
		OpenEvent: &ProtobufOpenEvent{
			Filename: e.Filename[:],
			Flags:    e.Flags,
			Mode:     e.Mode,
		},
	}
}

func (e ReadEvent) Metric() *Metric {
	return &Metric{
		ReadEvent: &ProtobufReadEvent{
			Fd:    e.Fd,
			Buf:   e.Buf[:],
			Count: e.Count,
		},
	}
}

func (e WriteEvent) Metric() *Metric {
	return &Metric{
		WriteEvent: &ProtobufWriteEvent{
			Fd:    e.Fd,
			Buf:   e.Buf[:],
			Count: e.Count,
		},
	}
}

// file events struct

type FileEvent struct {
	Fd    uint64
	Ino   uint64
	Major uint64
	Minor uint64
}
