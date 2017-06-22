// Generated file, do not edit.
// Source: metagenerator.go

package tracer

import (
	"bytes"
	"encoding/binary"
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

type ChmodEvent struct {
	Filename [256]byte
	Mode     uint64
}

type ChownEvent struct {
	Filename [256]byte
	User     int64
	Group    int64
}

type CloseEvent struct {
	Fd uint64
}

type FchmodEvent struct {
	Fd   uint64
	Mode uint64
}

type FchmodatEvent struct {
	Dfd      int64
	Filename [256]byte
	Mode     uint64
}

type FchownEvent struct {
	Fd    uint64
	User  int64
	Group int64
}

type FchownatEvent struct {
	Dfd      int64
	Filename [256]byte
	User     int64
	Group    int64
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
	Fd    uint64
	Buf   [256]byte
	Count int64
}

type WriteEvent struct {
	Fd    uint64
	Buf   [256]byte
	Count int64
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

type Printable interface {
	String(ret int64) string
}

type DefaultEvent struct{}

func (w DefaultEvent) String(ret int64) string {
	return ""
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

	return fmt.Sprintf("Fd %d ", e.Fd)
}

func (e FchmodEvent) String(ret int64) string {

	return fmt.Sprintf("Fd %d Mode %d ", e.Fd, e.Mode)
}

func (e FchmodatEvent) String(ret int64) string {
	buffer := (*C.char)(unsafe.Pointer(&e.Filename))
	length := C.int(0)
	length = C.int(bufLen(e.Filename))
	bufferGo := C.GoStringN(buffer, length)

	return fmt.Sprintf("Dfd %d Filename %q Mode %d ", e.Dfd, bufferGo, e.Mode)
}

func (e FchownEvent) String(ret int64) string {

	return fmt.Sprintf("Fd %d User %d Group %d ", e.Fd, e.User, e.Group)
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

	return fmt.Sprintf("Fd %d Buf %q Count %d ", e.Fd, bufferGo, e.Count)
}

func (e WriteEvent) String(ret int64) string {
	buffer := (*C.char)(unsafe.Pointer(&e.Buf))
	length := C.int(0)
	if ret > 0 {
		length = C.int(min(int(ret), len(e.Buf)))
	}
	bufferGo := C.GoStringN(buffer, length)

	return fmt.Sprintf("Fd %d Buf %q Count %d ", e.Fd, bufferGo, e.Count)
}

func GetStruct(syscall string, buf *bytes.Buffer) (Printable, error) {
	switch syscall {

	case "chmod":
		ev := ChmodEvent{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		return ev, nil

	case "chown":
		ev := ChownEvent{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		return ev, nil

	case "close":
		ev := CloseEvent{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		return ev, nil

	case "fchmod":
		ev := FchmodEvent{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		return ev, nil

	case "fchmodat":
		ev := FchmodatEvent{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		return ev, nil

	case "fchown":
		ev := FchownEvent{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		return ev, nil

	case "fchownat":
		ev := FchownatEvent{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		return ev, nil

	case "mkdir":
		ev := MkdirEvent{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		return ev, nil

	case "mkdirat":
		ev := MkdiratEvent{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		return ev, nil

	case "open":
		ev := OpenEvent{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		return ev, nil

	case "read":
		ev := ReadEvent{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		return ev, nil

	case "write":
		ev := WriteEvent{}
		if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
			return nil, err
		}
		return ev, nil

	default:
		return DefaultEvent{}, nil
	}
}
