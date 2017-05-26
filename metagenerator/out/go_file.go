package main

import (
	"syscall"
	"unsafe"
)

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
	Timestamp uint64
	Pid int64
	Ret int64
	Filename [256]byte
	Mode uint64
}

type ChownEvent struct {
	Timestamp uint64
	Pid int64
	Ret int64
	Filename [256]byte
	User int64
	Group int64
}

type CloseEvent struct {
	Timestamp uint64
	Pid int64
	Ret int64
	Fd uint64
}

type FchmodEvent struct {
	Timestamp uint64
	Pid int64
	Ret int64
	Fd uint64
	Mode uint64
}

type FchmodatEvent struct {
	Timestamp uint64
	Pid int64
	Ret int64
	Dfd int64
	Filename [256]byte
	Mode uint64
}

type FchownEvent struct {
	Timestamp uint64
	Pid int64
	Ret int64
	Fd uint64
	User int64
	Group int64
}

type FchownatEvent struct {
	Timestamp uint64
	Pid int64
	Ret int64
	Dfd int64
	Filename [256]byte
	User int64
	Group int64
	Flag int64
}

type MkdirEvent struct {
	Timestamp uint64
	Pid int64
	Ret int64
	Pathname [256]byte
	Mode uint64
}

type MkdiratEvent struct {
	Timestamp uint64
	Pid int64
	Ret int64
	Dfd int64
	Pathname [256]byte
	Mode uint64
}

type OpenEvent struct {
	Timestamp uint64
	Pid int64
	Ret int64
	Filename [256]byte
	Flags int64
	Mode uint64
}

type ReadEvent struct {
	Timestamp uint64
	Pid int64
	Ret int64
	Fd uint64
	Buf [256]byte
	Count int64
}

type WriteEvent struct {
	Timestamp uint64
	Pid int64
	Ret int64
	Fd uint64
	Buf [256]byte
	Count int64
}
