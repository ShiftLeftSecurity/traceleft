// Code generated by protoc-gen-go. DO NOT EDIT.
// source: config.proto

/*
Package generator is a generated protocol buffer package.

It is generated from these files:
	config.proto

It has these top-level messages:
	Event
	Config
*/
package generator

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Event struct {
	Name string        `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	Args []*Event_Args `protobuf:"bytes,2,rep,name=args" json:"args,omitempty"`
}

func (m *Event) Reset()                    { *m = Event{} }
func (m *Event) String() string            { return proto.CompactTextString(m) }
func (*Event) ProtoMessage()               {}
func (*Event) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Event) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Event) GetArgs() []*Event_Args {
	if m != nil {
		return m.Args
	}
	return nil
}

type Event_Args struct {
	Position uint32 `protobuf:"varint,1,opt,name=position" json:"position,omitempty"`
	Type     string `protobuf:"bytes,2,opt,name=type" json:"type,omitempty"`
	Name     string `protobuf:"bytes,3,opt,name=name" json:"name,omitempty"`
	Suffix   string `protobuf:"bytes,4,opt,name=suffix" json:"suffix,omitempty"`
	HashFunc string `protobuf:"bytes,5,opt,name=hashFunc" json:"hashFunc,omitempty"`
}

func (m *Event_Args) Reset()                    { *m = Event_Args{} }
func (m *Event_Args) String() string            { return proto.CompactTextString(m) }
func (*Event_Args) ProtoMessage()               {}
func (*Event_Args) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0, 0} }

func (m *Event_Args) GetPosition() uint32 {
	if m != nil {
		return m.Position
	}
	return 0
}

func (m *Event_Args) GetType() string {
	if m != nil {
		return m.Type
	}
	return ""
}

func (m *Event_Args) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Event_Args) GetSuffix() string {
	if m != nil {
		return m.Suffix
	}
	return ""
}

func (m *Event_Args) GetHashFunc() string {
	if m != nil {
		return m.HashFunc
	}
	return ""
}

type Config struct {
	Event []*Event `protobuf:"bytes,1,rep,name=event" json:"event,omitempty"`
}

func (m *Config) Reset()                    { *m = Config{} }
func (m *Config) String() string            { return proto.CompactTextString(m) }
func (*Config) ProtoMessage()               {}
func (*Config) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *Config) GetEvent() []*Event {
	if m != nil {
		return m.Event
	}
	return nil
}

func init() {
	proto.RegisterType((*Event)(nil), "generator.Event")
	proto.RegisterType((*Event_Args)(nil), "generator.Event.Args")
	proto.RegisterType((*Config)(nil), "generator.Config")
}

func init() { proto.RegisterFile("config.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 208 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xe2, 0xe2, 0x49, 0xce, 0xcf, 0x4b,
	0xcb, 0x4c, 0xd7, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x4c, 0x4f, 0xcd, 0x4b, 0x2d, 0x4a,
	0x2c, 0xc9, 0x2f, 0x52, 0x3a, 0xc6, 0xc8, 0xc5, 0xea, 0x5a, 0x96, 0x9a, 0x57, 0x22, 0x24, 0xc4,
	0xc5, 0x92, 0x97, 0x98, 0x9b, 0x2a, 0xc1, 0xa8, 0xc0, 0xa8, 0xc1, 0x19, 0x04, 0x66, 0x0b, 0x69,
	0x72, 0xb1, 0x24, 0x16, 0xa5, 0x17, 0x4b, 0x30, 0x29, 0x30, 0x6b, 0x70, 0x1b, 0x89, 0xea, 0xc1,
	0xf5, 0xe9, 0x81, 0xf5, 0xe8, 0x39, 0x16, 0xa5, 0x17, 0x07, 0x81, 0x95, 0x48, 0xd5, 0x71, 0xb1,
	0x80, 0x78, 0x42, 0x52, 0x5c, 0x1c, 0x05, 0xf9, 0xc5, 0x99, 0x25, 0x99, 0xf9, 0x79, 0x60, 0xa3,
	0x78, 0x83, 0xe0, 0x7c, 0x90, 0x15, 0x25, 0x95, 0x05, 0xa9, 0x12, 0x4c, 0x10, 0x2b, 0x40, 0x6c,
	0xb8, 0xb5, 0xcc, 0x48, 0xd6, 0x8a, 0x71, 0xb1, 0x15, 0x97, 0xa6, 0xa5, 0x65, 0x56, 0x48, 0xb0,
	0x80, 0x45, 0xa1, 0x3c, 0x90, 0xd9, 0x19, 0x89, 0xc5, 0x19, 0x6e, 0xa5, 0x79, 0xc9, 0x12, 0xac,
	0x60, 0x19, 0x38, 0x5f, 0xc9, 0x80, 0x8b, 0xcd, 0x19, 0xec, 0x47, 0x21, 0x35, 0x2e, 0xd6, 0x54,
	0x90, 0xeb, 0x24, 0x18, 0xc1, 0xae, 0x16, 0x40, 0x77, 0x75, 0x10, 0x44, 0x3a, 0x89, 0x0d, 0x1c,
	0x18, 0xc6, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0x5b, 0x84, 0x79, 0xb8, 0x1c, 0x01, 0x00, 0x00,
}
