FROM fedora:26

ENV GOPATH /go

RUN dnf install -y llvm clang kernel-devel make binutils golang go-bindata git file which

RUN mkdir -p /src /go/src/github.com/ShiftLeftSecurity/traceleft
