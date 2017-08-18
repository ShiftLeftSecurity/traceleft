FROM fedora:26

ENV GOPATH /go

RUN dnf install -y llvm clang kernel-devel make binutils golang go-bindata git file which protobuf-compiler

RUN dnf list kernel-devel | awk '/^kernel-devel\..*/{print "/usr/src/kernels/"$2".x86_64"}' > /usr/src/kernel-package.txt

RUN mkdir -p /src /go/src/github.com/ShiftLeftSecurity/traceleft
