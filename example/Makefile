all: build-ebpf-object

build-ebpf-object:
	cd ../bpf && make
	cd bpf-handler && make
	go build
