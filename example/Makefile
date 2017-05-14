all: build-ebpf-object

build-ebpf-object:
	cd ../bpf && make
	cd battery && make
	go build
