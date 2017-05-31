all: build

.PHONY: build

build:
	cd bpf && make
	cd battery && make
	go build -o bin/slagent cli/main.go
