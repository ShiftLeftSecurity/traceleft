UID=$(shell id -u)
GOPATH=$(shell go env GOPATH)
SUDO=$(shell echo "sudo -E")

all: generate

generate:
	mkdir -p out
	$(SUDO) go run parser.go out/go_file out/c_file ../config.json
	$(SUDO) chown $(UID) out/go_file out/c_file
	mv out/go_file out/go_file.go
	mv out/c_file out/c_file.h
	mv out/c_file.h ../battery/event_structs.h
	mv out/go_file.go ../tracer/event_structs.go
	rm -rf out
