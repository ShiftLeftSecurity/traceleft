UID=$(shell id -u)
GOPATH=$(shell go env GOPATH)
SUDO=$(shell echo "sudo -E")

all: generate

generate:
	mkdir -p out
	$(SUDO) go run parser.go out/go_file out/c_file
	$(SUDO) chown $(UID) out/go_file out/c_file
	mv out/go_file out/go_file.go
	mv out/c_file out/c_file.h
	mv out/c_file.h ../battery/event_structs.h
