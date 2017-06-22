UID=$(shell id -u)
GOPATH=$(shell go env GOPATH)
SUDO=$(shell echo "sudo -E")

.PHONY: all generate

all: generate

# Calling from the root source directory:
# make -C metagenerator TRACER_DIR=$PWD/tracer BATTERY_DIR=$PWD/battery

generate:
	test -d "$(TRACER_DIR)" && test -d "$(BATTERY_DIR)"
	$(SUDO) go run cli/main.go event_structs_go event_structs_c
	$(SUDO) chown $(UID) event_structs_go event_structs_c
	mv event_structs_go $(TRACER_DIR)/event_structs.go
	mv event_structs_c $(BATTERY_DIR)/event_structs.h
	gofmt -w $(TRACER_DIR)/event_structs.go
