UID=$(shell id -u)
GOPATH=$(shell go env GOPATH)
SUDO=$(shell echo "sudo -E")

.PHONY: all generate

all: generate

generate:
	$(SUDO) go run parser.go ../tracer/event_structs ../battery/event_structs ../config.json
	$(SUDO) chown $(UID) ../tracer/event_structs ../battery/event_structs
	mv ../tracer/event_structs ../tracer/event_structs.go
	mv ../battery/event_structs ../battery/event_structs.h
