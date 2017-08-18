UID=$(shell id -u)
GID=$(shell id -g)
SUDO=$(shell echo "sudo -E")

DOCKER_IMAGE?=shiftleftsecurity/builder

.PHONY: all generate

all: generate

# Calling from the root source directory:
# make -C metagenerator TRACER_DIR=$PWD/tracer BATTERY_DIR=$PWD/battery

generate:
	test -d "$(TRACER_DIR)" && test -d "$(BATTERY_DIR)"
	$(SUDO) go run cli/main.go event_structs_go event_structs.proto event_structs_c
	$(SUDO) chown $(UID):$(GID) event_structs_go event_structs.proto event_structs_c
	mv event_structs_go $(TRACER_DIR)/event-structs-generated.go
	mv event_structs.proto $(TRACER_DIR)/event-structs-generated.proto
	mv event_structs_c $(BATTERY_DIR)/event-structs-generated.h
	$(SUDO) docker run --rm \
		-v $(TRACER_DIR):/src/tracer \
		--workdir=/src/tracer \
		$(DOCKER_IMAGE) \
		bash -c \
		'export PATH=$$GOPATH/bin:$$PATH && \
		go get -u github.com/golang/protobuf/protoc-gen-go && \
		protoc -I /src/tracer/ --go_out=plugins=grpc:/src/tracer/ /src/tracer/event-structs-generated.proto'
	$(SUDO) chown $(UID):$(GID) $(TRACER_DIR)/event-structs-generated.pb.go
	gofmt -w $(TRACER_DIR)/event-structs-generated.go $(TRACER_DIR)/event-structs-generated.pb.go
