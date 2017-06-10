UID=$(shell id -u)
GOPATH=$(shell go env GOPATH)
SUDO=$(shell echo "sudo -E")

.PHONY: all generate

all: generate

generate:
	$(SUDO) go run parser.go $(TRACER_DIR)/event_structs $(BATTERY_DIR)/event_structs $(CONFIG_FILE)
	$(SUDO) chown $(UID) $(TRACER_DIR)/event_structs $(BATTERY_DIR)/event_structs
	mv $(TRACER_DIR)/event_structs $(TRACER_DIR)/event_structs.go
	mv $(BATTERY_DIR)/event_structs $(BATTERY_DIR)/event_structs.h
	gofmt -w $(TRACER_DIR)/event_structs.go
