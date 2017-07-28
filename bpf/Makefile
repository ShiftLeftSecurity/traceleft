UID=$(shell id -u)
PWD=$(shell pwd)

DOCKER_IMAGE?=shiftleftsecurity/builder

# If you can use docker without being root, you can do "make SUDO="
SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")

.PHONY: all build-ebpf-object install-generated-go

all: build-ebpf-object install-generated-go

build-ebpf-object:
	$(SUDO) docker run --rm \
		-v $(PWD):/src:ro \
		-v $(PWD)/out:/dist/ \
		--workdir=/src \
		$(DOCKER_IMAGE) \
		make -f ebpf.mk
	sudo chown -R $(UID):$(UID) out

install-generated-go:
	cp out/trace-events.go ../probe/trace-events.go

