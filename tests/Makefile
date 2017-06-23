.PHONY: all

all: cli $(patsubst %.c, %, $(shell find . -name '*.c'))

cli: .FORCE

.FORCE:
	go build -a -o cli cli.go

%: %.c
	gcc -o $@ $^
