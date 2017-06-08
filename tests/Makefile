.PHONY: all

all: cli $(patsubst %.c, %, $(shell find . -name '*.c'))

cli:
	go build -o cli cli.go

%: %.c
	gcc -o $@ $^
