package main

import (
	"fmt"
	"os"

	"github.com/ShiftLeftSecurity/traceleft/metagenerator"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s GO_OUT_FILE PROTO_OUT_FILE H_OUT_FILE\n", os.Args[0])
		os.Exit(1)
	}

	goSyscalls, cSyscalls, protoSyscalls, err := metagenerator.GatherSyscalls()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error gathering syscalls: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Create(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	goStructs, err := metagenerator.GenerateGoStructs(goSyscalls)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating Go structs: %v\n", err)
		os.Exit(1)
	}

	if _, err := f.WriteString(goStructs); err != nil {
		fmt.Fprintf(os.Stderr, "error writing to file %q: %v\n", os.Args[1], err)
		os.Exit(1)
	}

	protof, err := os.Create(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer protof.Close()

	protoStructs, err := metagenerator.GenerateProtoStructs(protoSyscalls, goSyscalls)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating proto structs: %v\n", err)
		os.Exit(1)
	}

	if _, err := protof.WriteString(protoStructs); err != nil {
		fmt.Fprintf(os.Stderr, "error writing to file %q: %v\n", os.Args[2], err)
		os.Exit(1)
	}

	cf, err := os.Create(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer cf.Close()

	cStructs, err := metagenerator.GenerateCStructs(cSyscalls)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating C structs: %v\n", err)
		os.Exit(1)
	}

	if _, err := cf.WriteString(cStructs); err != nil {
		fmt.Fprintf(os.Stderr, "error writing to file %q: %v\n", os.Args[2], err)
		os.Exit(1)
	}
}
