package main

import (
	"os"
	"strconv"

	"github.com/pendulm/fileflip/pkg/env"
	"github.com/pendulm/fileflip/pkg/flip"
	"github.com/pendulm/fileflip/pkg/log"
)

func usage() {
	log.Error("Usage: fileflip [PID] [FILE]\n")
	log.Error("rotate opened file promptly while nobody knows\n")
}

func parseArgs() (pid int, filePath string) {
	var err error
	if len(os.Args) < 3 {
		goto printUsage
	}

	pid, err = strconv.Atoi(os.Args[1])
	if err != nil {
		goto printUsage
	}

	filePath = os.Args[2]
	return

printUsage:
	usage()
	os.Exit(env.ExitArgs)
	return
}

func main() {
	pid, filePath := parseArgs()
	flip.RunForFile(pid, filePath)
	os.Exit(env.ExitOk)
}
