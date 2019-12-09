package flip

import (
	"fmt"
	"path/filepath"
	"os"
	"syscall"
	"strconv"

	"github.com/pendulm/fileflip/pkg/env"
	"github.com/pendulm/fileflip/pkg/log"
	"github.com/pendulm/fileflip/pkg/ptrace"
)

var rolledSuffix string
var pageSize int = os.Getpagesize()

func init() {
	suffix := os.Getenv("FILEFLIP_SUFFIX")
	if suffix != "" {
		rolledSuffix = suffix
	} else {
		rolledSuffix = ".flipped"
	}
}

// RunForFile rollover a file in process
func RunForFile(pid int, filePath string) {
	var tmpFd int64

	filePath, origFd := preflightCheck(pid, filePath)

	mode := rollover(filePath)

	trace := ptrace.NewChild(pid)
	trace.Setup()

	flag, err := trace.RemoteSyscall(
		syscall.SYS_FCNTL,
		uint64(origFd),
		syscall.F_GETFL, 0)
	if err != nil {
		rollback(filePath)
		log.Die("fcntl F_GETFL error: %s\n", err)
	}

	childAddr, err := trace.RemoteSyscall(
		syscall.SYS_MMAP,
		0,
		uint64(pageSize),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE,
		0,
		0)
	if err != nil {
		rollback(filePath)
		log.Die("mmap error: %s\n", err)
	}

	filePathBytes := []byte(filePath)
	filePathBytes = append(filePathBytes, 0)

	if err := trace.RemoteMemcp(
		filePathBytes,
		uintptr(childAddr),
		len(filePath)+1); err != nil {
		rollback(filePath)
		goto sweepUp
	}

	tmpFd, err = trace.RemoteSyscall(
		syscall.SYS_OPEN,
		uint64(childAddr),
		uint64(flag|syscall.O_CREAT),
		uint64(mode))
	if err != nil {
		rollback(filePath)
		log.Error("open error: %s\n", err)
		goto sweepUp
	}

	_, err = trace.RemoteSyscall(syscall.SYS_DUP2, uint64(tmpFd), uint64(origFd))
	if err != nil {
		log.Error("dup2 error: %s\n", err)
		goto sweepUp
	}
	_, err = trace.RemoteSyscall(syscall.SYS_CLOSE, uint64(tmpFd))
	if err != nil {
		log.Error("close error: %s\n", err)
		goto sweepUp
	}

sweepUp:
	_, err = trace.RemoteSyscall(
		syscall.SYS_MUNMAP,
		uint64(childAddr),
		uint64(pageSize),
		0, 0, 0, 0)
	if err != nil {
		log.Error("munmap error: %s\n", err)
	}
	trace.Cleanup()
}

func getOpenedFds(pid int, filePath string) []int {
	procPath := fmt.Sprintf("/proc/%d/fd", pid)
	matchedFds := []int{}

	dirFile, err := os.Open(procPath)
	if err != nil {
		log.Die("%s\n", err)
	}

	names, err := dirFile.Readdirnames(0)
	if err != nil {
		log.Die("%s\n", err)
	}

	for _, name := range names {
		fdPath := fmt.Sprintf("/proc/%d/fd/%s", pid, name)
		openFilePath, err := os.Readlink(fdPath)
		if err != nil {
			log.Die("%s\n", err)
		}

		if openFilePath == filePath {
			fd, err := strconv.Atoi(name)
			if err != nil {
				log.Error("can't get fd number from %s\n", fdPath)
				continue
			}
			matchedFds = append(matchedFds, fd)
		}
	}
	dirFile.Close()
	return matchedFds
}

func rollover(filePath string) os.FileMode {
	var fInfo os.FileInfo
	fInfo, err := os.Stat(filePath)
	if err != nil {
		log.Die("%s\n", err)
	}

	rolledPath := fmt.Sprintf("%s%s", filePath, rolledSuffix)
	if _, err := os.Stat(rolledPath); err == nil {
		log.Die("file %s already exsits\n", rolledPath)
	}

	if err := os.Rename(filePath, rolledPath); err != nil {
		log.Die("%s\n", err)
	}
	return fInfo.Mode()
}

func rollback(filePath string) {
	rolledPath := fmt.Sprintf("%s%s", filePath, rolledSuffix)
	if _, err := os.Stat(rolledPath); err != nil {
		log.Error("file %s not exsits\n", rolledPath)
		return
	}
	if _, err := os.Stat(filePath); err == nil {
		log.Error("file %s already exsits\n", filePath)
		return
	}
	if err := os.Rename(filePath, rolledPath); err != nil {
		log.Error("%s\n", err)
	}
}

func detectAmd64Linux() bool {
	arch := []byte{}
	sys := []byte{}

	buf := &syscall.Utsname{}
	syscall.Uname(buf)
	for _, c := range buf.Machine {
		if c == 0 {
			break
		}
		arch = append(arch, byte(c))
	}
	for _, c := range buf.Sysname {
		if c == 0 {
			break
		}
		sys = append(sys, byte(c))
	}

	if string(arch) == "x86_64" && string(sys) == "Linux" {
		return true
	}
	return false
}

func preflightCheck(pid int, filePath string) (string, int) {
	if detectAmd64Linux() == false {
		log.DieWithCode(env.ExitArgs, "%s only works in amd64 Linux\n", os.Args[0])
	}
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		log.DieWithCode(env.ExitArgs, "%s\n", err)
	}
	if _, err := os.Stat(absPath); err != nil {
		log.DieWithCode(env.ExitArgs, "%s\n", err)
	}
	if pid <= 1 {
		log.DieWithCode(env.ExitArgs, "error pid %d\n", pid)
	}
	if len(absPath) >= pageSize {
		log.DieWithCode(env.ExitArgs, "file name too long: %s\n", absPath)
	}

	fds := getOpenedFds(pid, filePath)
	if len(fds) == 0 {
		log.DieWithCode(env.ExitArgs, "can't find file %s opened in process\n", absPath)
	}

	// we only handle the first match
	fd := fds[0]
	return absPath, fd
}
