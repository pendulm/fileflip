package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const (
	bit7thSet = 0x80
	pageSize  = 4096
	// ulong(-4095)
	maxErrnoValue uint64 = 18446744073709547521
	// __WALL flag does not include the WSTOPPED
	// and WEXITED flags, but implies their functionality
	waitOptWALL = 0x40000000
)

const (
	exitOk = iota
	exitArgs
	exitErr
	exitIgn
)

const (
	childRunning = iota
	childSignalDelivery
	childSyscallEnter
	childSyscallExit
	childExited
	childKilled
)

func debugToggle() bool {
	if os.Getenv("FILEFLIP_DEBUG") != "" {
		return true
	}
	return false
}

func getEnvSuffix() string {
	suffix := os.Getenv("FILEFLIP_SUFFIX")
	if suffix != "" {
		return suffix
	}
	return ".flipped"
}

var (
	debugEnable  bool   = debugToggle()
	rolledSuffix string = getEnvSuffix()
)

func debugPrintf(format string, v ...interface{}) {
	if debugEnable == false {
		return
	}
	unixNano := time.Now().UnixNano()
	fmt.Fprintf(os.Stderr, "%v debug: ", unixNano)
	if v == nil {
		fmt.Fprintf(os.Stderr, format)
	} else {
		fmt.Fprintf(os.Stderr, format, v...)
	}
}

// PtraceChild include common methods for control target process and
// mask tracing status internally
type PtraceChild struct {
	// pid is child pid
	pid int
	// childState store ptrace state of pid
	childState int
	// savedRegs keeps registers before syscall and
	// restore it after our action was done
	savedRegs *syscall.PtraceRegs
	// savedSignal keep comming signal for inject again
	savedSignal syscall.Signal
	// attached is a flag means we wait for first SIGSTOP
	attached bool
}

// NewPtraceChild return a new PtraceChild form given pid
func NewPtraceChild(pid int) *PtraceChild {
	return &PtraceChild{
		pid:         pid,
		childState:  childRunning,
		savedRegs:   nil,
		savedSignal: 0,
		attached:    false,
	}
}

func (pt *PtraceChild) setup() {
	debugPrintf("setup attaching\n")
	switch pt.childState {
	case childExited, childKilled:
		fmt.Fprintf(os.Stderr, "process %d quit by killed or exited\n", pt.pid)
		os.Exit(exitErr)
	case childRunning:
		if pt.attached == false {
			if err := syscall.PtraceAttach(pt.pid); err != nil {
				fmt.Fprintf(os.Stderr, "attach %d failed: %s\n", pt.pid, err)
				os.Exit(exitErr)
			}
		} else {
			if err := syscall.Kill(pt.pid, syscall.SIGSTOP); err != nil {
				fmt.Fprintf(os.Stderr, "send SIGSTOP to %d failed: %s\n", pt.pid, err)
				os.Exit(exitErr)
			}
		}
		pt.waitChild()
	default:
		break
	}

	if err := syscall.PtraceSetOptions(
		pt.pid, syscall.PTRACE_O_TRACESYSGOOD); err != nil {
		fmt.Fprintf(os.Stderr, "ptrace set option error: %s", err)
		os.Exit(exitErr)
	}
}

func (pt *PtraceChild) cleanup() {
	switch pt.childState {
	case childExited, childKilled:
		fmt.Fprintf(os.Stderr, "process %d quit by killed or exited\n", pt.pid)
		os.Exit(exitErr)
	case childRunning:
		if pt.attached == false {
			return
		}
		if err := syscall.Kill(pt.pid, syscall.SIGSTOP); err != nil {
			fmt.Fprintf(os.Stderr, "send SIGSTOP to %d failed: %s\n", pt.pid, err)
			os.Exit(exitErr)
		}
		pt.waitChild()
	default:
		break
	}
	if err := syscall.PtraceDetach(pt.pid); err != nil {
		fmt.Fprintf(os.Stderr, "detach %d failed: %s\n", pt.pid, err)
		os.Exit(exitErr)
	}
	pt.attached = false
	debugPrintf("cleanup detached\n")
}

func (pt *PtraceChild) waitChild() {
	wstatus := new(syscall.WaitStatus)

	debugPrintf("waitChild enter with status: %d\n", pt.childState)
	wpid, err := syscall.Wait4(pt.pid, wstatus, waitOptWALL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "waiting child error: %s\n", err)
		// exit and just leave kernel to detach the child
		os.Exit(exitErr)
	}
	if wpid != pt.pid {
		fmt.Fprintf(os.Stderr, "expect %d but wait retured %d\n", pt.pid, wpid)
	}

	var sig syscall.Signal

	switch {
	case wstatus.Exited():
		pt.childState = childExited
		debugPrintf("wait notified with status: childExited\n")
	case wstatus.Signaled():
		sig = wstatus.Signal()
		pt.childState = childKilled
		if sig == syscall.SIGKILL {
			// unstoppable kill
			debugPrintf("wait notified with status: childKilled\n")
		} else {
			// killed by signal injected
			panic("all signal suppressed, this should not happend\n")
		}
	case wstatus.Stopped():
		// no PTRACE_O_TRACE_* option is turned on, so no PTRACE_EVENT occurs
		sig = wstatus.StopSignal()
		// syscall-stop
		if sig == syscall.SIGTRAP|bit7thSet {
			if pt.childState != childSyscallEnter {
				pt.childState = childSyscallEnter
				debugPrintf("wait notified with status: childSyscallEnter\n")
			} else {
				pt.childState = childSyscallExit
				debugPrintf("wait notified with status: childSyscallExit\n")
			}
		} else {
			// we suppress all signal and wait for first SIGSTOP
			if pt.attached == false && sig == syscall.SIGSTOP {
				pt.attached = true
			}
			pt.savedSignal = sig
			pt.childState = childSignalDelivery
			debugPrintf("wait notified with status: childSignalDelivery(%d)\n", sig)
		}
	case wstatus.Continued():
		panic("waitpid without WCONTINUED, this should not happend\n")
	default:
		panic(fmt.Sprintf("unknown wait status: %d, this should not happend\n", wstatus))
	}
}

func printRegs(reg *syscall.PtraceRegs) {
	fmt.Printf("R15 = %v\t", reg.R15)
	fmt.Printf("R14 = %v\t", reg.R14)
	fmt.Printf("R13 = %v\t", reg.R13)
	fmt.Printf("R12 = %v\t", reg.R12)
	fmt.Printf("Rbp = %v\t", reg.Rbp)
	fmt.Printf("Rbx = %v\t", reg.Rbx)
	fmt.Printf("R11 = %v\t", reg.R11)
	fmt.Printf("R10 = %v\t", reg.R10)
	fmt.Printf("R9 = %v\t", reg.R9)
	fmt.Printf("R8 = %v\t", reg.R8)
	fmt.Printf("Rax = %v\t", reg.Rax)
	fmt.Printf("Rcx = %v\t", reg.Rcx)
	fmt.Printf("Rdx = %v\t", reg.Rdx)
	fmt.Printf("Rsi = %v\t", reg.Rsi)
	fmt.Printf("Rdi = %v\t", reg.Rdi)
	fmt.Printf("Orig_rax = %v\t", reg.Orig_rax)
	fmt.Printf("Rip = %v\t", reg.Rip)
	fmt.Printf("Cs = %v\t", reg.Cs)
	fmt.Printf("Eflags = %v\t", reg.Eflags)
	fmt.Printf("Rsp = %v\t", reg.Rsp)
	fmt.Printf("Ss = %v\t", reg.Ss)
	fmt.Printf("Fs_base = %v\t", reg.Fs_base)
	fmt.Printf("Gs_base = %v\t", reg.Gs_base)
	fmt.Printf("Ds = %v\t", reg.Ds)
	fmt.Printf("Es = %v\t", reg.Es)
	fmt.Printf("Fs = %v\t", reg.Fs)
	fmt.Printf("Gs = %v\n", reg.Gs)
}

// catchSyscall wait for child issue next syscall, after that
// we can play our magic
func (pt *PtraceChild) catchSyscall() {
	for {
		debugPrintf("catchSyscall loop current state: %d\n", pt.childState)
		if pt.childState == childSyscallEnter {
			break
		}
		if err := syscall.PtraceSyscall(pt.pid, 0); err != nil {
			fmt.Fprintf(os.Stderr, "catchSyscall resume syscall failed: %s\n", err)
			os.Exit(exitErr)
		}
		pt.waitChild()
		debugPrintf("catchSyscall loop new state: %d\n", pt.childState)
	}

	if pt.savedRegs != nil {
		return
	}
	pt.savedRegs = &syscall.PtraceRegs{}

	if err := syscall.PtraceGetRegs(pt.pid, pt.savedRegs); err != nil {
		fmt.Fprintf(os.Stderr, "save catched syscall failed: %s\n", err)
		os.Exit(exitErr)
	}
}

func (pt *PtraceChild) resumeSyscall() {
	if err := syscall.PtraceSetRegs(pt.pid, pt.savedRegs); err != nil {
		fmt.Fprintf(os.Stderr, "resume syscall failed: %s\n", err)
		os.Exit(exitErr)
	}
}

func (pt *PtraceChild) remoteMemcp(src []byte, addr uintptr, size int) error {
	count, err := syscall.PtracePokeData(pt.pid, addr, src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "memcp to child error: %s\n", err)
		return err
	}
	if count != size {
		fmt.Fprintf(os.Stderr, "memcp %d bytes but only successed %d bytes\n", size, count)
		return syscall.EINVAL
	}
	return nil
}

func (pt *PtraceChild) remoteSyscall(nr int, args ...uint64) (int64, error) {
	if debugEnable == true {
		format := "remoteSyscall invoke nr=%d"
		if args == nil {
			debugPrintf(format+"\n", nr)
		} else {
			for i := range args {
				endl := " "
				if i == len(args)-1 {
					endl = "\n"
				}
				format += fmt.Sprintf(" arg%d=%v%s", i, args[i], endl)
			}
			debugPrintf(format, nr)
		}
	}
	// wait for syscall-enter-stop
	pt.catchSyscall()

	reg := &syscall.PtraceRegs{}
	*reg = *pt.savedRegs

	if args != nil {
		// syscall convention:
		// SEE: https://github.com/torvalds/linux/blob/v5.0/arch/x86/entry/entry_64.S#L107
		switch len(args) {
		case 6:
			reg.R9 = args[5]
			fallthrough
		case 5:
			reg.R8 = args[4]
			fallthrough
		case 4:
			reg.R10 = args[3]
			fallthrough
		case 3:
			reg.Rdx = args[2]
			fallthrough
		case 2:
			reg.Rsi = args[1]
			fallthrough
		case 1:
			reg.Rdi = args[0]
		default:
			panic("too many syscall args\n")
		}
	}

	reg.Orig_rax = uint64(nr)

	if err := syscall.PtraceSetRegs(pt.pid, reg); err != nil {
		fmt.Fprintf(os.Stderr, "fill syscall %d regs failed: %s\n", nr, err)
		os.Exit(exitErr)
	}

	if err := syscall.PtraceSyscall(pt.pid, 0); err != nil {
		fmt.Fprintf(os.Stderr, "hijack syscall %d failed: %s\n", nr, err)
		os.Exit(exitErr)
	}
	// wait for syscall-exit-stop
	pt.waitChild()

	if err := syscall.PtraceGetRegs(pt.pid, reg); err != nil {
		fmt.Fprintf(os.Stderr, "get syscall result failed: %s\n", pt.pid, err)
		os.Exit(exitErr)
	}

	rv := reg.Rax
	pt.resumeSyscall()
	debugPrintf("remoteSyscall return nr=%d retval=%v\n", nr, rv)

	if rv > maxErrnoValue {
		return -1, syscall.Errno(-int64(rv))
	}
	return int64(rv), nil
}

func startFlip(pid int, filePath string) {
	var tmpFd int64

	fds := getOpenedFds(pid, filePath)

	if len(fds) == 0 {
		fmt.Fprintf(os.Stderr, "can't find file %s opened in process\n", filePath)
		os.Exit(exitArgs)
	}

	// we only handle the first match
	origFd := fds[0]

	mode := rollover(filePath)

	trace := NewPtraceChild(pid)
	trace.setup()

	flag, err := trace.remoteSyscall(
		syscall.SYS_FCNTL,
		uint64(origFd),
		syscall.F_GETFL, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fcntl F_GETFL error: %s\n", err)
		rollback(filePath)
		os.Exit(exitErr)
	}

	childAddr, err := trace.remoteSyscall(
		syscall.SYS_MMAP,
		0,
		pageSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE,
		0,
		0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mmap error: %s\n", err)
		rollback(filePath)
		os.Exit(exitErr)
	}

	filePathBytes := []byte(filePath)
	filePathBytes = append(filePathBytes, 0)

	if err := trace.remoteMemcp(
		filePathBytes,
		uintptr(childAddr),
		len(filePath)+1); err != nil {
		rollback(filePath)
		goto sweepUp
	}

	tmpFd, err = trace.remoteSyscall(
		syscall.SYS_OPEN,
		uint64(childAddr),
		uint64(flag|syscall.O_CREAT),
		uint64(mode))
	if err != nil {
		fmt.Fprintf(os.Stderr, "open error: %s\n", err)
		rollback(filePath)
		goto sweepUp
	}

	_, err = trace.remoteSyscall(syscall.SYS_DUP2, uint64(tmpFd), uint64(origFd))
	if err != nil {
		fmt.Fprintf(os.Stderr, "dup2 error: %s\n", err)
		goto sweepUp
	}
	_, err = trace.remoteSyscall(syscall.SYS_CLOSE, uint64(tmpFd))
	if err != nil {
		fmt.Fprintf(os.Stderr, "close error: %s\n", err)
		goto sweepUp
	}

sweepUp:
	_, err = trace.remoteSyscall(syscall.SYS_MUNMAP, uint64(childAddr), pageSize, 0, 0, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "munmap error: %s\n", err)
	}
	trace.cleanup()
}

func getOpenedFds(pid int, filePath string) []int {
	procPath := fmt.Sprintf("/proc/%d/fd", pid)
	matchedFds := []int{}

	dirFile, err := os.Open(procPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(exitErr)
	}

	names, err := dirFile.Readdirnames(0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(exitErr)
	}

	for _, name := range names {
		fdPath := fmt.Sprintf("/proc/%d/fd/%s", pid, name)
		openFilePath, err := os.Readlink(fdPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(exitErr)
		}

		if openFilePath == filePath {
			fd, err := strconv.Atoi(name)
			if err != nil {
				fmt.Fprintf(os.Stderr, "can't get fd number from %s\n", fdPath)
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
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(exitErr)
	}

	rolledPath := fmt.Sprintf("%s%s", filePath, rolledSuffix)
	if _, err := os.Stat(rolledPath); err == nil {
		fmt.Fprintf(os.Stderr, "file %s already exsits\n", rolledPath)
		os.Exit(exitErr)
	}

	if err := os.Rename(filePath, rolledPath); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(exitErr)
	}
	return fInfo.Mode()
}

func rollback(filePath string) {
	rolledPath := fmt.Sprintf("%s%s", filePath, rolledSuffix)
	if _, err := os.Stat(rolledPath); err != nil {
		fmt.Fprintf(os.Stderr, "file %s not exsits\n", rolledPath)
		return
	}
	if _, err := os.Stat(filePath); err == nil {
		fmt.Fprintf(os.Stderr, "file %s already exsits\n", filePath)
		os.Exit(exitErr)
		return
	}
	if err := os.Rename(filePath, rolledPath); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: fileflip [PID] [FILE]")
	fmt.Fprintln(os.Stderr, "rotate opened file promptly while nobody knows")
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
	os.Exit(exitArgs)
	return
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

func preflightCheck(pid int, filePath string) string {
	if detectAmd64Linux() == false {
		fmt.Fprintf(os.Stderr, "%s only works in amd64 Linux\n", os.Args[0])
		os.Exit(exitArgs)
	}
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(exitArgs)
	}
	if _, err := os.Stat(absPath); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(exitArgs)
	}
	if pid <= 1 {
		fmt.Fprintf(os.Stderr, "error pid %d\n", pid)
		os.Exit(exitArgs)
	}
	if len(absPath) >= pageSize {
		fmt.Fprintf(os.Stderr, "file name too long: %s\n", absPath)
		os.Exit(exitArgs)
	}
	return absPath
}

func main() {
	pid, filePath := parseArgs()
	absPath := preflightCheck(pid, filePath)
	startFlip(pid, absPath)
	os.Exit(exitOk)
}
