// +build linux,amd64

package ptrace

import (
	"fmt"
	"syscall"

	"github.com/pendulm/fileflip/pkg/log"
)

const (
	bit7thSet = 0x80
	// ulong(-4095)
	maxErrnoValue uint64 = 18446744073709547521
	// __WALL flag does not include the WSTOPPED
	// and WEXITED flags, but implies their functionality
	waitOptWALL = 0x40000000
)

const (
	childRunning = iota
	childSignalDelivery
	childSyscallEnter
	childSyscallExit
	childExited
	childKilled
)

var childStateStr = map[int]string{
	childRunning:        "childRunning",
	childSignalDelivery: "childSignalDelivery",
	childSyscallEnter:   "childSyscallEnter",
	childSyscallExit:    "childSyscallExit",
	childExited:         "childExited",
	childKilled:         "childKilled",
}

// Child include common methods for control target process and
// mask tracing status internally
type Child struct {
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

// NewChild return a new Child form given pid
func NewChild(pid int) *Child {
	return &Child{
		pid:         pid,
		childState:  childRunning,
		savedRegs:   nil,
		savedSignal: 0,
		attached:    false,
	}
}

// Setup starts attach to child then tracer can control tracee
func (pt *Child) Setup() {
	log.Debug("setup attaching\n")
	switch pt.childState {
	case childExited, childKilled:
		log.Die("process %d quit by killed or exited\n", pt.pid)
	case childRunning:
		if pt.attached == false {
			if err := syscall.PtraceAttach(pt.pid); err != nil {
				log.Die("attach %d failed: %s\n", pt.pid, err)
			}
		} else {
			if err := syscall.Kill(pt.pid, syscall.SIGSTOP); err != nil {
				log.Die("send SIGSTOP to %d failed: %s\n", pt.pid, err)
			}
		}
		pt.waitChild()
	default:
		break
	}

	if err := syscall.PtraceSetOptions(
		pt.pid, syscall.PTRACE_O_TRACESYSGOOD); err != nil {
		log.Die("ptrace set option error: %s", err)
	}
}

// Cleanup detach from child and child continue to run
func (pt *Child) Cleanup() {
	switch pt.childState {
	case childExited, childKilled:
		log.Die("process %d quit by killed or exited\n", pt.pid)
	case childRunning:
		if pt.attached == false {
			return
		}
		if err := syscall.Kill(pt.pid, syscall.SIGSTOP); err != nil {
			log.Die("send SIGSTOP to %d failed: %s\n", pt.pid, err)
		}
		pt.waitChild()
	default:
		break
	}
	if err := syscall.PtraceDetach(pt.pid); err != nil {
		log.Die("detach %d failed: %s\n", pt.pid, err)
	}
	pt.attached = false
	log.Debug("cleanup detached\n")
}

func (pt *Child) waitChild() {
	wstatus := new(syscall.WaitStatus)

	log.Debug("waitChild enter with status: %s\n", childStateStr[pt.childState])
	wpid, err := syscall.Wait4(pt.pid, wstatus, waitOptWALL, nil)
	if err != nil {
		// exit and just leave kernel to detach the child
		log.Die("waiting child error: %s\n", err)
	}
	if wpid != pt.pid {
		log.Error("expect %d but wait retured %d\n", pt.pid, wpid)
	}

	var sig syscall.Signal

	switch {
	case wstatus.Exited():
		pt.childState = childExited
		log.Debug("wait notified with status: childExited\n")
	case wstatus.Signaled():
		sig = wstatus.Signal()
		pt.childState = childKilled
		if sig == syscall.SIGKILL {
			// unstoppable kill
			log.Debug("wait notified with status: childKilled\n")
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
				log.Debug("wait notified with status: childSyscallEnter\n")
			} else {
				pt.childState = childSyscallExit
				log.Debug("wait notified with status: childSyscallExit\n")
			}
		} else {
			// we suppress all signal and wait for first SIGSTOP
			if pt.attached == false && sig == syscall.SIGSTOP {
				pt.attached = true
			}
			pt.savedSignal = sig
			pt.childState = childSignalDelivery
			log.Debug("wait notified with status: childSignalDelivery(%d)\n", sig)
		}
	case wstatus.Continued():
		panic("waitpid without WCONTINUED, this should not happend\n")
	default:
		panic(fmt.Sprintf("unknown wait status: %d, this should not happend\n", wstatus))
	}
}

// catchSyscall wait for child issue next syscall, after that
// we can play our magic
func (pt *Child) catchSyscall() {
	for {
		log.Debug("catchSyscall loop current state: %s\n", childStateStr[pt.childState])
		if pt.childState == childSyscallEnter {
			break
		}
		if err := syscall.PtraceSyscall(pt.pid, 0); err != nil {
			log.Die("catchSyscall resume syscall failed: %s\n", err)
		}
		pt.waitChild()
		log.Debug("catchSyscall loop new state: %s\n", childStateStr[pt.childState])
	}

	if pt.savedRegs != nil {
		return
	}
	pt.savedRegs = &syscall.PtraceRegs{}

	if err := syscall.PtraceGetRegs(pt.pid, pt.savedRegs); err != nil {
		log.Die("save catched syscall failed: %s\n", err)
	}
}

func (pt *Child) resumeSyscall() {
	if err := syscall.PtraceSetRegs(pt.pid, pt.savedRegs); err != nil {
		log.Die("resume syscall failed: %s\n", err)
	}
}

// RemoteMemcp copy date to child's memory
func (pt *Child) RemoteMemcp(src []byte, addr uintptr, size int) error {
	count, err := syscall.PtracePokeData(pt.pid, addr, src)
	if err != nil {
		log.Error("memcp to child error: %s\n", err)
		return err
	}
	if count != size {
		log.Error("memcp %d bytes but only successed %d bytes\n", size, count)
		return syscall.EINVAL
	}
	return nil
}

// RemoteSyscall invoke a syscall on behalf of child
func (pt *Child) RemoteSyscall(nr int, args ...uint64) (int64, error) {
	if log.IsDebug() == true {
		format := "remoteSyscall invoke nr=%d"
		if args == nil {
			log.Debug(format+"\n", nr)
		} else {
			for i := range args {
				endl := " "
				if i == len(args)-1 {
					endl = "\n"
				}
				format += fmt.Sprintf(" arg%d=%v%s", i, args[i], endl)
			}
			log.Debug(format, nr)
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
		log.Die("fill syscall %d regs failed: %s\n", nr, err)
	}

	if err := syscall.PtraceSyscall(pt.pid, 0); err != nil {
		log.Die("hijack syscall %d failed: %s\n", nr, err)
	}
	// wait for syscall-exit-stop
	pt.waitChild()

	if err := syscall.PtraceGetRegs(pt.pid, reg); err != nil {
		log.Die("get syscall result failed: %s\n", err)
	}

	rv := reg.Rax
	log.Debug("remoteSyscall return nr=%d retval=%v\n", nr, rv)

	pt.resumeSyscall()

	if rv > maxErrnoValue {
		return -1, syscall.Errno(-int64(rv))
	}
	return int64(rv), nil
}
