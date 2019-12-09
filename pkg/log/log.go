package log

import (
	"fmt"
	"os"
	"time"

	"github.com/pendulm/fileflip/pkg/env"
)

var debugEnable bool

func init() {
	if os.Getenv("FILEFLIP_DEBUG") != "" {
		debugEnable = true
	} else {
		debugEnable = false
	}
}

// IsDebug use for bypass building expensive debug argument when debug is not toggled
func IsDebug() bool {
	return debugEnable == true
}

// Debug print message with nanosecond timestamp
func Debug(format string, v ...interface{}) {
	if debugEnable == false {
		return
	}
	unixNano := time.Now().UnixNano()
	fmt.Fprintf(os.Stderr, "%v debug: ", unixNano)
	fmt.Fprintf(os.Stderr, format, v...)
}

// DieWithCode print message and exit with specific code
func DieWithCode(code int, format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format, v...)
	os.Exit(code)
}

// Die print message and exit
func Die(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format, v...)
	os.Exit(env.ExitErr)
}

// Error print error message
func Error(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format, v...)
}
