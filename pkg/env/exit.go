package env

const (
	// ExitOk is return code for normal exit
	ExitOk = iota
	// ExitArgs is return code for command argument error
	ExitArgs
	// ExitErr is return code for system internal error
	ExitErr
	// ExitIgn has no meaning yet
	ExitIgn
)
