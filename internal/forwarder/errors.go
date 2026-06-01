package forwarder

import (
	"errors"

	"github.com/miekg/dns"
)

type RcodeError struct {
	Rcode int
	Err   error
}

func (e *RcodeError) Error() string {
	return e.Err.Error()
}

func (e *RcodeError) Unwrap() error {
	return e.Err
}

func (e *RcodeError) ShouldLog() bool {
	return e.Rcode != dns.RcodeNameError
}

func ShouldLog(err error) bool {
	var loggable interface{ ShouldLog() bool }
	if errors.As(err, &loggable) {
		return loggable.ShouldLog()
	}
	return true
}
