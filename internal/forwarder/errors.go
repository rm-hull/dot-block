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
	if e.Err != nil {
		return e.Err.Error()
	}
	return "dns rcode error: " + dns.RcodeToString[e.Rcode]
}

func (e *RcodeError) Unwrap() error {
	return e.Err
}

func (e *RcodeError) ShouldLog() bool {
	return e.Rcode != dns.RcodeNameError
}

func ShouldLog(err error) bool {
	if err == nil {
		return false
	}
	var loggable interface{ ShouldLog() bool }
	if errors.As(err, &loggable) {
		return loggable.ShouldLog()
	}
	return true
}
