package gospake2

const (
	// BadSide indicates we got same side while finalizing SPAKE2 asymmetric
	// mode or different side in symmetric mode
	BadSide = 1 << iota

	// WrongLength indicates we got message of length different than expected
	WrongLength = 1 << iota

	// CorruptMessage indicates we got corrupt message while finalizing SPAKE2
	CorruptMessage = 1 << iota

	// ReflectionAttempt indicates attempt to send same pake message as we calculated
	ReflectionAttempt = 2 << iota
)

// SPAKEErr gives error encountered during SPAKE2 calculations
type SPAKEErr struct {
	kind int
	msg  string
}

// NewError creates new SPAKEErr from given kind
func NewError(kind int, msg string) SPAKEErr {
	return SPAKEErr{kind, msg}
}

func (e *SPAKEErr) Error() string {
	return e.msg
}

// Kind returns error kind
func (e *SPAKEErr) Kind() int {
	return e.kind
}
