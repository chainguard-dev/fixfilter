package types

import "fmt"

type ErrWrongParser struct {
	// expected is the name of the scanner that the current parser was expecting
	expected string

	// detected is the name of the scanner that was discovered in the input stream
	detected string
}

func NewErrWrongParser(expected, detected string) error {
	return &ErrWrongParser{
		expected: expected,
		detected: detected,
	}
}

func (e ErrWrongParser) Error() string {
	return fmt.Sprintf("parser expected scanner to be %q but detected %q instead", e.expected, e.detected)
}
