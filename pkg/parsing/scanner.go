package parsing

import "github.com/chainguard-dev/fixfilter/pkg/parsing/types"

func ValidateScanner(expected, detected string) error {
	if expected != detected {
		return types.NewErrWrongParser(expected, detected)
	}

	return nil
}
