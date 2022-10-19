package fixfilter

import (
	"errors"
	"fmt"
	"github.com/anchore/grype/grype/presenter/models"
)

func CheckWolfi(result *models.Document) error {
	if result == nil {
		return errors.New("no Grype result document provided")
	}

	if result.Distro.Name == "wolfi" {
		return nil
	}

	return fmt.Errorf("Grype result document describes a non-Wolfi artifact (reported distro name: %q)", result.Distro.Name)
}
