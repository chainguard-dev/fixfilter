package grype

import (
	"encoding/json"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/pkg/errors"
	"io"
)

func ResultFromJSON(grypeJSON io.Reader) (*models.Document, error) {
	dec := json.NewDecoder(grypeJSON)

	document := &models.Document{}
	err := dec.Decode(document)
	if err != nil {
		return nil, errors.Wrap(err, "unable to process Grype JSON output")
	}

	return document, nil
}
