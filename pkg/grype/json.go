package grype

import (
	"encoding/json"
	"fmt"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/chainguard-dev/fixfilter/pkg/parsing/types"
	"github.com/pkg/errors"
	"io"
)

func ParseJSON(r io.Reader) (*types.Report, error) {
	dec := json.NewDecoder(r)

	document := &models.Document{}
	err := dec.Decode(document)
	if err != nil {
		return nil, fmt.Errorf("unable to parse Grype JSON: %w", err)
	}

	if document.Descriptor.Name != "grype" {
		return nil, errors.New("input format does not appear to be Grype JSON")
	}

	var matches []types.Match
	for _, m := range document.Matches {
		matches = append(matches, convert(m))
	}

	report := types.Report{
		Matches: matches,
		Distro:  document.Distro.Name,
	}

	return &report, nil
}

func convert(m models.Match) types.Match {
	p := types.Package{
		Name:    m.Artifact.Name,
		Version: m.Artifact.Version,
		Type:    string(m.Artifact.Type),
	}

	if upstreams := m.Artifact.Upstreams; len(upstreams) == 1 {
		p.Origin = upstreams[0].Name
	}

	return types.Match{
		Package: p,
		Vulnerability: types.Vulnerability{
			ID:       m.Vulnerability.ID,
			Severity: m.Vulnerability.Severity,
		},
	}
}
