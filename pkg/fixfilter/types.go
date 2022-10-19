package fixfilter

import "github.com/anchore/grype/grype/presenter/models"

type Package struct {
	Name, Version, Type string
}

type Vulnerability struct {
	ID       string
	Severity string
}

type Match struct {
	Package       Package
	Vulnerability Vulnerability
}

func convert(m models.Match) Match {
	return Match{
		Package: Package{
			Name:    m.Artifact.Name,
			Version: m.Artifact.Version,
			Type:    string(m.Artifact.Type),
		},
		Vulnerability: Vulnerability{
			ID:       m.Vulnerability.ID,
			Severity: m.Vulnerability.Severity,
		},
	}
}
