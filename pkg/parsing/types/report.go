package types

import "encoding/json"

type Report struct {
	Matches []Match
	Distro  string
}

const Wolfi = "wolfi"

type Match struct {
	Package       Package
	Vulnerability Vulnerability
}

type Package struct {
	Name, Version, Type, Origin string
}

type Vulnerability struct {
	ID       string
	Severity string
}

type CveMatchGroupings struct {
	ValidApkMatches       Matches
	InvalidatedApkMatches Matches
	NonApkMatches         Matches
}

type Matches []Match

func (m Matches) MarshalJSON() ([]byte, error) {
	if m == nil {
		return json.Marshal([]Match{})
	}

	return json.Marshal([]Match(m))
}
