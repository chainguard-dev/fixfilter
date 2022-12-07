package types

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
	ValidApkMatches       []Match
	InvalidatedApkMatches []Match
	NonApkMatches         []Match
}
