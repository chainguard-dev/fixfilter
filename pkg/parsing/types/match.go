package types

type Match struct {
	Package       Package
	Vulnerability Vulnerability
}

type Package struct {
	Name, Version, Type string
}

type Vulnerability struct {
	ID       string
	Severity string
}
