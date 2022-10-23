package types

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
