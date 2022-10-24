package types

import "io"

type Parser func(r io.Reader) (*Report, error)
