package grype

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/chainguard-dev/fixfilter/pkg/parsing/types"
	"io"
	"strings"
)

func ParseTable(r io.Reader) (*types.Report, error) {
	scanner := bufio.NewScanner(r)

	scanner.Scan()
	columnHeaders := scanner.Text()

	indexOfName := strings.Index(columnHeaders, "NAME")
	indexOfInstalled := strings.Index(columnHeaders, "INSTALLED")
	indexOfType := strings.Index(columnHeaders, "TYPE")
	indexOfVulnerability := strings.Index(columnHeaders, "VULNERABILITY")
	indexOfSeverity := strings.Index(columnHeaders, "SEVERITY")

	if !allRealIndexes(indexOfName, indexOfInstalled, indexOfType, indexOfVulnerability, indexOfSeverity) {
		return nil, errors.New("unable to parse input as Grype table format")
	}

	var matches []types.Match

	for scanner.Scan() {
		row := scanner.Text()

		m := types.Match{
			Package: types.Package{
				Name:    strings.Split(row[indexOfName:], " ")[0],
				Version: strings.Split(row[indexOfInstalled:], " ")[0],
				Type:    strings.Split(row[indexOfType:], " ")[0],
			},
			Vulnerability: types.Vulnerability{
				ID:       strings.Split(row[indexOfVulnerability:], " ")[0],
				Severity: strings.Split(row[indexOfSeverity:], " ")[0],
			},
		}

		matches = append(matches, m)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to parse input as Grype table format: %w", err)
	}

	report := types.Report{
		Matches: matches,
	}

	return &report, nil
}

func allRealIndexes(indexes ...int) bool {
	for _, index := range indexes {
		if index < 0 {
			return false
		}
	}

	return true
}
