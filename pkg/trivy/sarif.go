package trivy

import (
	"fmt"
	"github.com/chainguard-dev/fixfilter/pkg/parsing"
	"github.com/chainguard-dev/fixfilter/pkg/parsing/types"
	sarifHelpers "github.com/chainguard-dev/fixfilter/pkg/sarif"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"io"
	"regexp"
)

func ParseSARIF(r io.Reader) ([]types.Match, error) {
	run, err := sarifHelpers.ExtractRun(r)
	if err != nil {
		return nil, fmt.Errorf("unable to parse Trivy SARIF: %w", err)
	}

	if err := parsing.ValidateScanner("Trivy", run.Tool.Driver.Name); err != nil {
		return nil, err
	}

	rules, err := sarifHelpers.IndexRules(*run)
	if err != nil {
		return nil, err
	}

	return resultsToMatches(rules, run.Results)
}

var resultMessageRegex = regexp.MustCompile(`Package: (?P<packageName>.*)\nInstalled Version: (?P<installedVersion>.*)\n.*\nSeverity: (?P<severity>.*)\n`)

func resultsToMatches(rules map[string]sarif.ReportingDescriptor, results []*sarif.Result) ([]types.Match, error) {
	var matches []types.Match

	for _, result := range results {
		if result == nil {
			continue
		}

		ruleID := result.RuleID
		if ruleID == nil {
			continue
		}

		rule := rules[*ruleID]
		subexps := parsing.NamedSubexps(resultMessageRegex, *result.Message.Text)

		m := types.Match{
			Package: types.Package{
				Name:    subexps["packageName"],
				Version: subexps["installedVersion"],
				Type:    "",
			},
			Vulnerability: types.Vulnerability{
				ID:       rule.ID,
				Severity: subexps["severity"],
			},
		}

		matches = append(matches, m)
	}

	return matches, nil
}
