package grype

import (
	"fmt"
	"github.com/chainguard-dev/fixfilter/pkg/parsing"
	"github.com/chainguard-dev/fixfilter/pkg/parsing/types"
	sarifHelpers "github.com/chainguard-dev/fixfilter/pkg/sarif"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"io"
	"regexp"
)

func ParseSARIF(r io.Reader) (*types.Report, error) {
	run, err := sarifHelpers.ExtractRun(r)
	if err != nil {
		return nil, fmt.Errorf("unable to parse Grype SARIF: %w", err)
	}

	if err := parsing.ValidateScanner("Grype", run.Tool.Driver.Name); err != nil {
		return nil, err
	}

	rules, err := sarifHelpers.IndexRules(*run)
	if err != nil {
		return nil, err
	}

	matches, err := resultsToMatches(rules, run.Results)
	if err != nil {
		return nil, err
	}

	report := types.Report{
		Matches: matches,
	}

	return &report, nil
}

var resultMessageRegex = regexp.MustCompile(`(?U).*reports (?P<packageName>.*) at version (?P<installedVersion>.*)\s{1,2}which is a vulnerable \((?P<type>.*)\) package installed.*`)
var ruleShortDescriptionRegex = regexp.MustCompile(`(?P<vulnerabilityID>[[:alnum:]]{3,}(-[[:alnum:]]{3,}){2,3}) (?P<severity>[[:alpha:]]+) vulnerability`)

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
		ruleSubexps := parsing.NamedSubexps(ruleShortDescriptionRegex, *rule.ShortDescription.Text)

		m := types.Match{
			Package: types.Package{
				Name:    subexps["packageName"],
				Version: subexps["installedVersion"],
				Type:    subexps["type"],
			},
			Vulnerability: types.Vulnerability{
				ID:       ruleSubexps["vulnerabilityID"],
				Severity: ruleSubexps["severity"],
			},
		}

		matches = append(matches, m)
	}

	return matches, nil
}
