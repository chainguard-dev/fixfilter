package sarif

import (
	"errors"
	"fmt"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"io"
)

func ExtractRun(r io.Reader) (*sarif.Run, error) {
	by, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	report, err := sarif.FromBytes(by)
	if err != nil {
		return nil, err
	}

	if runsCount := len(report.Runs); runsCount != 1 {
		return nil, fmt.Errorf("expected SARIF report to include 1 run, but it had %d", runsCount)
	}

	run := report.Runs[0]
	if run == nil {
		return nil, errors.New("unable to process nil run")
	}

	return run, nil
}

func IndexRules(run sarif.Run) (map[string]sarif.ReportingDescriptor, error) {
	rulesIndex := make(map[string]sarif.ReportingDescriptor)

	driver := run.Tool.Driver
	if driver == nil {
		return nil, errors.New("unable to process nil tool driver")
	}

	for i, rule := range driver.Rules {
		if rule == nil {
			continue
		}

		if _, exists := rulesIndex[rule.ID]; exists {
			return nil, fmt.Errorf("duplicate rule detected at index %d", i)
		}

		rulesIndex[rule.ID] = *rule
	}

	return rulesIndex, nil
}
