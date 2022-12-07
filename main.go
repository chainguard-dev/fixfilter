package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/chainguard-dev/fixfilter/pkg/grype"
	"github.com/chainguard-dev/fixfilter/pkg/parsing/types"
	"github.com/chainguard-dev/fixfilter/pkg/secdb"
	"github.com/chainguard-dev/fixfilter/pkg/split"
	"github.com/chainguard-dev/fixfilter/pkg/trivy"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var output string

	cmd := cobra.Command{
		Use:     "fixfilter { - | path-to-Grype-JSON-file }",
		Example: "grype -q cgr.dev/chainguard/ko:latest | fixfilter -",
		Short:   "Use the Wolfi secdb to filter vulnerability scan (JSON) results from Grype",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			vulnReportPath := args[0]

			return runRoot(vulnReportPath, output)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.Flags().StringVarP(&output, "output", "o", "pretty", "output format [json, pretty]")

	return &cmd
}

func runRoot(vulnReportPath string, output string) error {
	rc, err := getResultData(vulnReportPath)
	if err != nil {
		return err
	}
	defer rc.Close()

	report, err := tryAllParsers(rc)
	if err != nil {
		return err
	}

	secdbClient, err := secdb.NewClient()
	if err != nil {
		return err
	}

	groupings, err := split.Split(*report, secdbClient)
	if err != nil {
		return fmt.Errorf("unable to split vulnerability matches: %w", err)
	}

	switch output {
	case "json":
		err := json.NewEncoder(os.Stdout).Encode(groupings)
		if err != nil {
			return err
		}

		return nil

	case "pretty":
		if matches := groupings.ValidApkMatches; len(matches) > 0 {
			fmt.Println("⚠️  Legit vulnerabilities:")
			printMatches(matches)
		}

		if matches := groupings.InvalidatedApkMatches; len(matches) > 0 {
			fmt.Println("✅ Fixed vulnerabilities:")
			printMatches(matches)
		}

		if matches := groupings.NonApkMatches; len(matches) > 0 {
			fmt.Println("🙈 Non-apk vulnerabilities:")
			printMatches(matches)
		}

		return nil

	default:
		return fmt.Errorf("unrecognized output format %q", output)
	}
}

func renderMatch(m types.Match) string {
	return fmt.Sprintf("%s (%s): %s", m.Package.Name, m.Package.Version, m.Vulnerability.ID)
}

func printMatches(ms []types.Match) {
	for _, m := range ms {
		fmt.Println("   • " + renderMatch(m))
	}
	fmt.Println()
}

func getResultData(input string) (io.ReadCloser, error) {
	if input == "-" {
		// read from STDIN
		return io.NopCloser(os.Stdin), nil
	}

	f, err := os.Open(input)
	if err != nil {
		return nil, errors.Wrap(err, "unable to obtain scanner result data")
	}

	return f, nil
}

func tryAllParsers(r io.Reader) (*types.Report, error) {
	parseFns := []types.Parser{
		grype.ParseTable,
		grype.ParseJSON,
		grype.ParseSARIF,
		trivy.ParseSARIF,
	}

	var parseErrs *multierror.Error

	by, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	for _, parse := range parseFns {
		parserReader := bytes.NewReader(by)

		report, err := parse(parserReader)
		if err != nil {
			parseErrs = multierror.Append(parseErrs, err)

			continue
		}

		return report, nil
	}

	return nil, fmt.Errorf("no parser was able to extract scan result data from input: %w", parseErrs)
}
