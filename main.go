package main

import (
	"fmt"
	"github.com/chainguard-dev/fixfilter/pkg/fixfilter"
	"github.com/chainguard-dev/fixfilter/pkg/grype"
	"github.com/chainguard-dev/fixfilter/pkg/secdb"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"io"
	"os"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:           "fixfilter { - | path-to-Grype-JSON-file }",
		Example:       "grype -q cgr.dev/chainguard/ko:latest | fixfilter -",
		Short:         "Use the Wolfi secdb to filter vulnerability scan (JSON) results from Grype",
		Args:          cobra.ExactArgs(1),
		RunE:          runRoot,
		SilenceErrors: true,
	}

	return &cmd
}

func runRoot(cmd *cobra.Command, args []string) error {
	input := args[0]

	jsonReadCloser, err := getJSON(input)
	if err != nil {
		return err
	}
	defer jsonReadCloser.Close()

	result, err := grype.ResultFromJSON(jsonReadCloser)
	if err != nil {
		return err
	}

	err = fixfilter.CheckWolfi(result)
	if err != nil {
		return err
	}

	secdbClient, err := secdb.NewClient()
	if err != nil {
		return err
	}

	validApkMatches, invalidatedApkMatches, nonApkMatches := fixfilter.Split(result, secdbClient)

	if len(validApkMatches) > 0 {
		fmt.Println("⚠️  Legit vulnerabilities (apk):")
		for _, m := range validApkMatches {
			fmt.Println("   • " + renderMatch(m))
		}
		fmt.Println()
	}

	if len(invalidatedApkMatches) > 0 {
		fmt.Println("✅ Fixed vulnerabilities (apk):")
		for _, m := range invalidatedApkMatches {
			fmt.Println("   • " + renderMatch(m))
		}
		fmt.Println()
	}

	if len(nonApkMatches) > 0 {
		fmt.Println("🙈 Non-apk vulnerabilities:")
		for _, m := range nonApkMatches {
			fmt.Println("   • " + renderMatch(m))
		}
		fmt.Println()
	}

	return nil
}

func renderMatch(m fixfilter.Match) string {
	return fmt.Sprintf("%s (%s): %s", m.Package.Name, m.Package.Version, m.Vulnerability.ID)
}

func getJSON(input string) (io.ReadCloser, error) {
	if input == "-" {
		// read from STDIN
		return io.NopCloser(os.Stdin), nil
	}

	f, err := os.Open(input)
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrieve Grype JSON output")
	}

	return f, nil
}
