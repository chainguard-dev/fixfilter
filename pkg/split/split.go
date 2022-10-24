package split

import (
	"errors"
	"fmt"
	"github.com/chainguard-dev/fixfilter/pkg/parsing/types"
	"github.com/chainguard-dev/fixfilter/pkg/secdb"
	apk "github.com/knqyf263/go-apk-version"
	"strings"
)

// Split devices the Grype result matches into three groups (each group is a
// []Match): APK matches that are valid, APK matches that are invalidated by
// secdb data, and non-APK matches.
func Split(report types.Report, secdbClient *secdb.Client) (validApkMatches []types.Match, invalidatedApkMatches []types.Match, NonApkMatches []types.Match, err error) {
	if secdbClient == nil {
		return nil, nil, nil, errors.New("cannot use nil secdb client")
	}

	if !(strings.EqualFold(report.Distro, types.Wolfi) || report.Distro == "") {
		return nil, nil, nil, fmt.Errorf("cannot apply Wolfi fix data to non-Wolfi packages: distro is %q", report.Distro)
	}

	matches := report.Matches

	for _, m := range matches {
		// This match isn't for an apk package. Separate it out.
		if m.Package.Type != "apk" && m.Package.Type != "" {
			NonApkMatches = append(NonApkMatches, m)
			continue
		}

		var fix *string

		// If this package has an "origin" package, use that to find fixes in the secdb.
		if o := m.Package.Origin; o != "" {
			fix = secdbClient.FindFix(m.Package.Origin, m.Vulnerability.ID)
		} else {
			fix = secdbClient.FindFix(m.Package.Name, m.Vulnerability.ID)
		}

		// There's no fix for this vulnerability. So it's valid.
		if fix == nil {
			validApkMatches = append(validApkMatches, m)
			continue
		}

		pkgVersion, err := apk.NewVersion(m.Package.Version)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to determine version of apk package: %w", err)
		}
		fixVersion, err := apk.NewVersion(*fix)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to determine fix version from secdb: %w", err)
		}

		if pkgVersion.LessThan(fixVersion) {
			// This package hasn't been fixed yet. So the vulnerability match is valid.
			validApkMatches = append(validApkMatches, m)
			continue
		}

		// This package has the fix! So we'll invalidate the match.
		invalidatedApkMatches = append(invalidatedApkMatches, m)
	}

	return validApkMatches, invalidatedApkMatches, NonApkMatches, nil
}
