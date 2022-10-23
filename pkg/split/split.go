package split

import (
	"github.com/chainguard-dev/fixfilter/pkg/parsing/types"
	"github.com/chainguard-dev/fixfilter/pkg/secdb"
	apk "github.com/knqyf263/go-apk-version"
	"log"
)

// Split devices the Grype result matches into three groups (each group is a
// []Match): APK matches that are valid, APK matches that are invalidated by
// secdb data, and non-APK matches.
func Split(matches []types.Match, secdbClient *secdb.Client) (validApkMatches []types.Match, invalidatedApkMatches []types.Match, NonApkMatches []types.Match) {
	if secdbClient == nil {
		// TODO: log this
		return
	}

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
			log.Print(err)
			continue
		}
		fixVersion, err := apk.NewVersion(*fix)
		if err != nil {
			log.Print(err)
			continue
		}

		if pkgVersion.LessThan(fixVersion) {
			// This package hasn't been fixed yet. So the vulnerability match is valid.
			validApkMatches = append(validApkMatches, m)
			continue
		}

		// This package has the fix! So we'll invalidate the match.
		invalidatedApkMatches = append(invalidatedApkMatches, m)
	}

	return validApkMatches, invalidatedApkMatches, NonApkMatches
}
