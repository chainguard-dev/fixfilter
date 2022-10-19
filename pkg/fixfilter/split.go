package fixfilter

import (
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/chainguard-dev/fixfilter/pkg/secdb"
	apk "github.com/knqyf263/go-apk-version"
	"log"
)

// Split devices the Grype result matches into three groups (each group is a
// []Match): APK matches that are valid, APK matches that are invalidated by
// secdb data, and non-APK matches.
func Split(result *models.Document, secdbClient *secdb.Client) (validApkMatches []Match, invalidatedApkMatches []Match, NonApkMatches []Match) {
	if result == nil || secdbClient == nil {
		// TODO: log this
		return
	}

	for _, grypeMatch := range result.Matches {
		m := convert(grypeMatch)

		// This match isn't for an apk package. Separate it out.
		if m.Package.Type != "apk" {
			NonApkMatches = append(NonApkMatches, m)
			continue
		}

		fix := secdbClient.FindFix(m.Package.Name, m.Vulnerability.ID)

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
