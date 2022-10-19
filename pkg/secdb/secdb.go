package secdb

import (
	"chainguard.dev/wolfi-secdb/pkg/types"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"net/http"
)

const secdbURL = "https://packages.wolfi.dev/os/security.json"

type packageCVE struct {
	pkgName, cveID string
}

type Client struct {
	db *types.Database

	// indexedFixes is a map of {package name, and a CVE ID) to the version of a package that fixes the CVE
	indexedFixes map[packageCVE]string
}

func NewClient() (*Client, error) {
	webClient := http.Client{}
	resp, err := webClient.Get(secdbURL)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create secdb client")
	}
	if resp.StatusCode != 200 {
		err := fmt.Errorf("unable to retrieve Wolfi secdb from %q, response status code %d", secdbURL, resp.StatusCode)
		return nil, errors.Wrap(err, "unable to create secdb client")
	}

	defer resp.Body.Close()

	db, err := databaseFromJSON(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create secdb client")
	}

	indexedFixes := indexFixes(db)

	return &Client{
		db:           db,
		indexedFixes: indexedFixes,
	}, nil
}

// FindFix returns a version of the specific package that addresses the CVE if such a version exists, and returns nil if not.
func (c Client) FindFix(pkgName, cveID string) *string {
	fixedVersion, wasFound := c.indexedFixes[packageCVE{
		pkgName: pkgName,
		cveID:   cveID,
	}]

	if !wasFound {
		return nil
	}

	return &fixedVersion
}

func databaseFromJSON(secdbJSON io.Reader) (*types.Database, error) {
	dec := json.NewDecoder(secdbJSON)

	database := &types.Database{}
	err := dec.Decode(database)
	if err != nil {
		return nil, err
	}

	return database, nil
}

func indexFixes(db *types.Database) map[packageCVE]string {
	indexedFixes := make(map[packageCVE]string)

	for _, entry := range db.Packages {
		pkg := entry.Pkg

		for fixVersion, cves := range pkg.Secfixes {
			for _, cve := range cves {
				indexedFixes[packageCVE{
					pkg.Name,
					cve,
				}] = fixVersion
			}
		}
	}

	return indexedFixes
}
