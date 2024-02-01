# fixfilter (ARCHIVED)

> [!WARNING]
> This project is no longer maintained and should not be used. This tool has been obviated by first-class support for Wolfi in [Trivy](https://github.com/aquasecurity/trivy) and [Grype](https://github.com/anchore/grype).

Apply Wolfi's secfixes data to vulnerability scanner results

## Installation

1. Clone the repo.

```shell
git clone git@github.com:chainguard-dev/fixfilter.git
```

2. Install the Go binary.

```shell
cd ./fixfilter && go install
```

## Usage

`fixfilter` takes as input vulnerability scan result data in any of the following formats:

- Trivy's SARIF output (`trivy ... -f sarif`)
- Grype's SARIF output (`grype ... -o sarif`)
- Grype's native JSON output (`grype ... -o json`)
- Grype's default table output (`grype ...`)

If you have result data saved to a local file, you can provide the local path:

```shell
# E.g., let's assume you've run a command like this:
grype cgr.dev/chainguard/ko -o json > ko.grype.json

# To filter these results with Wolfi's fix data:
fixfilter ./ko.grype.json
```

Or, you can just pipe scanner result data directly into `fixfilter`, by specifying `-` as the input arg:

```shell
grype cgr.dev/chainguard/ko -o json | fixfilter -
```

## Known limitations

### Applying fixes to apk subpackages

With Wolfi, similar to the Alpine ecosystem, subpackages (i.e. packages that declare another package as their "origin") do not have their own fix data in the secdb. Instead, fix information can be found in the secdb db by searching by the package's origin.

Unfortunately, not all vulnerability scanner output includes this "origin" data. Currently, only **Grype's native JSON output** provides this information. Thus, when using other data formats, fixfilter isn't able to correctly mark subpackages as fixed.

### Distinguishing between Wolfi and non-Wolfi packages

fixfilter is filtering vulnerability results using Wolfi's secdb. This fix data describes vulnerability fixes for **Wolfi packages only**. It is invalid to apply this fix data to non-Wolfi packages, such as Alpine packages.

However, not all vulnerability scanner output describes the _distro_ for the packages in the output. Currently, only **Grype's native JSON output** reports distro information. For this format, fixfilter can detect when you've supplied vulnerability scan data for the wrong distro and proactively error out, to prevent a misleading report about which vulnerabilities have been fixed. But for other data formats, fixfilter will blindly apply the Wolfi fix data to input data, regardless of whether the input data describes Wolfi packages.

<!-- TODO: Trivy's native JSON output reports the distro, too. So we should update this section when support for Trivy JSON is added. -->
