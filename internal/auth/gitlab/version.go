package gitlab

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
)

// VersionClassification is the outcome of version parsing and classification.
type VersionClassification int

const (
	// VersionUnknown indicates an unparseable or unsupported version.
	VersionUnknown VersionClassification = iota
	// VersionBelowFloor indicates a version below the supported floor (18.9).
	VersionBelowFloor
	// VersionMaster indicates a -pre version on gitlab.com.
	VersionMaster
	// VersionTag indicates a release version.
	VersionTag
)

// floorMajor and floorMinor define the minimum supported GitLab version (18.9).
const (
	floorMajor = 18
	floorMinor = 9
)

// versionRe matches the version grammar: major.minor.patch with optional -ee or -pre suffix.
// Components are decimal without leading zeros (0 or [1-9][0-9]*), at most 4 digits each.
var versionRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})(-ee|-pre)?$`)

// parsedVersion holds the components of a parsed GitLab version.
type parsedVersion struct {
	major  int
	minor  int
	patch  int
	suffix string // "-ee", "-pre", or "".
}

// parseVersion parses a GitLab version string. It returns (nil, false) for an
// unparseable version. The regex ensures each component is at most 4 digits.
func parseVersion(version string) (*parsedVersion, bool) {
	m := versionRe.FindStringSubmatch(version)
	if m == nil {
		return nil, false
	}

	// Atoi cannot fail: the regex already validated decimal format.
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])

	return &parsedVersion{
		major:  major,
		minor:  minor,
		patch:  patch,
		suffix: m[4],
	}, true
}

// belowFloor reports whether v is below the supported floor (18.9).
func (v *parsedVersion) belowFloor() bool {
	if v.major < floorMajor {
		return true
	}
	if v.major > floorMajor {
		return false
	}

	return v.minor < floorMinor
}

// ClassifyVersion classifies a GitLab instance version and returns the
// classification, the git ref to use for fetching the OpenAPI document, and a
// reason string for unsupported versions. hostname and port are the served
// authority (api_host when set, else host), with the port explicit. scrub removes known credentials from the
// instance's text before it is echoed.
func ClassifyVersion(
	version, hostname, port string, scrub func(string) string,
) (VersionClassification, string, string) {
	parsed, ok := parseVersion(version)
	if !ok {
		// The version is the instance's text: it is scrubbed, then quoted and bounded, in that order, since a
		// bound that cuts a credential first leaves a fragment the scrubber can no longer match.
		return VersionUnknown, "", "instance reports unrecognized version " +
			apiref.Truncate(strconv.Quote(scrub(version)), apiref.MaxChoice)
	}

	if parsed.belowFloor() {
		return VersionBelowFloor, "", fmt.Sprintf(
			"GitLab 18.9 or later required (instance reports %q)", version)
	}

	// -pre on gitlab.com is master.
	if parsed.suffix == "-pre" {
		if isGitLabCom(hostname, port) {
			return VersionMaster, "master", ""
		}

		return VersionUnknown, "", fmt.Sprintf(
			"instance reports development version %q (only gitlab.com's development builds are supported)", version)
	}

	// Plain version or -ee version becomes a tag.
	// CE gets the EE file (they are byte-identical).
	ref := fmt.Sprintf("v%d.%d.%d-ee", parsed.major, parsed.minor, parsed.patch)

	return VersionTag, ref, ""
}

// isGitLabCom reports whether hostname:port names the public GitLab SaaS instance.
func isGitLabCom(hostname, port string) bool {
	return strings.EqualFold(hostname, "gitlab.com") && port == "443"
}
