package gitlab

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// versionClassification is the outcome of version parsing and classification.
type versionClassification int

const (
	versionUnknown versionClassification = iota
	versionBelowFloor
	versionMaster
	versionTag
)

// floorMajor and floorMinor define the minimum supported GitLab version (18.9).
const (
	floorMajor = 18
	floorMinor = 9
	maxDigits  = 9999
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
// unparseable version or one whose components overflow maxDigits.
func parseVersion(version string) (*parsedVersion, bool) {
	m := versionRe.FindStringSubmatch(version)
	if m == nil {
		return nil, false
	}

	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])

	if major > maxDigits || minor > maxDigits || patch > maxDigits {
		return nil, false
	}

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

// classifyVersion classifies a GitLab instance version and returns the
// classification, the git ref to use for fetching the OpenAPI document, and a
// reason string for unsupported versions. hostname and port are the served
// authority (api_host when set, else host), with the port explicit.
func classifyVersion(version, hostname, port string) (versionClassification, string, string) {
	parsed, ok := parseVersion(version)
	if !ok {
		return versionUnknown, "", fmt.Sprintf("instance reports unrecognized version %q", version)
	}

	if parsed.belowFloor() {
		return versionBelowFloor, "", fmt.Sprintf(
			"GitLab 18.9 or later required (instance reports %q)", version)
	}

	// -pre on gitlab.com is master.
	if parsed.suffix == "-pre" {
		if isGitLabCom(hostname, port) {
			return versionMaster, "master", ""
		}

		return versionUnknown, "", fmt.Sprintf(
			"instance reports development version %q (only gitlab.com's development builds are supported)", version)
	}

	// Plain version or -ee version becomes a tag.
	// CE gets the EE file (they are byte-identical).
	ref := fmt.Sprintf("v%d.%d.%d-ee", parsed.major, parsed.minor, parsed.patch)

	return versionTag, ref, ""
}

// isGitLabCom reports whether hostname:port names the public GitLab SaaS instance.
func isGitLabCom(hostname, port string) bool {
	return strings.EqualFold(hostname, "gitlab.com") && port == "443"
}
