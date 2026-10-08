package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
)

// Grammar bounds for an apiVersion and for the document hash the root publishes.
const (
	// maxGroupBytes is the DNS-1123 subdomain limit a group name is held to.
	maxGroupBytes = 253
	// maxVersionBytes is the DNS-1035 label limit a version is held to.
	maxVersionBytes = 63
	// hashLen is the length of kube-openapi's ETag: %X of a SHA-512.
	hashLen = 128
	// rootPrefix is the path every group-version document is read under.
	rootPrefix = "/openapi/v3/"
	// hashQuery introduces the hash in a document URL.
	hashQuery = "?hash="
)

// ErrModel marks a model that is not an apiVersion.
var ErrModel = errors.New(`model must be an apiVersion: a version such as "v1" for the core group, or ` +
	`<group>/<version> such as "apps/v1"`)

// ErrRootShape marks a root that is not a JSON object with a paths object.
var ErrRootShape = errors.New("the /openapi/v3 root is not a JSON object with a paths object")

var (
	// versionPattern is a DNS-1035 label.
	versionPattern = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)
	// groupPattern is a DNS-1123 subdomain: dot-separated DNS-1123 labels.
	groupPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`)
	// hashPattern is a usable document hash.
	hashPattern = regexp.MustCompile(`^[0-9A-F]{128}$`)
)

// APIVersion is a validated apiVersion and the document key it names.
type APIVersion struct {
	// Group is empty for the core group.
	Group   string
	Version string
	// Key is api/<version> for the core group and apis/<group>/<version> otherwise.
	Key string
}

// ParseAPIVersion validates model, used exactly as sent: a version for the core group, or a group, a '/' and a
// version. The group is a DNS-1123 subdomain and the version a DNS-1035 label.
func ParseAPIVersion(model string) (APIVersion, error) {
	group, version, grouped := strings.Cut(model, "/")
	if !grouped {
		group, version = "", model
	}
	if !validVersion(version) || (grouped && !validGroup(group)) {
		return APIVersion{}, ErrModel
	}
	if !grouped {
		return APIVersion{Version: version, Key: "api/" + version}, nil
	}

	return APIVersion{Group: group, Version: version, Key: "apis/" + group + "/" + version}, nil
}

// Model is the apiVersion as a model value.
func (v APIVersion) Model() string {
	if v.Group == "" {
		return v.Version
	}

	return v.Group + "/" + v.Version
}

func validVersion(s string) bool {
	return len(s) <= maxVersionBytes && versionPattern.MatchString(s)
}

func validGroup(s string) bool {
	return len(s) <= maxGroupBytes && groupPattern.MatchString(s)
}

// ValidHash reports a hash in the form kube-openapi publishes: 128 characters from [0-9A-F].
func ValidHash(s string) bool {
	return len(s) == hashLen && hashPattern.MatchString(s)
}

// Root is the parsed /openapi/v3 root: its paths entries, each held as raw JSON until it is read.
type Root struct {
	entries map[string]json.RawMessage
}

// ParseRoot runs the streaming pass with the root's element cap, then decodes the root as a JSON object with a
// paths object. Entries are decoded only when they are read, so one malformed entry never fails the root.
func ParseRoot(ctx context.Context, body []byte) (Root, error) {
	if _, err := Scan(ctx, body, MaxRootElements); err != nil {
		return Root{}, err
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return Root{}, ErrRootShape
	}
	var entries map[string]json.RawMessage
	if json.Unmarshal(top["paths"], &entries) != nil || entries == nil {
		return Root{}, ErrRootShape
	}

	return Root{entries: entries}, nil
}

// Lookup reports whether the root lists key, matched as an exact string, and the usable hash its entry publishes:
// only when serverRelativeURL is exactly /openapi/v3/<key>?hash= followed by a valid hash. An entry that is not an
// object with a string serverRelativeURL is listed with no hash.
func (r Root) Lookup(key string) (string, bool) {
	raw, ok := r.entries[key]
	if !ok {
		return "", false
	}
	var entry map[string]json.RawMessage
	_ = json.Unmarshal(raw, &entry) // an entry that is not an object has no hash.
	var url string
	_ = json.Unmarshal(entry["serverRelativeURL"], &url) // a non-string URL has no hash.
	hash, found := strings.CutPrefix(url, rootPrefix+key+hashQuery)
	if !found || !ValidHash(hash) {
		return "", true
	}

	return hash, true
}

// Versions lists, sorted, the model values of the listed keys that are apiVersions of v's group, v itself
// excluded. Every other key, the root's non-resource documents included, is ignored.
func (r Root) Versions(v APIVersion) []string {
	var out []string
	for key := range r.entries {
		other, ok := keyAPIVersion(key)
		if ok && other.Group == v.Group && other.Version != v.Version {
			out = append(out, other.Model())
		}
	}
	slices.Sort(out)

	return out
}

// keyAPIVersion reads a root key back as an apiVersion when it is a group-version document key.
func keyAPIVersion(key string) (APIVersion, bool) {
	model, ok := strings.CutPrefix(key, "api/")
	if !ok {
		model, ok = strings.CutPrefix(key, "apis/")
	}
	if !ok {
		return APIVersion{}, false
	}
	v, err := ParseAPIVersion(model)

	return v, err == nil && v.Key == key
}
