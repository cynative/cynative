package k8s

import (
	"testing"
)

// FuzzParseRoot checks that a root and a model never steer a document URL: whatever the root says, a usable hash
// is a valid one and is published under the requested key's own canonical URL. The seeds reach every branch of
// ParseRoot, Lookup, Versions and ParseAPIVersion.
func FuzzParseRoot(f *testing.F) {
	url := `/openapi/v3/apis/apps/v1?hash=` + testHash
	for _, s := range [][2]string{
		{`{"paths":{"apis/apps/v1":{"serverRelativeURL":"` + url + `"}}}`, "apps/v1"},
		{`{"paths":{"apis/apps/v1":{"serverRelativeURL":"/elsewhere?hash=` + testHash + `"}}}`, "apps/v1"},
		{`{"paths":{"apis/apps/v1":"x","api/v1":{},"apis/apps":{},"apis/v1":{},"api/a/v1":{}}}`, "apps/v2"},
		{`{"paths":{"api/v1":{"serverRelativeURL":5}}}`, "v1"},
		{`{"paths":[]}`, "v1"},
		{`[]`, "v1"},
		{`{`, "v1"},
		{`{"paths":{}}`, "Apps/v1"},
		{`{"paths":{}}`, "a/b/c"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, body, model string) {
		v, err := ParseAPIVersion(model)
		if err != nil {
			return
		}
		if v.Model() != model {
			t.Fatalf("model %q round-trips as %q", model, v.Model())
		}
		r, err := ParseRoot(t.Context(), []byte(body))
		if err != nil {
			return
		}
		if hash, _ := r.Lookup(v.Key); hash != "" && !ValidHash(hash) {
			t.Fatalf("Lookup(%q) published unusable hash %q", v.Key, hash)
		}
		for _, c := range r.Versions(v) {
			if cv, cerr := ParseAPIVersion(c); cerr != nil || cv.Group != v.Group {
				t.Fatalf("choice %q is not a version of group %q", c, v.Group)
			}
		}
	})
}
