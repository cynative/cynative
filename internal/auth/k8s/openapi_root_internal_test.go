package k8s

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestParseAPIVersion(t *testing.T) {
	t.Parallel()
	long := func(n int) string { return "a" + strings.Repeat("b", n-1) }
	ok := map[string]string{
		"v1":                               "api/v1",
		"apps/v1":                          "apis/apps/v1",
		"metrics.k8s.io/v1beta1":           "apis/metrics.k8s.io/v1beta1",
		"core/v1":                          "apis/core/v1",
		"api/v1":                           "apis/api/v1",
		"9x.example/v2alpha1":              "apis/9x.example/v2alpha1",
		long(63):                           "api/" + long(63),
		strings.Repeat("a.", 126) + "a/v1": "apis/" + strings.Repeat("a.", 126) + "a/v1",
		"x-1.y/v-1":                        "apis/x-1.y/v-1",
		"a/" + long(63):                    "apis/a/" + long(63),
		strings.Repeat("a", 63) + ".b/v1":  "apis/" + strings.Repeat("a", 63) + ".b/v1",
	}
	for model, key := range ok {
		v, err := ParseAPIVersion(model)
		if err != nil || v.Key != key || v.Model() != model {
			t.Errorf("ParseAPIVersion(%q) = %+v, %v; want key %q", model, v, err, key)
		}
	}
	for _, model := range []string{
		"", "V1", "1v", "v1-", "v_1", " v1", "v1 ", "apps/", "/v1", "apps/v1/x", "Apps/v1", "apps./v1", ".apps/v1",
		"a..b/v1", "-a/v1", "a-/v1", "apps/V1", long(64), "a/" + long(64), strings.Repeat("a.", 127) + "a/v1",
		strings.Repeat("a", 64) + ".b/v1", "apps%2fv1", "apps/v1?x", "apps/v1#",
	} {
		if v, err := ParseAPIVersion(model); !errors.Is(err, ErrModel) {
			t.Errorf("ParseAPIVersion(%q) = %+v, %v; want ErrModel", model, v, err)
		}
	}
}

func TestValidHash(t *testing.T) {
	t.Parallel()
	good := strings.Repeat("0123456789ABCDEF", 8)
	if !ValidHash(good) {
		t.Fatal("a 128-character uppercase hex hash is refused")
	}
	for _, h := range []string{"", good[:127], good + "0", strings.ToLower(good), good[:127] + "G", good[:127] + " "} {
		if ValidHash(h) {
			t.Errorf("ValidHash(%q) = true", h)
		}
	}
}

const testHash = "AAB28BA8462DC5830123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" +
	"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"

func testRoot(t *testing.T) Root {
	t.Helper()
	r, err := ParseRoot(t.Context(), []byte(`{"paths":{
	"api":{"serverRelativeURL":"/openapi/v3/api?hash=`+testHash+`"},
	"api/v1":{"serverRelativeURL":"/openapi/v3/api/v1?hash=`+testHash+`"},
	"apis":{"serverRelativeURL":"/openapi/v3/apis"},
	"apis/apps":{"serverRelativeURL":"/openapi/v3/apis/apps"},
	"apis/apps/v1":{"serverRelativeURL":"/openapi/v3/apis/apps/v1?hash=`+testHash+`"},
	"apis/apps/v1beta2":{"serverRelativeURL":"/openapi/v3/apis/apps/v1beta2?hash=`+strings.ToLower(testHash)+`"},
	"apis/apps/V9":{},
	"apis/batch/v1":{"serverRelativeURL":"/openapi/v3/apis/batch/v1"},
	"apis/elsewhere.io/v1":{"serverRelativeURL":"https://evil.example/openapi/v3/apis/elsewhere.io/v1?hash=`+testHash+`"},
	"apis/other.io/v1":{"serverRelativeURL":"/openapi/v3/apis/apps/v1?hash=`+testHash+`"},
	"apis/odd.io/v1":"not an object",
	"apis/num.io/v1":{"serverRelativeURL":5},
	"apis/q.io/v1":{"serverRelativeURL":"/openapi/v3/apis/q.io/v1?hash=`+testHash+`&x=1"},
	"api/v2":{"serverRelativeURL":"/openapi/v3/api/v2?hash="},
	"apis/v3":{},
	"api/apps/v1":{},
	"version":{"serverRelativeURL":"/openapi/v3/version?hash=`+testHash+`"},
	"openid/v1/jwks":{},".well-known/openid-configuration":{},"logs":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRoot_Lookup(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	cases := []struct {
		key    string
		listed bool
		hash   string
	}{
		{"api/v1", true, testHash},
		{"apis/apps/v1", true, testHash},
		{"apis/apps/v1beta2", true, ""},
		{"apis/batch/v1", true, ""},
		{"apis/elsewhere.io/v1", true, ""},
		{"apis/other.io/v1", true, ""},
		{"apis/odd.io/v1", true, ""},
		{"apis/num.io/v1", true, ""},
		{"apis/q.io/v1", true, ""},
		{"api/v2", true, ""},
		{"apis/apps/v2", false, ""},
		{"APIS/apps/v1", false, ""},
	}
	for _, tc := range cases {
		if hash, listed := r.Lookup(tc.key); listed != tc.listed || hash != tc.hash {
			t.Errorf("Lookup(%q) = %q, %v; want %q, %v", tc.key, hash, listed, tc.hash, tc.listed)
		}
	}
}

func TestRoot_VersionsNameOnlyTheSameGroup(t *testing.T) {
	t.Parallel()
	r := testRoot(t)
	apps, _ := ParseAPIVersion("apps/v2")
	if got := r.Versions(apps); !slices.Equal(got, []string{"apps/v1", "apps/v1beta2"}) {
		t.Errorf("apps choices = %q", got)
	}
	core, _ := ParseAPIVersion("v9")
	if got := r.Versions(core); !slices.Equal(got, []string{"v1", "v2"}) {
		t.Errorf("core choices = %q", got)
	}
	listed, _ := ParseAPIVersion("apps/v1")
	if got := r.Versions(listed); !slices.Equal(got, []string{"apps/v1beta2"}) {
		t.Errorf("a listed version names itself: %q", got)
	}
	none, _ := ParseAPIVersion("nothing.io/v1")
	if got := r.Versions(none); got != nil {
		t.Errorf("unknown group choices = %q", got)
	}
}

func TestParseRoot_Refusals(t *testing.T) {
	t.Parallel()
	for body, want := range map[string]error{
		`[]`:                 ErrRootShape,
		`{"paths":[]}`:       ErrRootShape,
		`{"paths":null}`:     ErrRootShape,
		`{}`:                 ErrRootShape,
		`{"Paths":{"a":{}}}`: ErrRootShape,
		`not json`:           ErrScanRefused,
		`"paths"`:            ErrRootShape,
	} {
		if _, err := ParseRoot(t.Context(), []byte(body)); !errors.Is(err, want) {
			t.Errorf("ParseRoot(%s) err = %v, want %v", body, err, want)
		}
	}
	if _, err := ParseRoot(t.Context(), members(MaxRootElements)); !errors.Is(err, ErrScanRefused) {
		t.Errorf("a root over its element cap: err = %v", err)
	}
	if _, err := ParseRoot(t.Context(), []byte(`{"paths":{}}`)); err != nil {
		t.Errorf("an empty paths object: err = %v", err)
	}
}
