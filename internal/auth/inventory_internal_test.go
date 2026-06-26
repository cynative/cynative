package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	awshardening "github.com/cynative/cynative/internal/auth/aws"
	"github.com/cynative/cynative/internal/auth/exposure"
	githubhardening "github.com/cynative/cynative/internal/auth/github"
	gitlabclass "github.com/cynative/cynative/internal/auth/gitlab"
)

func TestParseGithubLogin(t *testing.T) {
	t.Parallel()

	if got := parseGithubLogin(http.StatusOK, strings.NewReader(`{"login":"octocat"}`)); got != "@octocat" {
		t.Errorf("got %q, want @octocat", got)
	}
	if got := parseGithubLogin(http.StatusForbidden, strings.NewReader(`{"login":"x"}`)); got != "" {
		t.Errorf("non-200 → empty, got %q", got)
	}
	if got := parseGithubLogin(http.StatusOK, strings.NewReader(`not json`)); got != "" {
		t.Errorf("bad json → empty, got %q", got)
	}
	if got := parseGithubLogin(http.StatusOK, strings.NewReader(`{"login":""}`)); got != "" {
		t.Errorf("empty login → empty, got %q", got)
	}
}

func TestAWSPostureLabel(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"arn:aws:iam::aws:policy/SecurityAudit": "policy=arn:aws:iam::aws:policy/SecurityAudit",
		"SecurityAudit":                         "policy=SecurityAudit",
		"":                                      "policy=",
	} {
		if got := awsPostureLabel(in); got != want {
			t.Errorf("awsPostureLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGcpPostureLabel(t *testing.T) {
	t.Parallel()

	if got := gcpPostureLabel("roles/viewer"); got != "role=roles/viewer" {
		t.Errorf("got %q, want role=roles/viewer", got)
	}
}

func TestAzurePostureLabel_WithGUID(t *testing.T) {
	t.Parallel()

	got := azurePostureLabel("Reader", "acdd72a7-3385-48ef-bd42-f606fba81ae7")
	want := "role definition=Reader (acdd72a7-3385-48ef-bd42-f606fba81ae7)"
	if got != want {
		t.Fatalf("azurePostureLabel = %q, want %q", got, want)
	}
}

func TestAWSEnforced(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		r    awshardening.ScopeResult
		want string
	}{
		{
			name: "verified assume-role",
			r: awshardening.ScopeResult{ //nolint:exhaustruct // mode+verified.
				Mode:     awshardening.CredScopeAssumeRole,
				Verified: true,
			},
			want: enforcedClientAWS,
		},
		{
			name: "unverified assume-role",
			r: awshardening.ScopeResult{ //nolint:exhaustruct // mode only.
				Mode: awshardening.CredScopeAssumeRole,
			},
			want: enforcedClientAWSUnverified,
		},
		{
			name: "disabled",
			r:    awshardening.ScopeResult{Mode: awshardening.CredScopeDisabled}, //nolint:exhaustruct // mode only.
			want: enforcedClient,
		},
	}
	for _, tc := range cases {
		if got := awsEnforced(tc.r); got != tc.want {
			t.Errorf("%s: awsEnforced = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestGithubPosture_AccessPrefix(t *testing.T) {
	t.Parallel()

	posture, _ := githubPosture(githubhardening.BuildExposure(nil), nil)
	if !strings.HasPrefix(posture, "access=default(read-only) · enforced=client · permissions=") {
		t.Fatalf("githubPosture = %q", posture)
	}
}

func TestK8sPostureLabel(t *testing.T) {
	t.Parallel()

	if got := k8sPostureLabel("view"); got != "cluster role=view" {
		t.Errorf("got %q, want cluster role=view", got)
	}
}

func TestGithubPosture(t *testing.T) {
	t.Parallel()

	if p, w := githubPosture(githubhardening.BaselineExposure(), nil); w ||
		p != "access=default(read-only) · enforced=client · permissions=default=read,secret-scanning=none" {
		t.Errorf("githubPosture(baseline) = (%q,%v), want quiet full posture", p, w)
	}
	loudMap := map[string]string{"issues": "write"}
	loud := exposure.MergeExposure(githubhardening.BaselineExposure(), exposure.Exposure{"issues": exposure.LevelWrite})
	if p, w := githubPosture(loud, loudMap); !w ||
		p != "access=custom · enforced=client · permissions=default=read,issues=write,secret-scanning=none" {
		t.Errorf("githubPosture(write) = (%q,%v), want loud override scalar", p, w)
	}
}

func TestGitlabPosture(t *testing.T) {
	t.Parallel()

	if p, w := gitlabPosture(gitlabclass.BaselineExposure(), nil); w ||
		p != "access=default(read-only) · enforced=client · permissions=default=read,ci-variables=none" {
		t.Errorf("gitlabPosture(baseline) = (%q,%v), want quiet full posture", p, w)
	}
	loudMap := map[string]string{"default": "write"}
	loud := exposure.MergeExposure(gitlabclass.BaselineExposure(), exposure.Exposure{"default": exposure.LevelWrite})
	if p, w := gitlabPosture(loud, loudMap); !w ||
		p != "access=custom · enforced=client · permissions=default=write,ci-variables=none" {
		t.Errorf("gitlabPosture(write) = (%q,%v), want loud default=write scalar", p, w)
	}
}

func TestJoinIdentity(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ p, pr, want string }{
		{"proj", "me@x", "proj · me@x"}, {"proj", "", "proj"}, {"", "me@x", "me@x"}, {"", "", ""},
	} {
		if got := joinIdentity(tt.p, tt.pr); got != tt.want {
			t.Errorf("joinIdentity(%q,%q) = %q, want %q", tt.p, tt.pr, got, tt.want)
		}
	}
}

func TestEmitOutcome(t *testing.T) {
	t.Parallel()

	out := connectorOutcome{
		providers: []Provider{nil, nil},
		statuses:  []ConnectorStatus{{Name: "aws"}, {Name: "eks"}}, //nolint:exhaustruct // name only.
		visible:   []bool{true, false},                             // eks status suppressed.
	}
	var seen []string
	got := emitOutcome(out, func(s ConnectorStatus) { seen = append(seen, s.Name) })
	if len(got) != 2 {
		t.Errorf("providers = %d, want 2", len(got))
	}
	if len(seen) != 1 || seen[0] != "aws" {
		t.Errorf("emitted %v, want [aws]", seen)
	}
	// nil onStatus must not panic.
	if ps := emitOutcome(out, nil); len(ps) != 2 {
		t.Errorf("nil onStatus: providers = %d, want 2", len(ps))
	}
}

// nameProv is a minimal Provider whose Name identifies its registrar, so the test
// can assert the RETURNED provider order is registrar order (deterministic).
type nameProv struct{ n string }

func (p nameProv) Name() string                                    { return p.n }
func (p nameProv) Description() string                             { return "" }
func (p nameProv) InjectAuth(*http.Request, json.RawMessage) error { return nil }
func (p nameProv) AuthorizesHost(context.Context, string, json.RawMessage) (bool, error) {
	return false, nil
}

func TestDriveConcurrent(t *testing.T) {
	t.Parallel()

	mk := func(name string, visible bool, delay bool) func() connectorOutcome {
		return func() connectorOutcome {
			if delay {
				time.Sleep(20 * time.Millisecond) // a slow registrar finishes LAST in completion order.
			}

			return connectorOutcome{
				providers: []Provider{nameProv{n: name}},
				statuses:  []ConnectorStatus{{Name: name}}, //nolint:exhaustruct // name only.
				visible:   []bool{visible},
			}
		}
	}

	var mu sync.Mutex
	var seen []string
	registrars := []func() connectorOutcome{
		mk("slow", true, true), mk("fast", true, false), mk("quiet", false, false),
	}
	providers := driveConcurrent(registrars, func(s ConnectorStatus) {
		mu.Lock()
		seen = append(seen, s.Name)
		mu.Unlock()
	})

	want := []string{"slow", "fast", "quiet"}
	if len(providers) != len(want) {
		t.Fatalf("accumulated %d providers, want %d", len(providers), len(want))
	}
	for i, w := range want {
		if got := providers[i].Name(); got != w {
			t.Errorf("providers[%d] = %q, want %q (return order must be registrar order)", i, got, w)
		}
	}
	if len(seen) != 2 || seen[len(seen)-1] != "slow" {
		t.Errorf("emitted %v, want [fast, slow] in completion order (slow last)", seen)
	}
}

func TestDriveConcurrent_NilOnStatus(t *testing.T) {
	t.Parallel()

	got := driveConcurrent([]func() connectorOutcome{
		func() connectorOutcome {
			return connectorOutcome{ //nolint:exhaustruct // name only.
				providers: []Provider{nil},
				statuses:  []ConnectorStatus{{Name: "a"}}, //nolint:exhaustruct // name only.
				visible:   []bool{true},
			}
		},
	}, nil)
	if len(got) != 1 {
		t.Errorf("accumulated %d providers, want 1 (nil onStatus must not panic)", len(got))
	}
}

func TestBuildPosture(t *testing.T) {
	t.Parallel()

	got := buildPosture(accessDefault, enforcedClient, "role=roles/viewer")
	want := "access=default(read-only) · enforced=client · role=roles/viewer"
	if got != want {
		t.Fatalf("buildPosture = %q, want %q", got, want)
	}
}

func TestAccessHelpers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"aws default", awsAccess(defaultAWSPolicyARN), accessDefault},
		{"aws custom", awsAccess("arn:aws:iam::123456789012:policy/My"), accessCustom},
		{"gcp default", gcpAccess(defaultGCPRole), accessDefault},
		{"gcp custom", gcpAccess("roles/editor"), accessCustom},
		{"azure default exact", azureAccess("Reader"), accessDefault},
		{"azure default casefold", azureAccess("reader"), accessDefault},
		{"azure custom guid", azureAccess("acdd72a7-3385-48ef-bd42-f606fba81ae7"), accessCustom},
		{"k8s default", k8sAccess("view"), accessDefault},
		{"k8s custom", k8sAccess("edit"), accessCustom},
		{"exposure default (nil)", exposureAccess(nil), accessDefault},
		{"exposure default (empty)", exposureAccess(map[string]string{}), accessDefault},
		{"exposure custom", exposureAccess(map[string]string{"issues": "write"}), accessCustom},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestManagedK8sPosture(t *testing.T) {
	t.Parallel()

	got := ManagedK8sPosture("view")
	want := "access=default(read-only) · enforced=client · cluster role=view"
	if got != want {
		t.Fatalf("ManagedK8sPosture = %q, want %q", got, want)
	}
}
