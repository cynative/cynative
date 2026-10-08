package auth

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	gitlabclass "github.com/cynative/cynative/internal/auth/gitlab"
	"github.com/cynative/cynative/internal/auth/openapidoc"
	"github.com/cynative/cynative/internal/cache"
)

// gitlabReleaseDocsFixture is a release document whose routes differ from gitlabDocsFixture (master): it has an
// operation master lacks and lacks master's runner operation.
const gitlabReleaseDocsFixture = `openapi: 3.0.0
info:
  version: '18.11'
paths:
  /api/v4/projects/{id}/issues:
    get:
      tags: [Issues]
      operationId: getApiV4ProjectsIdIssues
      parameters:
      - {in: path, name: id, required: true, schema: {type: string}}
  /api/v4/projects/{id}/release_only:
    get:
      tags: [Release only]
      operationId: getApiV4ProjectsIdReleaseOnly
      parameters:
      - {in: path, name: id, required: true, schema: {type: string}}
`

// gitlabReleaseRef is the tag the release fixture stands for.
const gitlabReleaseRef = "v18.11.0-ee"

// releaseDocsFetch serves the release fixture and counts its calls.
func releaseDocsFetch(n *atomic.Int32) func(context.Context) ([]byte, error) {
	return func(context.Context) ([]byte, error) {
		n.Add(1)

		return []byte(gitlabReleaseDocsFixture), nil
	}
}

// newVersionedGitLab builds a docs-only provider whose master docs fail the test when loaded and whose release
// fetcher hands out fetch, recording the refs it is asked for.
func newVersionedGitLab(
	t *testing.T, dir string, clock func() time.Time, fetch func(context.Context) ([]byte, error), refs *[]string,
) *gitlabProvider {
	t.Helper()
	p := newDocsOnlyGitLab(t, "gitlab.example", "", func(context.Context) ([]byte, error) {
		t.Error("master docs fetched")

		return nil, errors.New("master")
	})
	p.docsCfg = cache.Config{Dir: dir, TTL: time.Hour, Clock: clock}
	p.releaseFetch = func(ref string) func(context.Context) ([]byte, error) {
		*refs = append(*refs, ref)

		return fetch
	}

	return p
}

func TestChooseGitLabDocs(t *testing.T) {
	t.Parallel()
	ok := func(v string) metadataOutcome { return metadataOutcome{ok: true, version: v} }
	cases := []struct {
		name   string
		md     metadataOutcome
		served string
		class  gitlabclass.VersionClassification
		want   gitlabDocsChoice
	}{
		{
			"metadata read failed",
			metadataOutcome{reason: "probe failed: status 403"},
			"gitlab.example",
			gitlabclass.VersionUnknown,
			gitlabDocsChoice{unavailable: "the instance's GitLab version could not be read: probe failed: status 403"},
		},
		{
			"pre on gitlab.com", ok("19.5.0-pre"), "gitlab.com", gitlabclass.VersionMaster,
			gitlabDocsChoice{version: "19.5.0-pre"},
		},
		{
			"pre on gitlab.com:443", ok("19.5.0-pre"), "gitlab.com:443", gitlabclass.VersionMaster,
			gitlabDocsChoice{version: "19.5.0-pre"},
		},
		{
			"pre on an uppercase GitLab.COM", ok("19.5.0-pre"), "GitLab.COM", gitlabclass.VersionMaster,
			gitlabDocsChoice{version: "19.5.0-pre"},
		},
		{
			"pre on gitlab.com on a nondefault port", ok("19.5.0-pre"), "gitlab.com:8443", gitlabclass.VersionUnknown,
			gitlabDocsChoice{unavailable: `instance reports development version "19.5.0-pre" ` +
				`(only gitlab.com's development builds are supported)`},
		},
		{
			"pre on a self-managed host", ok("19.5.0-pre"), "gitlab.example", gitlabclass.VersionUnknown,
			gitlabDocsChoice{unavailable: `instance reports development version "19.5.0-pre" ` +
				`(only gitlab.com's development builds are supported)`},
		},
		{
			"EE release on a nondefault port", ok("18.11.0-ee"), "gitlab.example:8443", gitlabclass.VersionTag,
			gitlabDocsChoice{ref: "v18.11.0-ee", version: "18.11.0-ee"},
		},
		{
			"CE release reads the EE tag", ok("18.10.2"), "gitlab.example", gitlabclass.VersionTag,
			gitlabDocsChoice{ref: "v18.10.2-ee", version: "18.10.2"},
		},
		{
			"release on gitlab.com", ok("19.4.1-ee"), "gitlab.com", gitlabclass.VersionTag,
			gitlabDocsChoice{ref: "v19.4.1-ee", version: "19.4.1-ee"},
		},
		{
			"below the floor", ok("18.8.3-ee"), "gitlab.example", gitlabclass.VersionBelowFloor,
			gitlabDocsChoice{unavailable: `GitLab 18.9 or later required (instance reports "18.8.3-ee")`},
		},
		{
			"release candidate", ok("18.9.0-rc42-ee"), "gitlab.example", gitlabclass.VersionUnknown,
			gitlabDocsChoice{unavailable: `instance reports unrecognized version "18.9.0-rc42-ee"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			class, got := chooseGitLabDocs(tc.md, tc.served)
			if class != tc.class || got != tc.want {
				t.Errorf("class %v choice %+v, want %v %+v", class, got, tc.class, tc.want)
			}
		})
	}
}

// TestChooseGitLabDocs_HostileVersionNeverNamesARef pins that a version the instance controls cannot steer the
// document URL: anything outside the grammar selects no ref, and every ref that is selected is a plain release tag.
func TestChooseGitLabDocs_HostileVersionNeverNamesARef(t *testing.T) {
	t.Parallel()
	tag := regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-ee$`)
	hostile := []string{
		"18.9.0-ee/../../../evil", "18.9.0-ee?x=1", "18.9.0-ee#frag", "18.9.0-ee%2F..", "../master", " 18.9.0-ee",
		"18.9.0-ee\n", "18.9.0-ee/", "master", "v18.9.0-ee", "18.9.0-ee-ee", "18.9.0\x00-ee", "18.9.0-EE",
		"18.9.0-pre/../x", strings.Repeat("1", 4096),
	}
	for _, v := range hostile {
		_, got := chooseGitLabDocs(metadataOutcome{ok: true, version: v}, "gitlab.com")
		if got.ref != "" || got.version != "" || got.unavailable == "" {
			t.Errorf("%q: choice %+v", v, got)
		}
	}
	for _, v := range []string{"18.9.0-ee", "18.9.0", "9999.9999.9999-ee"} {
		_, got := chooseGitLabDocs(metadataOutcome{ok: true, version: v}, "gitlab.example")
		if !tag.MatchString(got.ref) {
			t.Errorf("%q: ref %q", v, got.ref)
		}
		if u := gitlabOpenAPIRefURL(got.ref); u != "https://gitlab.com/gitlab-org/gitlab/-/raw/"+got.ref+
			"/doc/api/openapi/openapi_v3.yaml" {
			t.Errorf("%q: url %q", v, u)
		}
	}
	if gitlabOpenAPIRefURL("master") != gitlabOpenAPIURL {
		t.Errorf("master url %q", gitlabOpenAPIRefURL("master"))
	}
}

// TestGitLabUseDocs_ReleaseGetsItsOwnCache pins a release ref onto a docs cache of its own name, fetched through
// the release fetcher for exactly that ref, with master's docs never touched.
func TestGitLabUseDocs_ReleaseGetsItsOwnCache(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var fetches atomic.Int32
	var refs []string
	p := newVersionedGitLab(t, dir, time.Now, releaseDocsFetch(&fetches), &refs)
	p.useDocs(gitlabDocsChoice{ref: gitlabReleaseRef, version: "18.11.0-ee"})
	if p.release == nil || p.release.cache.DataPath != filepath.Join(dir, "docs-v18.11.0-ee.json") ||
		p.release.cache.MetaPath != filepath.Join(dir, "docs-v18.11.0-ee.meta") {
		t.Fatalf("release docs %+v", p.release)
	}
	if len(refs) != 1 || refs[0] != gitlabReleaseRef {
		t.Fatalf("release fetcher asked for %q", refs)
	}
	res := p.Reference(t.Context(), apiref.Query{Operation: "getApiV4ProjectsIdReleaseOnly"})
	if res.Reference == nil || res.Reference.Operation != "getApiV4ProjectsIdReleaseOnly" {
		t.Fatalf("res = %+v", res)
	}
	if miss := p.Reference(t.Context(), apiref.Query{Operation: "deleteApiV4Runners"}); miss.Outcome !=
		apiref.OutcomeNotFound {
		t.Errorf("a master-only operation answered from the release: %+v", miss)
	}
	p.Reference(t.Context(), apiref.Query{Operation: "getApiV4ProjectsIdIssues"})
	if n := fetches.Load(); n != 1 {
		t.Errorf("release fetched %d times, want 1", n)
	}
}

// seedDocsCache loads a docs cache named name in dir from raw, so its payload and sidecar exist on disk.
func seedDocsCache(t *testing.T, dir, name, raw string, clock func() time.Time) {
	t.Helper()
	c := cache.NewNamedCache(cache.Config{Dir: dir, TTL: time.Hour, Clock: clock}, name,
		func(context.Context) ([]byte, error) { return []byte(raw), nil },
		gitlabclass.DistillReleaseDocs, (*openapidoc.OperationDocs).Serialize, openapidoc.Unmarshal, openapidoc.Admit)
	if c.Get(t.Context()) == nil {
		t.Fatalf("seed %s failed", name)
	}
}

// TestGitLabReference_NeverSubstitutesAnotherRef pins that fresh docs for master (the legacy docs.json) and for
// another release are never read for the selected release: its own load fails and the reference says why.
func TestGitLabReference_NeverSubstitutesAnotherRef(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	seedDocsCache(t, dir, "docs", gitlabDocsFixture, time.Now)
	seedDocsCache(t, dir, "docs-v18.10.0-ee", gitlabReleaseDocsFixture, time.Now)
	var refs []string
	p := newVersionedGitLab(t, dir, time.Now, func(context.Context) ([]byte, error) {
		return nil, errors.New("gitlab_hardening: fetch openapi: status 404")
	}, &refs)
	p.useDocs(gitlabDocsChoice{ref: gitlabReleaseRef, version: "18.11.0-ee"})
	res := p.Reference(t.Context(), apiref.Query{Operation: "getApiV4ProjectsIdIssues"})
	want := "GitLab OpenAPI documentation for v18.11.0-ee could not be loaded: " +
		"gitlab_hardening: fetch openapi: status 404"
	if res.Outcome != apiref.OutcomeUnavailable || res.Reason != want || res.Reference != nil {
		t.Errorf("res = %+v", res)
	}
	if h := p.Hint(t.Context(), authreq.View{Method: "GET", EscapedPath: "/api/v4/projects/1/issue"}, nil); len(
		h.Candidates) != 0 {
		t.Errorf("hint = %+v", h)
	}
}

// TestGitLabReference_ServesStaleSameRef pins that the selected release's own expired docs are served when its
// refresh fails.
func TestGitLabReference_ServesStaleSameRef(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	then := time.Unix(1_000_000, 0)
	seedDocsCache(t, dir, "docs-"+gitlabReleaseRef, gitlabReleaseDocsFixture, func() time.Time { return then })
	var refs []string
	var refreshes atomic.Int32
	p := newVersionedGitLab(t, dir, func() time.Time { return then.Add(48 * time.Hour) },
		func(context.Context) ([]byte, error) {
			refreshes.Add(1)

			return nil, errors.New("offline")
		}, &refs)
	p.useDocs(gitlabDocsChoice{ref: gitlabReleaseRef, version: "18.11.0-ee"})
	res := p.Reference(t.Context(), apiref.Query{Operation: "getApiV4ProjectsIdReleaseOnly"})
	if res.Reference == nil || res.Reference.Operation != "getApiV4ProjectsIdReleaseOnly" {
		t.Errorf("res = %+v", res)
	}
	if refreshes.Load() != 1 {
		t.Errorf("refreshes = %d, want 1 (the stale docs must have been expired)", refreshes.Load())
	}
}

// TestGitLabReference_UnavailableWithoutAMatchingDocument pins that an instance whose version selected no
// document answers unavailable with the reason, loads no docs and suggests nothing.
func TestGitLabReference_UnavailableWithoutAMatchingDocument(t *testing.T) {
	t.Parallel()
	var refs []string
	p := newVersionedGitLab(t, t.TempDir(), time.Now, func(context.Context) ([]byte, error) {
		t.Error("release docs fetched")

		return nil, errors.New("release")
	}, &refs)
	p.useDocs(gitlabDocsChoice{unavailable: `instance reports unrecognized version "18.9.0-custom"`})
	res := p.Reference(t.Context(), apiref.Query{Operation: "getApiV4ProjectsIdIssues"})
	want := `no GitLab OpenAPI document matches this instance: instance reports unrecognized version ` +
		`"18.9.0-custom"`
	if res.Outcome != apiref.OutcomeUnavailable || res.Reason != want {
		t.Errorf("res = %+v", res)
	}
	if h := p.Hint(t.Context(), authreq.View{Method: "GET", EscapedPath: "/api/v4/projects/1/issue"}, nil); len(
		h.Candidates) != 0 {
		t.Errorf("hint = %+v", h)
	}
	if len(refs) != 0 || p.release != nil {
		t.Errorf("refs %q release %+v", refs, p.release)
	}
}

// TestGitLabReference_UnavailableReasonIsBounded pins the reason's bound when the recorded cause is long.
func TestGitLabReference_UnavailableReasonIsBounded(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 5000)
	p := newDocsOnlyGitLab(t, "gitlab.example", "", nil)
	p.useDocs(gitlabDocsChoice{unavailable: long})
	if res := p.Reference(t.Context(), apiref.Query{Operation: "a"}); utf8.RuneCountInString(res.Reason) >
		apiref.MaxReason || !strings.HasPrefix(res.Reason, "no GitLab OpenAPI document matches this instance: x") {
		t.Errorf("reason has %d runes: %.80q", utf8.RuneCountInString(res.Reason), res.Reason)
	}
	failing := newDocsOnlyGitLab(t, "gitlab.example", "", func(context.Context) ([]byte, error) {
		return nil, errors.New(long)
	})
	failing.docsFailure = recordLoadFailure(failing.docs.cache)
	if res := failing.Reference(t.Context(), apiref.Query{Operation: "a"}); utf8.RuneCountInString(res.Reason) >
		apiref.MaxReason || !strings.HasPrefix(res.Reason, "GitLab OpenAPI documentation could not be loaded: x") {
		t.Errorf("reason has %d runes: %.80q", utf8.RuneCountInString(res.Reason), res.Reason)
	}
}

// TestGitLabReference_SurfacesTheLoadFailure pins the recorded cause of a failed master docs load: the fetch
// error, and the distiller's error for a document it rejects.
func TestGitLabReference_SurfacesTheLoadFailure(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		fetch func(context.Context) ([]byte, error)
		want  string
	}{
		"fetch status": {
			func(context.Context) ([]byte, error) {
				return nil, errors.New("gitlab_hardening: fetch openapi: status 503")
			},
			"GitLab OpenAPI documentation could not be loaded: gitlab_hardening: fetch openapi: status 503",
		},
		"parse error": {
			func(context.Context) ([]byte, error) { return []byte("paths: [a"), nil },
			"GitLab OpenAPI documentation could not be loaded: openapidoc: operation docs rejected: parse openapi: ",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := newDocsOnlyGitLab(t, "gitlab.example", "", tc.fetch)
			p.docsFailure = recordLoadFailure(p.docs.cache)
			res := p.Reference(t.Context(), apiref.Query{Operation: "getApiV4ProjectsId"})
			if res.Outcome != apiref.OutcomeUnavailable || !strings.HasPrefix(res.Reason, tc.want) {
				t.Errorf("reason %q, want prefix %q", res.Reason, tc.want)
			}
		})
	}
}

// TestRecordLoadFailure_ClearsOnSuccess pins that a later successful fetch clears the recorded cause.
func TestRecordLoadFailure_ClearsOnSuccess(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	c := newGitLabDocsCache(t.TempDir(), func(context.Context) ([]byte, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("first")
		}

		return []byte(gitlabDocsFixture), nil
	})
	f := recordLoadFailure(c)
	same := func(s string) string { return s }
	if c.Get(t.Context()) != nil || f.reason("base", same) != "base: first" {
		t.Fatalf("after a failure: %q", f.reason("base", same))
	}
	if c.Get(t.Context()) == nil || f.reason("base", nil) != "base" {
		t.Errorf("after a success: %q", f.reason("base", nil))
	}
	var none *loadFailure
	if none.reason("base", nil) != "base" {
		t.Errorf("nil recorder: %q", none.reason("base", nil))
	}
}

// TestGitLabOutcome_SelectsDocsFromMetadata pins the docs registration selects from the metadata it read and the
// served authority, api_host included.
func TestGitLabOutcome_SelectsDocsFromMetadata(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		cfg           GitLabHardeningConfig
		md            metadataOutcome
		ref           string
		unavailablePf string
	}{
		{
			"gitlab.com pre reads master",
			GitLabHardeningConfig{},
			metadataOutcome{ok: true, version: "19.5.0-pre"},
			"",
			"",
		},
		{
			"release reads its tag",
			GitLabHardeningConfig{Host: "gitlab.example"},
			metadataOutcome{ok: true, version: "18.11.0-ee"},
			gitlabReleaseRef, "",
		},
		{
			"api_host decides the authority",
			GitLabHardeningConfig{APIHost: "api.gitlab.example"},
			metadataOutcome{ok: true, version: "19.5.0-pre"},
			"", "instance reports development version",
		},
		{
			"api_host on gitlab.com",
			GitLabHardeningConfig{Host: "gitlab.example", APIHost: "GitLab.com:443"},
			metadataOutcome{ok: true, version: "19.5.0-pre"},
			"", "",
		},
		{
			"failed metadata",
			GitLabHardeningConfig{},
			metadataOutcome{reason: "probe failed: timeout"},
			"",
			"the instance's GitLab version could not be read: probe failed: timeout",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := stubDeps()
			var refs []string
			built := newVersionedGitLab(t, t.TempDir(), time.Now, releaseDocsFetch(new(atomic.Int32)), &refs)
			d.buildGitLab = func(GitLabHardeningConfig, string, glabCredential) (*gitlabProvider, error) {
				return built, nil
			}
			d.fetchGitLabMetadata = func(context.Context, *gitlabProvider) metadataOutcome { return tc.md }
			out := d.gitlabOutcome(t.Context(), tc.cfg, false)
			if len(out.providers) != 1 {
				t.Fatalf("out = %+v", out)
			}
			c := built.docsChoice
			if c.ref != tc.ref || !strings.HasPrefix(c.unavailable, tc.unavailablePf) ||
				(tc.unavailablePf == "") != (c.unavailable == "") {
				t.Errorf("choice %+v", c)
			}
			if (tc.ref != "") != (built.release != nil) {
				t.Errorf("release docs %+v for ref %q", built.release, tc.ref)
			}
		})
	}
}

// TestBuildGitLabProvider_WiresVersionedDocs pins the constructor's seams for version-matched docs: the master
// docs' failure recorder and a release fetcher whose cache lands beside the others.
func TestBuildGitLabProvider_WiresVersionedDocs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := GitLabHardeningConfig{Dir: dir, TTL: time.Hour, Clock: time.Now}
	p, err := buildGitLabProvider(cfg, "gitlab.example", glabCredential{AccessToken: "glpat-test"}, NoProxy())
	if err != nil {
		t.Fatal(err)
	}
	if p.docsFailure == nil || p.releaseFetch == nil {
		t.Fatalf("failure %v fetcher set %v", p.docsFailure, p.releaseFetch != nil)
	}
	p.useDocs(gitlabDocsChoice{ref: gitlabReleaseRef, version: "18.11.0-ee"})
	if p.release == nil || p.release.cache.DataPath != filepath.Join(dir, "docs-"+gitlabReleaseRef+".json") {
		t.Errorf("release docs %+v", p.release)
	}
}

// TestGitLabReference_ScrubsProxyCredentials pins that a proxy credential carried by a failure's text is
// replaced before the reason reaches api_reference, and before it is bounded, so a cut can never leave part of
// one behind. It covers the metadata read's reason and the master and release docs' load failures.
func TestGitLabReference_ScrubsProxyCredentials(t *testing.T) {
	t.Parallel()
	const (
		proxyErr = "proxyconnect tcp: Proxy Authentication Required alice:s3cret"
		scrubbed = "proxyconnect tcp: Proxy Authentication Required " + scrubPlaceholder
	)
	egress := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://alice:s3cret@proxy.corp:3128"})
	failing := func(context.Context) ([]byte, error) { return nil, errors.New(proxyErr) }
	q := apiref.Query{Operation: "getApiV4ProjectsIdIssues"}
	t.Run("metadata failure", func(t *testing.T) {
		t.Parallel()
		p := newDocsOnlyGitLab(t, "gitlab.example", "", nil)
		p.egress = egress
		_, choice := chooseGitLabDocs(metadataOutcome{reason: "probe failed: " + proxyErr}, "gitlab.example")
		p.useDocs(choice)
		want := "no GitLab OpenAPI document matches this instance: the instance's GitLab version could not be " +
			"read: probe failed: " + scrubbed
		if res := p.Reference(t.Context(), q); res.Reason != want {
			t.Errorf("reason = %q, want %q", res.Reason, want)
		}
	})
	t.Run("master docs load failure", func(t *testing.T) {
		t.Parallel()
		p := newDocsOnlyGitLab(t, "gitlab.example", "", failing)
		p.egress = egress
		p.docsFailure = recordLoadFailure(p.docs.cache)
		want := "GitLab OpenAPI documentation could not be loaded: " + scrubbed
		if res := p.Reference(t.Context(), q); res.Reason != want {
			t.Errorf("reason = %q, want %q", res.Reason, want)
		}
	})
	t.Run("release docs load failure", func(t *testing.T) {
		t.Parallel()
		var refs []string
		p := newVersionedGitLab(t, t.TempDir(), time.Now, failing, &refs)
		p.egress = egress
		p.useDocs(gitlabDocsChoice{ref: gitlabReleaseRef, version: "18.11.0-ee"})
		want := "GitLab OpenAPI documentation for v18.11.0-ee could not be loaded: " + scrubbed
		if res := p.Reference(t.Context(), q); res.Reason != want {
			t.Errorf("reason = %q, want %q", res.Reason, want)
		}
	})
	t.Run("credential across the bound", func(t *testing.T) {
		t.Parallel()
		p := newDocsOnlyGitLab(t, "gitlab.example", "", nil)
		p.egress = egress
		const base = "no GitLab OpenAPI document matches this instance: "
		// The pad puts the bound's cut inside the password, after "s3c".
		pad := strings.Repeat("x", apiref.MaxReason-3-len(base)-len("alice:s3c"))
		p.useDocs(gitlabDocsChoice{unavailable: pad + "alice:s3cret tail"})
		want := base + pad + scrubPlaceholder[:len("alice:s3c")] + "..."
		if res := p.Reference(t.Context(), q); res.Reason != want {
			t.Errorf("reason = %q, want %q", res.Reason, want)
		}
	})
}

// TestGitLabReference_NamesAnEmptyDocument pins what api-reference.md says of a document that parses but lists no
// operations: the reason names that rejection.
func TestGitLabReference_NamesAnEmptyDocument(t *testing.T) {
	t.Parallel()
	p := newDocsOnlyGitLab(t, "gitlab.example", "", func(context.Context) ([]byte, error) {
		return []byte("openapi: 3.0.0\npaths: {}\n"), nil
	})
	p.docsFailure = recordLoadFailure(p.docs.cache)
	res := p.Reference(t.Context(), apiref.Query{Operation: "getApiV4ProjectsId"})
	want := gitlabDocsUnloaded + ": openapidoc: operation docs rejected: no operations"
	if res.Outcome != apiref.OutcomeUnavailable || res.Reason != want {
		t.Errorf("res = %+v", res)
	}
}
