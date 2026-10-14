package gcp

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/auth/authreq"
)

func classifyView(t *testing.T, method, rawurl string) authreq.View {
	t.Helper()

	u, err := url.Parse(rawurl)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	return authreq.NewView(&http.Request{Method: method, URL: u, Header: http.Header{}}, "")
}

func computeIndex() MethodIndex {
	return MethodIndex{
		"compute.instances.list": {
			ID:          "compute.instances.list",
			HTTPMethod:  "GET",
			FlatPath:    "projects/{project}/zones/{zone}/instances",
			ServicePath: "compute/v1/",
		},
		"compute.instances.insert": {
			ID:          "compute.instances.insert",
			HTTPMethod:  "POST",
			FlatPath:    "projects/{project}/zones/{zone}/instances",
			ServicePath: "compute/v1/",
		},
		"compute.instances.get": {
			ID:          "compute.instances.get",
			HTTPMethod:  "GET",
			FlatPath:    "projects/{project}/zones/{zone}/instances/{instance}",
			ServicePath: "compute/v1/",
		},
		"compute.instances.delete": {
			ID:          "compute.instances.delete",
			HTTPMethod:  "DELETE",
			FlatPath:    "projects/{project}/zones/{zone}/instances/{instance}",
			ServicePath: "compute/v1/",
		},
		"compute.instances.start": {
			ID:          "compute.instances.start",
			HTTPMethod:  "POST",
			FlatPath:    "projects/{project}/zones/{zone}/instances/{instance}/start",
			ServicePath: "compute/v1/",
		},
	}
}

// storageIndex returns a storage v1 index: no flatPath, so servicePath+path fallback is used.
func storageIndex() MethodIndex {
	return MethodIndex{
		"storage.buckets.list": {
			ID:          "storage.buckets.list",
			HTTPMethod:  "GET",
			ServicePath: "storage/v1/",
			Path:        "b",
		},
		"storage.buckets.getIamPolicy": {
			ID:          "storage.buckets.getIamPolicy",
			HTTPMethod:  "GET",
			ServicePath: "storage/v1/",
			Path:        "b/{bucket}/iam",
		},
		"storage.objects.insert": {
			ID:          "storage.objects.insert",
			HTTPMethod:  "POST",
			ServicePath: "upload/storage/v1/",
			Path:        "b/{bucket}/o",
		},
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		idx     MethodIndex
		v       authreq.View
		want    string
		wantErr bool
	}{
		{
			name: "list",
			idx:  computeIndex(),
			v:    classifyView(t, "GET", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"),
			want: "compute.instances.list",
		},
		{
			name: "insert same template POST",
			idx:  computeIndex(),
			v:    classifyView(t, "POST", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"),
			want: "compute.instances.insert",
		},
		{
			name: "get vs delete by method GET",
			idx:  computeIndex(),
			v:    classifyView(t, "GET", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/i"),
			want: "compute.instances.get",
		},
		{
			name: "delete",
			idx:  computeIndex(),
			v:    classifyView(t, "DELETE", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/i"),
			want: "compute.instances.delete",
		},
		{
			name: "literal verb start",
			idx:  computeIndex(),
			v: classifyView(
				t,
				"POST",
				"https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/i/start",
			),
			want: "compute.instances.start",
		},
		{
			name: "storage list fallback",
			idx:  storageIndex(),
			v:    classifyView(t, "GET", "https://storage.googleapis.com/storage/v1/b"),
			want: "storage.buckets.list",
		},
		{
			name: "media upload",
			idx:  storageIndex(),
			v:    classifyView(t, "POST", "https://storage.googleapis.com/upload/storage/v1/b/mybucket/o"),
			want: "storage.objects.insert",
		},
		{
			name:    "zero match fails",
			idx:     computeIndex(),
			v:       classifyView(t, "GET", "https://compute.googleapis.com/compute/v1/nope"),
			wantErr: true,
		},
		{
			name: "trailing slash trims like the whole-path trim it replaced",
			idx:  computeIndex(),
			v: classifyView(
				t,
				"GET",
				"https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/",
			),
			want: "compute.instances.list",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Classify(tc.idx, tc.v)
			if tc.wantErr {
				if !errors.Is(err, ErrClassifierUnknownOp) {
					t.Fatalf("Classify err = %v, want ErrClassifierUnknownOp", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("Classify: %v", err)
			}

			if got != tc.want {
				t.Errorf("Classify = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClassifyColonVerb(t *testing.T) {
	t.Parallel()

	idx := storageIndex()
	got, err := Classify(idx, classifyView(t, "GET", "https://storage.googleapis.com/storage/v1/b/mybucket/iam"))
	if err != nil || got != "storage.buckets.getIamPolicy" {
		t.Fatalf("getIamPolicy classify = %q err=%v", got, err)
	}
}

func TestClassifyAmbiguousFailClosed(t *testing.T) {
	t.Parallel()

	// Two methods with the same HTTP method and template must return ErrClassifierUnknownOp.
	ambiguous := MethodIndex{
		"svc.foo.get": {ID: "svc.foo.get", HTTPMethod: "GET", FlatPath: "v1/projects/{project}/foo/{foo}"},
		"svc.bar.get": {ID: "svc.bar.get", HTTPMethod: "GET", FlatPath: "v1/projects/{project}/foo/{foo}"},
	}

	_, err := Classify(ambiguous, classifyView(t, "GET", "https://example.googleapis.com/v1/projects/p/foo/f"))
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("ambiguous match must return ErrClassifierUnknownOp, got %v", err)
	}
}

// TestClassifyLiteralMismatch covers the branch where segment count matches but a
// literal template segment differs from the request (matchTemplate returns false
// via the segmentEqual path).
func TestClassifyLiteralMismatch(t *testing.T) {
	t.Parallel()

	// "compute/v2/projects/..." has the same segment count as the v1 templates but
	// the literal "v1" segment will not match "v2", so no survivor → fail closed.
	_, err := Classify(
		computeIndex(),
		classifyView(t, "GET", "https://compute.googleapis.com/compute/v2/projects/p/zones/z/instances"),
	)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("literal mismatch must return ErrClassifierUnknownOp, got %v", err)
	}
}

// TestClassifyColonVerbCustom covers segmentEqual's colon branch:
//   - placeholder base matches any resource value when verbs agree
//   - mismatched colon-verbs fail closed (returns ErrClassifierUnknownOp)
//   - literal base in a colon-verb template matches the corresponding literal
func TestClassifyColonVerbCustom(t *testing.T) {
	t.Parallel()

	// Index with a placeholder-base colon-verb and a literal-base colon-verb.
	idx := MethodIndex{
		"svc.res.setIamPolicy": {
			ID:         "svc.res.setIamPolicy",
			HTTPMethod: "POST",
			FlatPath:   "v1/projects/{project}/resources/{resource}:setIamPolicy",
		},
		"svc.globalRes.testPermissions": {
			ID:         "svc.globalRes.testPermissions",
			HTTPMethod: "POST",
			FlatPath:   "v1/globalResources/myRes:testPermissions",
		},
	}

	// Placeholder-base colon-verb: verb matches, base is placeholder → match.
	got, err := Classify(
		idx,
		classifyView(t, "POST", "https://example.googleapis.com/v1/projects/p/resources/r:setIamPolicy"),
	)
	if err != nil || got != "svc.res.setIamPolicy" {
		t.Fatalf("placeholder colon-verb: got %q err=%v", got, err)
	}

	// Mismatched colon-verb: request has :getIamPolicy but only :setIamPolicy exists → fail closed.
	_, err = Classify(
		idx,
		classifyView(t, "POST", "https://example.googleapis.com/v1/projects/p/resources/r:getIamPolicy"),
	)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("mismatched colon-verb must return ErrClassifierUnknownOp, got %v", err)
	}

	// Literal-base colon-verb: template literal "myRes" matches request literal exactly.
	got, err = Classify(
		idx,
		classifyView(t, "POST", "https://example.googleapis.com/v1/globalResources/myRes:testPermissions"),
	)
	if err != nil || got != "svc.globalRes.testPermissions" {
		t.Fatalf("literal colon-verb: got %q err=%v", got, err)
	}
}

// TestClassifyRealFlatPathShape pins Bug C: real Discovery flatPath is RELATIVE
// to servicePath (no version prefix); the classifier must prepend servicePath to
// match the real request path /compute/v1/projects/.../instances.
func TestClassifyRealFlatPathShape(t *testing.T) {
	t.Parallel()

	idx := MethodIndex{
		"compute.instances.list": {
			ID:          "compute.instances.list",
			HTTPMethod:  "GET",
			FlatPath:    "projects/{project}/zones/{zone}/instances", // real shape: no compute/v1/.
			ServicePath: "compute/v1/",
		},
	}
	got, err := Classify(
		idx,
		classifyView(t, "GET", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"),
	)
	if err != nil || got != "compute.instances.list" {
		t.Fatalf("real-shape classify: got=%q err=%v, want compute.instances.list", got, err)
	}
}

// TestClassifySplitSegmentsEmpty covers splitSegments("") returning nil so that
// an empty-path template (a zero-segment method) matches only an empty request path.
func TestClassifySplitSegmentsEmpty(t *testing.T) {
	t.Parallel()

	// A method whose FlatPath is "" (root-level REST call).
	idx := MethodIndex{
		"svc.root.get": {ID: "svc.root.get", HTTPMethod: "GET", FlatPath: ""},
	}
	// A request to the root "/" path (trimmed → "") must match.
	got, err := Classify(idx, classifyView(t, "GET", "https://example.googleapis.com/"))
	if err != nil || got != "svc.root.get" {
		t.Fatalf("empty flatPath root match: got %q err=%v", got, err)
	}
	// A request with any non-empty path must not match.
	_, err = Classify(idx, classifyView(t, "GET", "https://example.googleapis.com/v1/something"))
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("non-empty path vs empty template must fail closed, got %v", err)
	}
}

// TestClassifyBarePlaceholderRejectsCustomVerb pins that a bare {placeholder}
// template segment must NOT swallow a request segment carrying a custom verb:
// a POST to .../resources/r:customVerb must not classify as the sibling
// .../resources/{resource} write method.
func TestClassifyBarePlaceholderRejectsCustomVerb(t *testing.T) {
	t.Parallel()

	idx := MethodIndex{
		"svc.res.update": {
			ID:         "svc.res.update",
			HTTPMethod: "POST",
			FlatPath:   "v1/projects/{project}/resources/{resource}",
		},
	}

	_, err := Classify(
		idx,
		classifyView(t, "POST", "https://example.googleapis.com/v1/projects/p/resources/r:customVerb"),
	)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("custom-verb request must not match a bare-placeholder template, got %v", err)
	}
}

// slotIndex is the shape the encoded-slash case turns on: a write at the
// resource and a read one segment below it, both POST.
func slotIndex() MethodIndex {
	return MethodIndex{
		"compute.reservationSlots.update": {
			ID:          "compute.reservationSlots.update",
			HTTPMethod:  "POST",
			FlatPath:    "projects/{project}/reservationSlots/{slot}",
			ServicePath: "compute/v1/",
		},
		"compute.reservationSlots.getHealth": {
			ID:          "compute.reservationSlots.getHealth",
			HTTPMethod:  "POST",
			FlatPath:    "projects/{project}/reservationSlots/{slot}/getHealth",
			ServicePath: "compute/v1/",
		},
	}
}

// TestClassify_EncodedSlashTiesTheTwoReadings: the wire reading names the write
// at the resource, the decoded reading names the read below it. Two survivors
// is an ambiguity, and the gate denies rather than picking the read.
func TestClassify_EncodedSlashTiesTheTwoReadings(t *testing.T) {
	t.Parallel()

	v := classifyView(t, http.MethodPost,
		"https://compute.googleapis.com/compute/v1/projects/p/reservationSlots/x%2FgetHealth")

	id, err := Classify(slotIndex(), v)
	if !errors.Is(err, ErrClassifierUnknownOp) {
		t.Fatalf("Classify = %q, %v, want ErrClassifierUnknownOp", id, err)
	}

	// Assert the ambiguous-match message specifically, not just
	// ErrClassifierUnknownOp: that sentinel also covers zero survivors, so this
	// alone would still pass if the fix regressed to matching nothing.
	if !strings.Contains(err.Error(), "2 methods match") {
		t.Fatalf("Classify err = %q, want it to report 2 methods match", err)
	}
}

// objectIndex is a storage v1 index carrying an object read. storageIndex (used
// by other tests in this file) carries no object-read method, so this fixture is
// its own index rather than an addition to storageIndex.
func objectIndex() MethodIndex {
	return MethodIndex{
		"storage.objects.get": {
			ID:          "storage.objects.get",
			HTTPMethod:  "GET",
			ServicePath: "storage/v1/",
			Path:        "b/{bucket}/o/{object}",
		},
		"storage.buckets.list": {
			ID:          "storage.buckets.list",
			HTTPMethod:  "GET",
			ServicePath: "storage/v1/",
			Path:        "b",
		},
	}
}

// TestClassify_SlashNamedObjectMatchesOnTheWireReading: a GCS object name
// carries its slashes percent-encoded, so only the reading that keeps them
// inside the segment matches the template. The decoded reading names nothing.
func TestClassify_SlashNamedObjectMatchesOnTheWireReading(t *testing.T) {
	t.Parallel()

	v := classifyView(t, http.MethodGet,
		"https://storage.googleapis.com/storage/v1/b/bk/o/dir%2Ffile.txt")

	id, err := Classify(objectIndex(), v)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if id != "storage.objects.get" {
		t.Errorf("id = %q, want storage.objects.get", id)
	}
}

// apigeeIndex is the shape the encoded-colon case turns on: a bare write at the
// environment resource and its testIamPermissions custom verb, both POST.
// testIamPermissions needs no IAM permission, so a request that misclassifies
// onto it skips the write's permission check entirely.
func apigeeIndex() MethodIndex {
	return MethodIndex{
		"apigee.organizations.environments.updateEnvironment": {
			ID:         "apigee.organizations.environments.updateEnvironment",
			HTTPMethod: "POST",
			Path:       "v1/organizations/{organizationsId}/environments/{environmentsId}",
		},
		"apigee.organizations.environments.testIamPermissions": {
			ID:         "apigee.organizations.environments.testIamPermissions",
			HTTPMethod: "POST",
			Path:       "v1/organizations/{organizationsId}/environments/{environmentsId}:testIamPermissions",
		},
	}
}

// TestClassify_EncodedColonDoesNotForgeACustomVerb: Google's frontend routes
// the path as sent, so a percent-encoded colon inside the resource id never
// reads as the custom-verb separator there. The wire reading names the plain
// write; the decoded reading's extra segment (the %2F splits it) matches
// neither template and contributes nothing. Classify must resolve to the write
// it will actually run, not the permissionless probe a decoded colon would
// forge.
func TestClassify_EncodedColonDoesNotForgeACustomVerb(t *testing.T) {
	t.Parallel()

	v := classifyView(t, http.MethodPost,
		"https://apigee.googleapis.com/v1/organizations/o/environments/e%2Fx%3AtestIamPermissions")

	id, err := Classify(apigeeIndex(), v)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if id != "apigee.organizations.environments.updateEnvironment" {
		t.Errorf("id = %q, want apigee.organizations.environments.updateEnvironment (not the permissionless verb)", id)
	}
}

// TestClassify_PlainCustomVerbStillClassifies pins that the fix does not break
// a real custom verb: an unencoded colon still routes to testIamPermissions.
func TestClassify_PlainCustomVerbStillClassifies(t *testing.T) {
	t.Parallel()

	v := classifyView(t, http.MethodPost,
		"https://apigee.googleapis.com/v1/organizations/o/environments/e:testIamPermissions")

	id, err := Classify(apigeeIndex(), v)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if id != "apigee.organizations.environments.testIamPermissions" {
		t.Errorf("id = %q, want apigee.organizations.environments.testIamPermissions", id)
	}
}

// TestClassify_MarksOnlyZeroSurvivors pins that a request no method matches is marked unmatched, with the gate's
// text and sentinel unchanged, and that an ambiguous one is not.
func TestClassify_MarksOnlyZeroSurvivors(t *testing.T) {
	t.Parallel()

	_, err := Classify(computeIndex(), classifyView(t, "GET",
		"https://compute.googleapis.com/compute/v1/projects/p/zones/z/instancez"))
	var um *authreq.UnmatchedRequestError
	if !errors.As(err, &um) || um.Service != "" {
		t.Fatalf("zero survivors = %v, want an unmatched marker with no service", err)
	}
	const want = "gcp_hardening: cannot identify method from request: no method matches GET " +
		"/compute/v1/projects/p/zones/z/instancez"
	if !errors.Is(err, ErrClassifierUnknownOp) || err.Error() != want {
		t.Fatalf("zero survivors = %q, want %q wrapping ErrClassifierUnknownOp", err, want)
	}

	ambiguous := MethodIndex{
		"svc.foo.get": {ID: "svc.foo.get", HTTPMethod: "GET", FlatPath: "v1/projects/{project}/foo/{foo}"},
		"svc.bar.get": {ID: "svc.bar.get", HTTPMethod: "GET", FlatPath: "v1/projects/{project}/foo/{foo}"},
	}
	_, err = Classify(ambiguous, classifyView(t, "GET", "https://example.googleapis.com/v1/projects/p/foo/f"))
	if !errors.Is(err, ErrClassifierUnknownOp) || errors.As(err, &um) {
		t.Fatalf("ambiguous = %v, want ErrClassifierUnknownOp and no unmatched marker", err)
	}
}

// sslPolicyIndex holds compute's sslPolicies.get and listAvailableFeatures, whose
// literal last segment also fits get's {sslPolicy} (#377). The keys are chosen by the caller so a test can put either GET
// first in the classifier's sorted walk.
func sslPolicyIndex(getKey, listKey string) MethodIndex {
	const base = "projects/{project}/global/sslPolicies/"

	return MethodIndex{
		getKey: {
			ID: "compute.sslPolicies.get", HTTPMethod: "GET", ServicePath: "compute/v1/",
			FlatPath: base + "{sslPolicy}",
		},
		listKey: {
			ID: "compute.sslPolicies.listAvailableFeatures", HTTPMethod: "GET", ServicePath: "compute/v1/",
			FlatPath: base + "listAvailableFeatures",
		},
	}
}

// TestClassify_LiteralSegmentWins pins the precedence Google's path matcher
// applies: where two templates first differ, a literal segment beats a
// placeholder, whatever order the index lists them in and however many literals
// each has; a custom verb is not part of that comparison; and a placeholder
// route still wins a request whose method the literal route does not serve.
func TestClassify_LiteralSegmentWins(t *testing.T) {
	t.Parallel()

	const ssl = "https://compute.googleapis.com/compute/v1/projects/p/global/sslPolicies/"

	verbIdx := MethodIndex{
		"svc.res.verb":  {ID: "svc.res.verb", HTTPMethod: "POST", FlatPath: "v1/res/{res}:run"},
		"svc.mine.verb": {ID: "svc.mine.verb", HTTPMethod: "POST", FlatPath: "v1/res/mine:run"},
	}
	verbPlaceholderFirstIdx := MethodIndex{
		"svc.a.verb": {ID: "svc.a.verb", HTTPMethod: "POST", FlatPath: "v1/res/{res}:run"},
		"svc.b.verb": {ID: "svc.b.verb", HTTPMethod: "POST", FlatPath: "v1/res/mine:run"},
	}
	postOnlyIdx := MethodIndex{
		"svc.get":  {ID: "svc.get", HTTPMethod: "GET", FlatPath: "v1/res/{res}"},
		"svc.post": {ID: "svc.post", HTTPMethod: "POST", FlatPath: "v1/res/mine"},
	}
	leftmostIdx := MethodIndex{
		"svc.a": {ID: "svc.a", HTTPMethod: "GET", FlatPath: "v1/{x}/b/c"},
		"svc.b": {ID: "svc.b", HTTPMethod: "GET", FlatPath: "v1/a/{y}/{z}"},
	}

	tieThenBetterIdx := MethodIndex{
		"svc.a1": {ID: "svc.a1", HTTPMethod: "GET", FlatPath: "v1/{x}/{y}"},
		"svc.a2": {ID: "svc.a2", HTTPMethod: "GET", FlatPath: "v1/{p}/{q}"},
		"svc.c":  {ID: "svc.c", HTTPMethod: "GET", FlatPath: "v1/{x}/b"},
	}
	sameIDIdx := MethodIndex{
		"svc.dup":    {ID: "svc.dup", HTTPMethod: "GET", FlatPath: "v1/res/mine"},
		"svc.dup~v2": {ID: "svc.dup", HTTPMethod: "GET", FlatPath: "v1/res/mine"},
		"svc.get":    {ID: "svc.get", HTTPMethod: "GET", FlatPath: "v1/res/{res}"},
	}

	cases := []struct {
		name, method, url, want string
		idx                     MethodIndex
	}{
		{"tie then better", "GET", "https://example.googleapis.com/v1/a/b", "svc.c", tieThenBetterIdx},
		{"same id ties with itself", "GET", "https://example.googleapis.com/v1/res/mine", "svc.dup", sameIDIdx},
		{
			"literal after placeholder", "GET", ssl + "listAvailableFeatures",
			"compute.sslPolicies.listAvailableFeatures", sslPolicyIndex("a.get", "b.list"),
		},
		{
			"literal before placeholder", "GET", ssl + "listAvailableFeatures",
			"compute.sslPolicies.listAvailableFeatures", sslPolicyIndex("b.get", "a.list"),
		},
		{
			"other names keep the get", "GET", ssl + "my-policy",
			"compute.sslPolicies.get", sslPolicyIndex("a.get", "b.list"),
		},
		{"leftmost difference decides", "GET", "https://example.googleapis.com/v1/a/b/c", "svc.b", leftmostIdx},
		{"literal route lacks the method", "GET", "https://example.googleapis.com/v1/res/mine", "svc.get", postOnlyIdx},
		{"verb base compared", "POST", "https://example.googleapis.com/v1/res/mine:run", "svc.mine.verb", verbIdx},
		{
			"verb base compared, placeholder first", "POST", "https://example.googleapis.com/v1/res/mine:run",
			"svc.b.verb", verbPlaceholderFirstIdx,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Classify(tc.idx, classifyView(t, tc.method, tc.url))
			if err != nil || got != tc.want {
				t.Fatalf("Classify = %q, %v, want %q", got, err, tc.want)
			}
		})
	}
}

// TestClassify_LiteralWinsOnlyWithinAReading pins that the precedence ranks the
// templates one reading matched and never overrides a disagreement between
// readings. The escaped reading of listAvailable%46eatures keeps the escape, so
// only get's {sslPolicy} matches it; the decoded reading spells the literal, so
// listAvailableFeatures wins there. Two readings naming two methods stay
// ambiguous.
func TestClassify_LiteralWinsOnlyWithinAReading(t *testing.T) {
	t.Parallel()

	v := classifyView(t, "GET",
		"https://compute.googleapis.com/compute/v1/projects/p/global/sslPolicies/listAvailable%46eatures")

	id, err := Classify(sslPolicyIndex("a.get", "b.list"), v)
	if !errors.Is(err, ErrClassifierUnknownOp) || !strings.Contains(err.Error(), "2 methods match") {
		t.Fatalf("Classify = %q, %v, want 2 methods match", id, err)
	}
}

// TestClassify_LiteralRankingStillDenies pins the requests the precedence must
// leave ambiguous: two best routes to different methods, and two routes to
// different methods where any literal matched only up to case, the losing route
// included. The path matcher the ranking follows looks
// literals up exactly, so it routes listavailablefeatures to {sslPolicy}, and
// v1/a/b to v1/{x}/{y}; ranking the case-folded match would pick the other
// method in both.
func TestClassify_LiteralRankingStillDenies(t *testing.T) {
	t.Parallel()

	const ssl = "https://compute.googleapis.com/compute/v1/projects/p/global/sslPolicies/"

	bestTieIdx := MethodIndex{
		"svc.a": {ID: "svc.a", HTTPMethod: "GET", FlatPath: "v1/res/mine"},
		"svc.b": {ID: "svc.b", HTTPMethod: "GET", FlatPath: "v1/res/mine"},
		"svc.c": {ID: "svc.c", HTTPMethod: "GET", FlatPath: "v1/res/{res}"},
	}
	foldedLoserIdx := MethodIndex{
		"svc.exact":  {ID: "svc.exact", HTTPMethod: "GET", FlatPath: "v1/a/{x}"},
		"svc.folded": {ID: "svc.folded", HTTPMethod: "GET", FlatPath: "v1/{y}/B"},
	}
	foldedVerbIdx := MethodIndex{
		"svc.cased": {ID: "svc.cased", HTTPMethod: "POST", FlatPath: "v1/res/Mine:run"},
		"svc.res":   {ID: "svc.res", HTTPMethod: "POST", FlatPath: "v1/res/{res}:run"},
	}
	laterLiteralIdx := MethodIndex{
		"svc.cased":   {ID: "svc.cased", HTTPMethod: "GET", FlatPath: "v1/A/b"},
		"svc.generic": {ID: "svc.generic", HTTPMethod: "GET", FlatPath: "v1/{x}/{y}"},
	}

	cases := []struct {
		name, method, url string
		idx               MethodIndex
	}{
		{"best routes tie", "GET", "https://example.googleapis.com/v1/res/mine", bestTieIdx},
		{"case-folded losing literal", "GET", "https://example.googleapis.com/v1/a/b", foldedLoserIdx},
		{"case-folded verb base", "POST", "https://example.googleapis.com/v1/res/mine:run", foldedVerbIdx},
		{"case-folded last literal", "GET", ssl + "listavailablefeatures", sslPolicyIndex("a.get", "b.list")},
		{"case-folded literal before a deciding one", "GET", "https://example.googleapis.com/v1/a/b", laterLiteralIdx},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			id, err := Classify(tc.idx, classifyView(t, tc.method, tc.url))
			if !errors.Is(err, ErrClassifierUnknownOp) || !strings.Contains(err.Error(), "2 methods match") {
				t.Fatalf("Classify = %q, %v, want 2 methods match", id, err)
			}
		})
	}
}
