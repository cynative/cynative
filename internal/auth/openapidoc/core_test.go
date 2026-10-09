package openapidoc_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/openapidoc"
)

func TestDistill_PrefersJSON(t *testing.T) {
	t.Parallel()
	d := distillTest(t, `{"paths":{
	"/a":{"get":{"operationId":"a","responses":{"200":{"content":{"application/cbor":{},"application/json":{}}}}}},
	"/b":{"get":{"operationId":"b","responses":{"200":{"content":{"text/zeta":{},"text/alpha":{}}}}}}}}`)
	if got := d.Ops["a"].ResponseType; got != "application/json" {
		t.Errorf("cbor and json: %q", got)
	}
	if got := d.Ops["b"].ResponseType; got != "text/alpha" {
		t.Errorf("zeta and alpha: %q", got)
	}
}

func TestDistill_Keep(t *testing.T) {
	t.Parallel()
	prof := testProfile()
	var seen []string
	prof.Keep = func(method, path, id string) bool {
		seen = append(seen, method+" "+path+" "+id)
		return id == "a"
	}
	d, err := openapidoc.Distill([]byte(`{"paths":{"/a":{"get":{"operationId":"a"}},"/b":{"post":{"operationId":"b"}},
	"/c":{"get":{}}}}`), prof)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Ops) != 1 || d.Ops["a"].Path != "/a" {
		t.Errorf("ops = %+v", d.Ops)
	}
	slices.Sort(seen)
	if strings.Join(seen, ";") != "GET /a a;POST /b b" {
		t.Errorf("Keep saw %q", seen)
	}
	prof.Keep = func(string, string, string) bool { return false }
	if _, err = openapidoc.Distill([]byte(`{"paths":{"/a":{"get":{"operationId":"a"}}}}`), prof); !errors.Is(
		err, openapidoc.ErrDocsRejected) {
		t.Errorf("nothing kept: err = %v", err)
	}
}

func TestDistill_SkipBodies(t *testing.T) {
	t.Parallel()
	prof := testProfile()
	prof.SkipBodies = true
	d, err := openapidoc.Distill([]byte(`{"paths":{"/a":{
	"post":{"operationId":"create","requestBody":{"required":true,"content":{"application/json":{"schema":
		{"$ref":"#/components/schemas/Thing"}}}}},
	"delete":{"operationId":"remove","requestBody":{"content":{"*/*":{"schema":{"type":"object"}}}}}}},
	"components":{"schemas":{"Thing":{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}}}}`),
		prof)
	if err != nil {
		t.Fatal(err)
	}
	if op := d.Ops["create"]; op.BodyRequired || len(op.BodyFields) != 0 || op.BodyGap == "" || op.BodySkipped {
		t.Errorf("required body = %+v", op)
	}
	if op := d.Ops["remove"]; op.BodyRequired || op.BodyGap != "" || !op.BodySkipped {
		t.Errorf("optional body = %+v", op)
	}
	ref := d.Reference(apiref.Query{Operation: "create"}, prof).Reference
	if ref.BodyEncoding != apiref.BodyNone || len(ref.FixedHeaders) != 0 {
		t.Errorf("a skipped body rendered: encoding %q headers %+v", ref.BodyEncoding, ref.FixedHeaders)
	}
}

func TestDistillContext_ChecksBeforeEachPathItem(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := openapidoc.DistillContext(ctx, []byte(`{"paths":{"/a":{"get":{"operationId":"a"}}}}`), testProfile())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if d, derr := openapidoc.DistillContext(t.Context(), []byte(`{"paths":{"/a":{"get":{"operationId":"a"}}}}`),
		testProfile()); derr != nil || len(d.Ops) != 1 {
		t.Fatalf("live context: %v %v", d, derr)
	}
}

func TestDistill_MaxTextBytes(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x ", 10_000)
	doc := `{"paths":{"/a":{"post":{"operationId":"a","summary":"` + long + `","parameters":[{"name":"q","in":"query",
	"description":"` + long + `"}],"requestBody":{"required":true,"content":{"application/json":{"schema":{
	"type":"object","required":["f"],"properties":{"f":{"type":"string","description":"` + long + `"}}}}}}}}}}`
	prof := testProfile()
	prof.MaxTextBytes = 16
	d, err := openapidoc.Distill([]byte(doc), prof)
	if err != nil {
		t.Fatal(err)
	}
	op := d.Ops["a"]
	if op.Summary != "x x x x x x x x..." || op.Params[0].Description != "x x x x x x x x..." ||
		op.BodyFields[0].Description != "x x x x x x x x..." {
		t.Errorf("cut text: summary %q param %q field %q", op.Summary, op.Params[0].Description,
			op.BodyFields[0].Description)
	}
	d, err = openapidoc.Distill([]byte(doc), testProfile())
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Ops["a"].Summary; len([]rune(got)) != apiref.MaxSummary || !strings.HasSuffix(got, "x...") {
		t.Errorf("uncut summary %q", got)
	}
}
