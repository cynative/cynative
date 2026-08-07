package authreq_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/auth/authreq"
)

// block is the decode target for the state-model table: a shape with one field,
// so a present block can be told apart from an absent one by its value.
type block struct {
	Marker string `json:"marker"`
}

// TestNewProviderArgs_Resolved covers the two non-error states, which the
// dispatchers rely on telling apart: a present block decodes, and an absent one
// is (nil, nil) rather than a failure.
func TestNewProviderArgs_Resolved(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		toolCall   string
		provider   string
		wantMarker string // "" means Parse must return a nil value.
	}{
		{name: "present block", toolCall: `{"aws_auth":{"marker":"mine"}}`, provider: "aws", wantMarker: "mine"},
		{name: "mixed-case provider", toolCall: `{"aws_auth":{"marker":"mine"}}`, provider: "AWS", wantMarker: "mine"},
		{name: "key absent", toolCall: `{"method":"GET"}`, provider: "aws"},
		{name: "key explicitly null", toolCall: `{"aws_auth":null}`, provider: "aws"},
		{name: "top-level null", toolCall: `null`, provider: "aws"},
		{name: "empty object", toolCall: `{}`, provider: "aws"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := authreq.Parse[block](authreq.NewProviderArgs(json.RawMessage(tc.toolCall), tc.provider))
			if err != nil {
				t.Fatalf("Parse() error = %v, want nil", err)
			}

			switch {
			case tc.wantMarker == "":
				if got != nil {
					t.Errorf("Parse() = %+v, want nil (absent)", *got)
				}
			case got == nil:
				t.Errorf("Parse() = nil, want marker %q", tc.wantMarker)
			case got.Marker != tc.wantMarker:
				t.Errorf("Parse().Marker = %q, want %q", got.Marker, tc.wantMarker)
			}
		})
	}
}

// TestNewProviderArgs_Invalid covers the third state. Each of these would be
// absent args if invalid collapsed into absent, which is what makes a malformed
// tool call look like a normal one to a gate that treats absent as allow.
func TestNewProviderArgs_Invalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		toolCall string
	}{
		{name: "empty input", toolCall: ``},
		{name: "malformed syntax", toolCall: `{`},
		{name: "number top level", toolCall: `5`},
		{name: "array top level", toolCall: `[]`},
		{name: "string top level", toolCall: `"x"`},
		{name: "non-object block", toolCall: `{"aws_auth":"nope"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := authreq.Parse[block](authreq.NewProviderArgs(json.RawMessage(tc.toolCall), "aws"))
			if err == nil {
				t.Fatal("Parse() error = nil, want an error")
			}
			if got != nil {
				t.Errorf("Parse() = %+v with an error, want a nil value", *got)
			}
		})
	}
}

func TestProviderArgs_ZeroValueIsAbsent(t *testing.T) {
	t.Parallel()

	got, err := authreq.Parse[block](authreq.ProviderArgs{})
	if err != nil {
		t.Fatalf("Parse(zero) error = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("Parse(zero) = %+v, want nil", *got)
	}
}

// TestNewProviderArgs_EmptyProviderIsNotAbsent guards the discriminator between
// the zero value and a constructed one. Parse tells them apart by an empty key,
// which works only because the constructor always appends the suffix. A
// nameless provider must therefore still look for its (nonsense) "_auth" block
// and fail closed on a malformed call, never inherit the zero value's "absent
// means allow".
func TestNewProviderArgs_EmptyProviderIsNotAbsent(t *testing.T) {
	t.Parallel()

	if _, err := authreq.Parse[block](authreq.NewProviderArgs(json.RawMessage(`{`), "")); err == nil {
		t.Error("Parse() error = nil, want an error: a nameless provider must not read as absent")
	}

	got, err := authreq.Parse[block](authreq.NewProviderArgs(json.RawMessage(`{"_auth":{"marker":"x"}}`), ""))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if got == nil || got.Marker != "x" {
		t.Errorf("Parse() = %v, want the \"_auth\" block: the suffix is appended unconditionally", got)
	}
}

func TestNewProviderArgs_SiblingBlindness(t *testing.T) {
	t.Parallel()

	call := json.RawMessage(`{"aws_auth":{"marker":"aws"},"gcp_auth":{"marker":"gcp"}}`)

	got, err := authreq.Parse[block](authreq.NewProviderArgs(call, "gcp"))
	if err != nil {
		t.Fatalf("Parse() error = %v, want nil", err)
	}
	if got == nil {
		t.Fatal("Parse() = nil, want the gcp block")
	}
	if got.Marker != "gcp" {
		t.Errorf("Parse().Marker = %q, want %q: the gate saw a sibling provider's block", got.Marker, "gcp")
	}
}

func TestParse_ErrorNamesTheKey(t *testing.T) {
	t.Parallel()

	_, err := authreq.Parse[block](authreq.NewProviderArgs(json.RawMessage(`{`), "eks"))
	if err == nil {
		t.Fatal("Parse() error = nil, want an error")
	}
	if !strings.Contains(err.Error(), "eks_auth") {
		t.Errorf("Parse() error = %q, want it to name eks_auth", err)
	}

	if _, ok := errors.AsType[*json.SyntaxError](err); !ok {
		t.Errorf("Parse() error = %q, want the json error wrapped with %%w", err)
	}
}
