package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
	azurehardening "github.com/cynative/cynative/internal/auth/azure"
	"github.com/cynative/cynative/internal/cache"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAzureProviderIsAnOperationDocumenter(t *testing.T) {
	t.Parallel()
	var p Provider = newAzureProvider(fakeAzureCatalog{}, "scope", nil)
	if _, ok := p.(OperationDocumenter); !ok {
		t.Fatal("azureProvider does not implement OperationDocumenter")
	}
}

func TestAzureReferenceWithoutDocsIsUnavailable(t *testing.T) {
	t.Parallel()
	p := newAzureProvider(fakeAzureCatalog{}, "scope", nil)
	got := p.Reference(
		context.Background(),
		apiref.Query{Connector: "azure", Service: "Microsoft.Compute", Operation: "X_Y"},
	)
	if got.Outcome != apiref.OutcomeUnavailable || got.Reason != "Azure API metadata is not configured" {
		t.Fatalf("Reference = %+v", got)
	}
}

func TestAzureHintIsEmpty(t *testing.T) {
	t.Parallel()
	p := newAzureProvider(fakeAzureCatalog{}, "scope", nil)
	h := p.Hint(context.Background(), authreq.View{}, &authreq.UnmatchedRequestError{})
	if len(h.Candidates) != 0 || h.Operation != "" || h.Note != "" || h.NoReference {
		t.Fatalf("Hint = %+v, want the zero hint", h)
	}
}

// TestNewAzureDocsAnswersWithoutIO builds the docs the shell wires and checks that a lookup the grammar refuses is
// answered before the store, the client or the gate are touched.
func TestNewAzureDocsAnswersWithoutIO(t *testing.T) {
	t.Parallel()
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("the specs client was used")

		return nil, context.Canceled
	})}
	docs := newAzureDocs(cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		"https://management.azure.com", client, func(err error) error { return err },
		func() azurehardening.Catalog {
			t.Error("the gate was peeked")

			return nil
		})
	p := newAzureProvider(fakeAzureCatalog{}, "scope", nil)
	p.docs = docs
	got := p.Reference(
		context.Background(),
		apiref.Query{Connector: "azure", Service: "not a namespace", Operation: "X_Y"},
	)
	if got.Outcome != apiref.OutcomeNotFound {
		t.Fatalf("Reference = %+v, want not_found", got)
	}
}

// TestAzureDeadlineTextMatchesTheTargetedLookups pins the azure package's copy of the deadline text, which cannot
// import this package, to ContextReason.
func TestAzureDeadlineTextMatchesTheTargetedLookups(t *testing.T) {
	t.Parallel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancelExpired()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{expired, canceled} {
		if got, want := azurehardening.ContextReason(ctx), ContextReason(ctx); got != want {
			t.Errorf("azure ContextReason = %q, want %q", got, want)
		}
	}
}

// TestNewAzureDocsScrubsIndexFetchErrors proves that newAzureDocs passes the scrub func to the store and that fetch
// errors are scrubbed. The client fails every request with an error carrying a secret marker; the scrub func replaces
// it with a placeholder; a lookup for a valid namespace attempts the index fetch, which fails and returns the scrubbed
// error.
func TestNewAzureDocsScrubsIndexFetchErrors(t *testing.T) {
	t.Parallel()
	var scrubCalled bool
	scrub := func(err error) error {
		scrubCalled = true
		if err == nil {
			return nil
		}

		return errors.New(strings.ReplaceAll(err.Error(), "hunter2", "[scrubbed]"))
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("fetch failed: hunter2")
	})}
	docs := newAzureDocs(
		cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: time.Now},
		"https://management.azure.com", client, scrub,
		func() azurehardening.Catalog { return nil },
	)
	p := newAzureProvider(fakeAzureCatalog{}, "scope", nil)
	p.docs = docs
	got := p.Reference(
		context.Background(),
		apiref.Query{Connector: "azure", Service: "Microsoft.Compute", Operation: "X_Y"},
	)
	if got.Outcome != apiref.OutcomeUnavailable {
		t.Fatalf("Reference outcome = %s, want unavailable", got.Outcome)
	}
	if !strings.Contains(got.Reason, "[scrubbed]") {
		t.Errorf("Reason = %q, want [scrubbed]", got.Reason)
	}
	if strings.Contains(got.Reason, "hunter2") {
		t.Errorf("Reason = %q, contains hunter2 (not scrubbed)", got.Reason)
	}
	if !scrubCalled {
		t.Error("scrub func was not called")
	}
}
