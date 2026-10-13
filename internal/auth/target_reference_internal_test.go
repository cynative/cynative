package auth

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authtest"
)

type fakeTargetDocumenter struct{ authtest.FailingProvider }

func (*fakeTargetDocumenter) PrepareLookup(apiref.Query, json.RawMessage) (TargetLookup, error) {
	return nil, errors.New("unused")
}

func TestTargetDocumenterFor(t *testing.T) {
	t.Parallel()
	plain := &authtest.FailingProvider{}
	td := &fakeTargetDocumenter{}
	if _, _, err := TargetDocumenterFor(nil, "failing"); !errors.Is(err, ErrUnknownProvider) {
		t.Errorf("not configured: err = %v", err)
	}
	if p, got, err := TargetDocumenterFor([]Provider{plain}, "FAILING"); err != nil || p != plain || got != nil {
		t.Errorf("plain provider: %v %v %v", p, got, err)
	}
	if p, got, err := TargetDocumenterFor([]Provider{td}, "failing"); err != nil || p != td || got != td {
		t.Errorf("target documenter: %v %v %v", p, got, err)
	}
}
