package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// serverNameStub implements Provider + ServerNameProvider for the dispatcher test.
type serverNameStub struct {
	name string
	sni  string
	err  error
}

func (s *serverNameStub) Name() string { return s.name }

func (s *serverNameStub) Description() string { return "stub" }
func (s *serverNameStub) InjectAuth(*http.Request, json.RawMessage) error {
	return nil
}

func (s *serverNameStub) AuthorizesHost(context.Context, string, json.RawMessage) (bool, error) {
	return true, nil
}

func (s *serverNameStub) ServerNameData(context.Context, json.RawMessage) (string, error) {
	return s.sni, s.err
}

// plainStub implements only Provider (no ServerNameProvider), to exercise the
// "provider doesn't implement the interface" branch of GetServerNameData.
type plainStub struct{ name string }

func (s *plainStub) Name() string { return s.name }

func (s *plainStub) Description() string { return "plain" }
func (s *plainStub) InjectAuth(*http.Request, json.RawMessage) error {
	return nil
}

func (s *plainStub) AuthorizesHost(context.Context, string, json.RawMessage) (bool, error) {
	return true, nil
}

func TestGetServerNameData(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	provs := []Provider{&serverNameStub{name: "k", sni: "api.internal"}, &plainStub{name: "failing"}}

	t.Run("empty name yields empty", func(t *testing.T) {
		t.Parallel()

		got, err := GetServerNameData(ctx, "", provs, nil)
		if err != nil || got != "" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("provider implementing returns its name", func(t *testing.T) {
		t.Parallel()

		got, err := GetServerNameData(ctx, "k", provs, nil)
		if err != nil || got != "api.internal" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("provider not implementing yields empty", func(t *testing.T) {
		t.Parallel()

		got, err := GetServerNameData(ctx, "failing", provs, nil)
		if err != nil || got != "" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("unknown provider errors", func(t *testing.T) {
		t.Parallel()

		if _, err := GetServerNameData(ctx, "nope", provs, nil); err == nil {
			t.Fatal("unknown provider must error")
		}
	})

	t.Run("provider error propagates", func(t *testing.T) {
		t.Parallel()

		bad := []Provider{&serverNameStub{name: "k", err: errors.New("boom")}}
		if _, err := GetServerNameData(ctx, "k", bad, nil); err == nil {
			t.Fatal("provider error must propagate")
		}
	})
}
