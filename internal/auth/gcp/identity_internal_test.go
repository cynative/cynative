package gcp

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestQuotaProjectIDFromJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"authorized_user with quota", `{"type":"authorized_user","quota_project_id":"cynative"}`, "cynative"},
		{"no quota field", `{"type":"service_account","project_id":"x"}`, ""},
		{"empty input", ``, ""},
		{"malformed json", `{not json`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := quotaProjectIDFromJSON([]byte(tc.in)); got != tc.want {
				t.Errorf("quotaProjectIDFromJSON(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCredTypeFromJSON(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, in, want string }{
		{"empty", ``, ""},
		{"malformed", `{not json`, ""},
		{"service_account", `{"type":"service_account"}`, "service_account"},
		{"authorized_user", `{"type":"authorized_user"}`, "authorized_user"},
		{"external_account", `{"type":"external_account"}`, "external_account"},
		{"no type field", `{"project_id":"x"}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := credTypeFromJSON([]byte(tc.in)); got != tc.want {
				t.Errorf("credTypeFromJSON(%q)=%q want %q", tc.in, got, tc.want)
			}
		})
	}
}

type fakeMetadata struct {
	onGCE     bool
	email     string
	emailErr  error
	projectID string
	projErr   error
	projCalls int
}

func (f *fakeMetadata) OnGCE() bool { return f.onGCE }

func (f *fakeMetadata) Email(_ context.Context) (string, error) { return f.email, f.emailErr }

func (f *fakeMetadata) ProjectID(_ context.Context) (string, error) {
	f.projCalls++
	return f.projectID, f.projErr
}

func TestResolveIdentity(t *testing.T) { //nolint:gocognit // test function with many subtests by design.
	t.Parallel()
	tokErr := errors.New("tok boom")
	const saJSON = `{"type":"service_account"}`
	const quotaJSON = `{"type":"authorized_user","quota_project_id":"qproj"}`

	t.Run("non-metadata cred uses tokeninfo even when OnGCE", func(t *testing.T) {
		t.Parallel()
		md := &fakeMetadata{onGCE: true}
		p, proj, err := resolveIdentity(context.Background(),
			credFacts{credJSON: []byte(saJSON), projectID: "p1"}, md,
			func(context.Context) (string, error) { return "sa@x", nil })
		if err != nil || p != "sa@x" || proj != "p1" {
			t.Fatalf("got (%q,%q,%v)", p, proj, err)
		}
		if md.projCalls != 0 {
			t.Error("ProjectID must not be called on the non-metadata path")
		}
	})

	t.Run("metadata email success, project present", func(t *testing.T) {
		t.Parallel()
		md := &fakeMetadata{onGCE: true, email: "vm@x", projectID: "ignored"}
		p, proj, err := resolveIdentity(context.Background(),
			credFacts{credJSON: nil, projectID: "p2"}, md,
			func(context.Context) (string, error) { return "", errors.New("must not call") })
		if err != nil || p != "vm@x" || proj != "p2" {
			t.Fatalf("got (%q,%q,%v)", p, proj, err)
		}
		if md.projCalls != 0 {
			t.Error("ProjectID must not be called when project already present")
		}
	})

	t.Run("metadata email success, project empty -> ProjectID", func(t *testing.T) {
		t.Parallel()
		md := &fakeMetadata{onGCE: true, email: "vm@x", projectID: "mdproj"}
		p, proj, err := resolveIdentity(context.Background(),
			credFacts{credJSON: nil, projectID: ""}, md,
			func(context.Context) (string, error) { return "", errors.New("must not call") })
		if err != nil || p != "vm@x" || proj != "mdproj" {
			t.Fatalf("got (%q,%q,%v)", p, proj, err)
		}
		if md.projCalls != 1 {
			t.Errorf("ProjectID calls = %d want 1", md.projCalls)
		}
	})

	t.Run("metadata email success, project empty, ProjectID errors -> ignored", func(t *testing.T) {
		t.Parallel()
		md := &fakeMetadata{onGCE: true, email: "vm@x", projErr: errors.New("md boom")}
		p, proj, err := resolveIdentity(context.Background(),
			credFacts{credJSON: nil, projectID: ""}, md,
			func(context.Context) (string, error) { return "", errors.New("must not call") })
		if err != nil || p != "vm@x" || proj != "" {
			t.Fatalf("got (%q,%q,%v) want (vm@x, '', nil)", p, proj, err)
		}
	})

	t.Run("metadata email errors -> tokeninfo", func(t *testing.T) {
		t.Parallel()
		md := &fakeMetadata{onGCE: true, emailErr: errors.New("email boom")}
		p, _, err := resolveIdentity(context.Background(),
			credFacts{credJSON: nil, projectID: "p3"}, md,
			func(context.Context) (string, error) { return "ti@x", nil })
		if err != nil || p != "ti@x" {
			t.Fatalf("got (%q,%v)", p, err)
		}
	})

	t.Run("not on GCE -> tokeninfo", func(t *testing.T) {
		t.Parallel()
		md := &fakeMetadata{onGCE: false}
		p, _, err := resolveIdentity(context.Background(),
			credFacts{credJSON: nil, projectID: "p4"}, md,
			func(context.Context) (string, error) { return "ti@x", nil })
		if err != nil || p != "ti@x" {
			t.Fatalf("got (%q,%v)", p, err)
		}
	})

	t.Run("project fallback to quota_project_id", func(t *testing.T) {
		t.Parallel()
		md := &fakeMetadata{onGCE: false}
		_, proj, err := resolveIdentity(context.Background(),
			credFacts{credJSON: []byte(quotaJSON), projectID: ""}, md,
			func(context.Context) (string, error) { return "u@x", nil })
		if err != nil || proj != "qproj" {
			t.Fatalf("got (%q,%v)", proj, err)
		}
	})

	t.Run("tokeninfo error wraps", func(t *testing.T) {
		t.Parallel()
		md := &fakeMetadata{onGCE: false}
		p, proj, err := resolveIdentity(context.Background(),
			credFacts{credJSON: []byte(saJSON), projectID: "p5"}, md,
			func(context.Context) (string, error) { return "", tokErr })
		if p != "" || proj != "" {
			t.Errorf("want empty principal/project on error, got (%q,%q)", p, proj)
		}
		if !errors.Is(err, tokErr) {
			t.Errorf("err = %v want wrap of tokErr", err)
		}
		if !strings.Contains(err.Error(), "tokeninfo principal probe:") {
			t.Errorf("err = %q want 'tokeninfo principal probe:' prefix", err)
		}
	})
}

func TestPrincipalFromTokeninfo(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		body    string
		status  int
		want    string
		wantErr bool
	}{
		{"non-200", `{}`, http.StatusNotFound, "", true},
		{"email", `{"email":"e@x"}`, http.StatusOK, "e@x", false},
		{"sub only", `{"sub":"123"}`, http.StatusOK, "123", false},
		{"email over sub", `{"email":"e","sub":"s"}`, http.StatusOK, "e", false},
		{"malformed", `{bad`, http.StatusOK, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := principalFromTokeninfo([]byte(tc.body), tc.status)
			if tc.wantErr && err == nil {
				t.Fatal("want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
	t.Run("non-200 status text", func(t *testing.T) {
		t.Parallel()
		_, err := principalFromTokeninfo([]byte(`{}`), 503)
		if err == nil || !strings.Contains(err.Error(), "tokeninfo status 503") {
			t.Errorf("err = %v want 'tokeninfo status 503'", err)
		}
	})
}
