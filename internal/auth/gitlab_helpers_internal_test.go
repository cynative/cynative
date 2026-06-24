package auth

import (
	"slices"
	"testing"
)

func TestGitlabEnvToken(t *testing.T) {
	t.Parallel()
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	cases := []struct {
		name string
		m    map[string]string
		want string
	}{
		{"gitlab_token wins", map[string]string{"GITLAB_TOKEN": "a", "OAUTH_TOKEN": "b"}, "a"},
		{"access_token fallback", map[string]string{"GITLAB_ACCESS_TOKEN": "b"}, "b"},
		{"oauth fallback", map[string]string{"OAUTH_TOKEN": "c"}, "c"},
		{"empty value skipped", map[string]string{"GITLAB_TOKEN": "", "GITLAB_ACCESS_TOKEN": "d"}, "d"},
		{"none set", map[string]string{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := gitlabEnvToken(env(c.m)); got != c.want {
				t.Fatalf("gitlabEnvToken(%q) = %q, want %q", c.name, got, c.want)
			}
		})
	}
}

func TestResolveGitLabHost(t *testing.T) {
	t.Parallel()
	if got := resolveGitLabHost(""); got != "gitlab.com" {
		t.Fatalf("resolveGitLabHost(empty) = %q, want gitlab.com", got)
	}
	if got := resolveGitLabHost("gitlab.example.com"); got != "gitlab.example.com" {
		t.Fatalf("resolveGitLabHost = %q", got)
	}
}

func TestGlabConfigPaths(t *testing.T) {
	t.Parallel()
	// GLAB_CONFIG_DIR is an exclusive override — no fallthrough to home/XDG/user-config.
	if got := glabConfigPaths("/gd", "/xdg", "/uc", "/home/u"); !slices.Equal(got,
		[]string{"/gd/config.yml"}) {
		t.Fatalf("override: %v", got)
	}
	// Legacy ~/.config precedes XDG precedes os.UserConfigDir().
	if got := glabConfigPaths("", "/xdg", "/uc", "/home/u"); !slices.Equal(got,
		[]string{
			"/home/u/.config/glab-cli/config.yml",
			"/xdg/glab-cli/config.yml",
			"/uc/glab-cli/config.yml",
		}) {
		t.Fatalf("home before xdg before user-config: %v", got)
	}
	// macOS-style: XDG_CONFIG_HOME unset, os.UserConfigDir() = ~/Library/Application Support.
	if got := glabConfigPaths("", "", "/home/u/Library/Application Support", "/home/u"); !slices.Equal(got,
		[]string{
			"/home/u/.config/glab-cli/config.yml",
			"/home/u/Library/Application Support/glab-cli/config.yml",
		}) {
		t.Fatalf("macOS user-config candidate: %v", got)
	}
	if got := glabConfigPaths("", "", "", "/home/u"); !slices.Equal(got,
		[]string{"/home/u/.config/glab-cli/config.yml"}) {
		t.Fatalf("home only: %v", got)
	}
	if got := glabConfigPaths("", "", "", ""); len(got) != 0 {
		t.Fatalf("none set: %v", got)
	}
}

func TestGitlabTokenHosts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		configHost string
		apiHost    string
		servedHost string
		want       []string
	}{
		{"plain gitlab.com", "gitlab.com", "", "gitlab.com", []string{"gitlab.com"}},
		// api_host-only (host defaulted to gitlab.com): the default must be dropped
		// so the gitlab.com token is never sent to the self-managed api_host.
		{
			"api_host only drops default",
			"gitlab.com", "gitlab.internal", "gitlab.internal",
			[]string{"gitlab.internal"},
		},
		{"explicit host dedup", "gitlab.example.com", "", "gitlab.example.com", []string{"gitlab.example.com"}},
		{
			"explicit host with served port",
			"gitlab.example.com", "gitlab.example.com:3443", "gitlab.example.com:3443",
			[]string{"gitlab.example.com"},
		},
		{
			"explicit login + api host kept",
			"login.example.com", "api.example.com", "api.example.com",
			[]string{"login.example.com", "api.example.com"},
		},
		{
			"config host port stripped",
			"gitlab.example.com:3443", "", "gitlab.example.com:3443",
			[]string{"gitlab.example.com"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := gitlabTokenHosts(c.configHost, c.apiHost, c.servedHost); !slices.Equal(got, c.want) {
				t.Fatalf("gitlabTokenHosts(%q,%q,%q) = %v, want %v", c.configHost, c.apiHost, c.servedHost, got, c.want)
			}
		})
	}
}

func TestParseGitLabUser(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{"valid", `{"id":7,"username":"alice","name":"Alice"}`, "alice", false},
		{"no username field", `{"id":7,"name":"Alice"}`, "", true},
		{"empty username", `{"username":""}`, "", true},
		{"invalid json", `{bad`, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseGitLabUser([]byte(c.raw))
			if c.wantErr {
				if err == nil {
					t.Fatalf("parseGitLabUser(%q) want err", c.raw)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("parseGitLabUser(%q) = %q, %v; want %q", c.raw, got, err, c.want)
			}
		})
	}
}

func TestGitlabIdentity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, username, served, want string
	}{
		{"gitlab.com", "alice", "gitlab.com", "@alice"},
		{"self-managed adds host", "alice", "gitlab.internal:8443", "@alice · gitlab.internal:8443"},
		{"empty username falls back to host", "", "gitlab.internal", "gitlab.internal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := gitlabIdentity(c.username, c.served); got != c.want {
				t.Fatalf("gitlabIdentity(%q,%q) = %q, want %q", c.username, c.served, got, c.want)
			}
		})
	}
}
