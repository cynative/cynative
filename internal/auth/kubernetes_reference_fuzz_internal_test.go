package auth

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
	k8sauthz "github.com/cynative/cynative/internal/auth/k8s"
)

// FuzzKubernetesLookupURL pins the URL property: for every model and hash a lookup accepts, on every authority a
// kubeconfig can name, the URL the reader sends is exactly "https://" + authority + "/openapi/v3/" + key plus the
// optional "?hash=" + hash, compared as a raw string, and it parses back to that host and that escaped path.
func FuzzKubernetesLookupURL(f *testing.F) {
	for _, s := range [][3]string{
		{"10.0.0.1:6443", "v1", refHash},
		{"10.0.0.1", "apps/v1", ""},
		{"[2001:db8::1]:6443", "metrics.k8s.io/v1beta1", refHash},
		{"[2001:db8::1]", "v1", ""},
		{"k8s.example:8443", "a-b.c/v2alpha1", refHash},
		{"K8S.example", "core/v1", refHash[:127]},
		{"k8s.example:", "x/" + "v1", "zz"},
		{"k8s.example:0443", "v1", refHash},
		{"user@k8s.example", "v1", ""},
		{"k8s.example", "Apps/v1", ""},
		{"k8s.example", "apps/v1/x", ""},
		{"k8s.example", "", refHash},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, authority, model, hash string) {
		u, err := url.Parse("https://" + authority)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
			AdmitHost(u.Hostname()) != nil || validClusterPort(u.Port()) != nil {
			return
		}
		target := clusterTargetOf(u)
		p := newKubernetesProvider(resolvedCluster{host: target.host, authority: target.authority, port: target.port})
		l, err := p.PrepareLookup(apiref.Query{Model: model, Operation: "a"}, json.RawMessage(`{}`))
		if err != nil {
			return
		}
		v, _ := k8sauthz.ParseAPIVersion(model)
		path := "/openapi/v3/" + v.Key
		query := ""
		if k8sauthz.ValidHash(hash) {
			query = "hash=" + hash
			path += "?" + query
		}
		tgt, _ := l.Resolve(t.Context())
		if !l.Admit(tgt, MetadataRead{Path: path}) {
			t.Fatalf("the lookup refused its own read %q", path)
		}
		raw := tgt.Endpoint + path
		if raw != "https://"+target.authority+path {
			t.Fatalf("URL %q, want %q", raw, "https://"+target.authority+path)
		}
		got, err := url.Parse(raw)
		if err != nil || got.Host != target.authority || got.EscapedPath() != "/openapi/v3/"+v.Key ||
			got.RawQuery != query {
			t.Fatalf(
				"URL %q parses as host %q path %q query %q (%v)",
				raw,
				got.Host,
				got.EscapedPath(),
				got.RawQuery,
				err,
			)
		}
	})
}
