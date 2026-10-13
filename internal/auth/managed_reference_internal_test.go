package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/aws/aws-sdk-go-v2/aws"
	"golang.org/x/oauth2"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
)

const (
	eksHost = "abc.gr7.us-east-1.eks.amazonaws.com"
	gkeHost = "34.120.0.10"
	aksHost = "my-cluster-dns.hcp.eastus.azmk8s.io"
)

// eksAt is an eks provider in us-east-1 whose DescribeCluster answers host, or err.
func eksAt(host string, err error) *eksProvider {
	p := newEKSProvider(aws.Config{Region: "us-east-1"})
	p.describeCluster = func(context.Context, aws.Config, string) (clusterTLS, error) {
		return clusterTLS{host: host, caData: "Y2E="}, err
	}

	return p
}

// gkeAt is a gke provider whose clusters.get answers host, or err.
func gkeAt(host string, err error) *gkeProvider {
	p := newGKEProvider(mockTokenSource(&oauth2.Token{}, nil))
	p.getCluster = func(context.Context, oauth2.TokenSource, string, string, string) (clusterTLS, error) {
		return clusterTLS{host: host, caData: "Y2E="}, err
	}

	return p
}

// aksAt is an aks provider whose ListClusterUserCredentials answers a token kubeconfig naming server.
func aksAt(t *testing.T, server string) *aksProvider {
	t.Helper()
	kubeconfig := strings.Replace(fakeKubeconfigToken(), "https://my-cluster-dns.hcp.eastus.azmk8s.io:443", server, 1)
	value := base64.StdEncoding.EncodeToString([]byte(kubeconfig))
	srv := aksARMMock(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"kubeconfigs":[{"name":"clusterUser","value":"%s"}]}`, value)
	})
	p := newAKSProvider(mockCredential(azcore.AccessToken{}, nil), cloud.Configuration{})
	p.newClient = aksClientFor(srv.URL, srv.Client())

	return p
}

const (
	eksBlock = `{"cluster_name":"c1"}`
	gkeBlock = `{"cluster_name":"c1","location":"us-central1-f","project":"proj-1"}`
	aksBlock = `{"cluster_name":"c1","resource_group":"rg","subscription_id":"` + bootSub + `"}`
)

func nsQuery() apiref.Query { return apiref.Query{Model: "v1", Operation: "listCoreV1Namespace"} }

// TestManagedPrepareLookup_Validation pins each managed connector's preparation: the canonical block of a valid
// one, the gate's own validate on every field, a block that does not decode, and a service.
func TestManagedPrepareLookup_Validation(t *testing.T) {
	t.Parallel()
	eks, gke, aks := eksAt(eksHost, nil), gkeAt(gkeHost, nil), aksAt(t, "https://"+aksHost)
	for _, tc := range []struct {
		name  string
		td    TargetDocumenter
		block string
		q     apiref.Query
		want  string // the canonical block, the error's text, or with a trailing "*" its prefix
		isErr error
	}{
		{"eks valid", eks, `{"Cluster_Name":"c1"}`, nsQuery(), eksBlock, nil},
		{
			"eks valid with a region", eks, `{"cluster_name":"c1","region":"us-east-2"}`, nsQuery(),
			`{"cluster_name":"c1","region":"us-east-2"}`, nil,
		},
		{"eks no cluster", eks, `{}`, nsQuery(), "eks_auth.cluster_name is required for action authorization", nil},
		{"eks cluster grammar", eks, `{"cluster_name":"a/b"}`, nsQuery(), "", ErrInvalidClusterIdentifier},
		{
			"eks region grammar", eks, `{"cluster_name":"c1","region":"us-east-1.x"}`, nsQuery(), "",
			ErrInvalidClusterIdentifier,
		},
		{
			"eks another partition", eks, `{"cluster_name":"c1","region":"cn-north-1"}`, nsQuery(), "",
			ErrInvalidClusterIdentifier,
		},
		{"eks undecodable", eks, `{"cluster_name":5}`, nsQuery(), errEKSBlock.Error(), nil},
		{
			"eks service", eks, eksBlock,
			apiref.Query{Service: "x", Model: "v1", Operation: "a"},
			`service must be empty for eks: the group goes in model, as in "apps/v1"`, nil,
		},
		{
			"gke valid", gke, `{"project":"proj-1","location":"us-central1-f","cluster_name":"c1"}`, nsQuery(), gkeBlock,
			nil,
		},
		{
			"gke missing", gke, `{"project":"proj-1","location":"us-central1-f"}`, nsQuery(),
			"gke_auth.cluster_name, location, and project are required for action authorization", nil,
		},
		{
			"gke project grammar", gke, `{"project":"P","location":"us-central1-f","cluster_name":"c1"}`, nsQuery(), "",
			ErrInvalidClusterIdentifier,
		},
		{
			"gke location grammar", gke, `{"project":"proj-1","location":"us/1","cluster_name":"c1"}`, nsQuery(), "",
			ErrInvalidClusterIdentifier,
		},
		{
			"gke cluster grammar", gke, `{"project":"proj-1","location":"us-central1-f","cluster_name":"c:1"}`, nsQuery(),
			"", ErrInvalidClusterIdentifier,
		},
		{"gke undecodable", gke, `[]`, nsQuery(), errGKEBlock.Error(), nil},
		{
			"gke model", gke, gkeBlock,
			apiref.Query{Model: " v1", Operation: "a"},
			"gke: model must be an apiVersion*",
			nil,
		},
		{
			"aks valid", aks, `{"subscription_id":"` + bootSub + `","resource_group":"rg","cluster_name":"c1"}`,
			nsQuery(), aksBlock, nil,
		},
		{
			"aks missing", aks, `{"cluster_name":"c1"}`, nsQuery(),
			"cluster_name, resource_group, and subscription_id are required", nil,
		},
		{
			"aks subscription grammar", aks, `{"subscription_id":"x","resource_group":"rg","cluster_name":"c1"}`,
			nsQuery(), "", ErrInvalidClusterIdentifier,
		},
		{
			"aks group grammar", aks, `{"subscription_id":"` + bootSub + `","resource_group":"r/g","cluster_name":"c1"}`,
			nsQuery(), "", ErrInvalidClusterIdentifier,
		},
		{
			"aks cluster grammar", aks, `{"subscription_id":"` + bootSub + `","resource_group":"rg","cluster_name":"-c"}`,
			nsQuery(), "", ErrInvalidClusterIdentifier,
		},
		{"aks undecodable", aks, `"x"`, nsQuery(), errAKSBlock.Error(), nil},
		{
			"aks operation", aks, aksBlock,
			apiref.Query{Model: "v1", Operation: "list pods"},
			errKubeOperation.Error(),
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, err := tc.td.PrepareLookup(tc.q, json.RawMessage(tc.block))
			prefix, isPrefix := strings.CutSuffix(tc.want, "*")
			if got := preparedAs(l, err, tc.isErr); got != tc.want && (!isPrefix || !strings.HasPrefix(got, prefix)) {
				t.Errorf("PrepareLookup = %q, want %q", got, tc.want)
			}
		})
	}
}

// preparedAs is what a preparation gave: the canonical block, "" for an error that is isErr, or the error's text.
func preparedAs(l TargetLookup, err, isErr error) string {
	switch {
	case err == nil:
		return string(l.Block())
	case isErr != nil && errors.Is(err, isErr):
		return ""
	default:
		return err.Error()
	}
}

// parityCase is one raw block and the canonical block it must give.
type parityCase struct{ raw, canonical string }

// checkBlockParity is P1 for one connector: the struct the gate's validate saw, the canonical block every read
// carries, and the struct the gate's own authreq.Parse decodes from that block are the same.
func checkBlockParity[A comparable](
	t *testing.T, name string, g *k8sGate[A], td TargetDocumenter, cases []parityCase,
) {
	t.Helper()
	inner := g.validate
	var seen []A
	g.validate = func(a *A) error {
		seen = append(seen, *a)

		return inner(a)
	}
	for _, c := range cases {
		seen = seen[:0]
		l, err := td.PrepareLookup(nsQuery(), json.RawMessage(c.raw))
		if err != nil || len(seen) != 1 {
			t.Fatalf("%s %s: %v after %d validations", name, c.raw, err, len(seen))
		}
		block := l.Block()
		parsed, err := authreq.Parse[A](authreq.NewProviderArgs(
			json.RawMessage(`{"`+name+`_auth":`+string(block)+`}`), name))
		if err != nil || string(block) != c.canonical || *parsed != seen[0] {
			t.Errorf("%s %s: canonical %s (want %s), parsed %+v, validated %+v, %v", name, c.raw, block,
				c.canonical, parsed, seen[0], err)
		}
	}
}

// TestManagedPrepareLookup_BlockParity is P1 for the three managed connectors over case-variant, duplicate and
// unknown keys.
func TestManagedPrepareLookup_BlockParity(t *testing.T) {
	t.Parallel()
	eks := eksAt(eksHost, nil)
	checkBlockParity(t, "eks", &eks.k8sGate, eks, []parityCase{
		{`{"Cluster_Name":"c1"}`, eksBlock},
		{`{"cluster_name":"x","cluster_name":"c1"}`, eksBlock},
		{`{"CLUSTER_NAME":"x","cluster_name":"c1"}`, eksBlock},
		{`{"cluster_name":"c1","REGION":"us-east-2","zone":"z"}`, `{"cluster_name":"c1","region":"us-east-2"}`},
	})
	gke := gkeAt(gkeHost, nil)
	checkBlockParity(t, "gke", &gke.k8sGate, gke, []parityCase{
		{`{"PROJECT":"proj-1","Location":"us-central1-f","cluster_NAME":"c1"}`, gkeBlock},
		{`{"project":"proj-2","project":"proj-1","location":"us-central1-f","cluster_name":"c1","x":1}`, gkeBlock},
	})
	aks := aksAt(t, "https://"+aksHost)
	checkBlockParity(t, "aks", &aks.k8sGate, aks, []parityCase{
		{`{"Subscription_ID":"` + bootSub + `","RESOURCE_GROUP":"rg","cluster_name":"c1"}`, aksBlock},
		{`{"subscription_id":"` + bootSub + `","resource_group":"other","resource_group":"rg","cluster_name":"c1",` +
			`"location":"eastus"}`, aksBlock},
	})
}

// managedCase is one connector's resolution, for the tests that resolve all three.
type managedCase struct {
	name     string
	td       TargetDocumenter
	block    string
	identity string
	host     string
	pins     func(ctx context.Context, v authreq.View, args authreq.ProviderArgs) error
}

func managedCases(t *testing.T) []managedCase {
	t.Helper()
	eks, gke, aks := eksAt(eksHost, nil), gkeAt(gkeHost, nil), aksAt(t, "https://"+aksHost+":443")
	pins := func(ah func(context.Context, string, authreq.ProviderArgs) (bool, error), port string) func(
		context.Context, authreq.View, authreq.ProviderArgs,
	) error {
		return func(ctx context.Context, v authreq.View, args authreq.ProviderArgs) error {
			ok, err := ah(ctx, v.Hostname, args)
			if err != nil || !ok {
				return fmt.Errorf("AuthorizesHost(%q) = %v, %w", v.Hostname, ok, err)
			}

			return authorizeRequestPort(v, port)
		}
	}

	return []managedCase{
		{"eks", eks, eksBlock, "eks/us-east-1/c1@" + eksHost, eksHost, pins(eks.AuthorizesHost, eks.expectedPort)},
		{"gke", gke, gkeBlock, "gke/proj-1/us-central1-f/c1@" + gkeHost, gkeHost, pins(gke.AuthorizesHost,
			gke.expectedPort)},
		{"aks", aks, aksBlock, "aks/" + bootSub + "/rg/c1@" + aksHost, aksHost, pins(aks.AuthorizesHost,
			aks.expectedPort)},
	}
}

// TestManagedLookup_PublishesWhatTheGateAdmits is P2: the endpoint a lookup resolves carries no port, its
// identity names the cluster and the host, and a request built from it passes the connector's own host gate and
// port pin with the same block.
func TestManagedLookup_PublishesWhatTheGateAdmits(t *testing.T) {
	t.Parallel()
	for _, tc := range managedCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, err := tc.td.PrepareLookup(nsQuery(), json.RawMessage(tc.block))
			if err != nil {
				t.Fatal(err)
			}
			tgt, err := l.Resolve(t.Context())
			if err != nil || tgt != (Target{Endpoint: "https://" + tc.host, Identity: tc.identity}) {
				t.Fatalf("Resolve = %+v, %v", tgt, err)
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tgt.Endpoint+kubeRootPath, nil)
			if err != nil {
				t.Fatal(err)
			}
			args := authreq.NewProviderArgs(json.RawMessage(`{"`+tc.name+`_auth":`+string(l.Block())+`}`), tc.name)
			if err = tc.pins(t.Context(), authreq.NewView(req, ""), args); err != nil {
				t.Errorf("the published endpoint is not what the gate admits: %v", err)
			}
		})
	}
}

// TestManagedLookup_ResolveRefusals pins what Resolve refuses for each connector before it publishes anything: a
// resolution error, an empty host, a host AdmitHost refuses, and an IPv6 literal, which the managed gates' own
// ClusterRole fetch cannot address either.
func TestManagedLookup_ResolveRefusals(t *testing.T) {
	t.Parallel()
	errMissing := errors.New("cluster not found")
	for _, tc := range []struct {
		name  string
		td    TargetDocumenter
		block string
		want  error
	}{
		{"eks resolution error", eksAt(eksHost, errMissing), eksBlock, errMissing},
		{"eks empty host", eksAt("", nil), eksBlock, errNoClusterHost},
		{"eks non-ASCII host", eksAt("kübe.example", nil), eksBlock, ErrNonASCIIHost},
		{"eks IPv6 host", eksAt("2001:db8::1", nil), eksBlock, errIPv6ClusterHost},
		{"gke resolution error", gkeAt(gkeHost, errMissing), gkeBlock, errMissing},
		{"gke empty host", gkeAt("", nil), gkeBlock, errNoClusterHost},
		{"gke zoned host", gkeAt("fe80::1%eth0", nil), gkeBlock, ErrZonedHost},
		{"aks empty host", aksAt(t, "https://:443"), aksBlock, errNoClusterHost},
		{"aks non-ASCII host", aksAt(t, "https://kübe.example"), aksBlock, ErrNonASCIIHost},
		{"aks IPv6 host", aksAt(t, "https://[2001:db8::1]:443"), aksBlock, errIPv6ClusterHost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, err := tc.td.PrepareLookup(nsQuery(), json.RawMessage(tc.block))
			if err != nil {
				t.Fatal(err)
			}
			if tgt, rerr := l.Resolve(t.Context()); !errors.Is(rerr, tc.want) || tgt != (Target{}) {
				t.Errorf("Resolve = %+v, %v; want %v", tgt, rerr, tc.want)
			}
		})
	}
}

// TestManagedLookup_AnswersOverTheSharedRecipe runs an eks lookup end to end over the recipe kubernetes uses: the
// reads carry no block of their own, so they carry the canonical one, and the reference names the connector, its
// block, the endpoint with no port, the cluster identity and the configured ClusterRole.
func TestManagedLookup_AnswersOverTheSharedRecipe(t *testing.T) {
	t.Parallel()
	p := eksAt(eksHost, nil)
	p.clusterRole = "reader"
	l, err := p.PrepareLookup(apiref.Query{Model: "metrics.k8s.io/v1beta1", Operation: listOp},
		json.RawMessage(`{"cluster_name":"c1","region":"us-east-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	tgt, err := l.Resolve(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rd := &scriptReader{t: t, script: map[string][]scripted{
		"/openapi/v3":                 {ok(hashedRoot(refHash))},
		metricsP + "?hash=" + refHash: {ok(metricsDoc(t))},
		"/version":                    {ok(versionBody)},
	}}
	res := l.Answer(t.Context(), tgt, rd)
	if res.Outcome != apiref.OutcomeFound {
		t.Fatalf("answer: %+v", res)
	}
	ref := res.Reference
	wantArgs := map[string]string{"cluster_name": "c1", "region": "us-east-1"}
	if ref.Connector != "eks" || ref.AuthField != "eks_auth" || !maps.Equal(ref.AuthArgs, wantArgs) ||
		ref.Endpoint != "https://"+eksHost || ref.Source.Target != "eks/us-east-1/c1@"+eksHost ||
		!slices.Contains(ref.Limitations, fmt.Sprintf(limitPermissionText, "reader")) {
		t.Errorf("reference %+v", ref)
	}
	for _, r := range rd.reads {
		if r.Block != nil {
			t.Errorf("read %s carries its own block %s", r.Path, r.Block)
		}
	}
	if string(l.Block()) != `{"cluster_name":"c1","region":"us-east-1"}` {
		t.Errorf("block %s", l.Block())
	}
}

// limitPermissionText is the k8s package's permission limitation, as a reference shows it.
const limitPermissionText = "a description, not a permission: the gate allows only what the configured " +
	"ClusterRole %q permits"

// TestKubernetesLookup_ReferenceNamesNoBlock pins that a kubernetes reference stays as it was: its block has no
// fields, so the template gains no kubernetes_auth.
func TestKubernetesLookup_ReferenceNamesNoBlock(t *testing.T) {
	t.Parallel()
	rd := &scriptReader{t: t, script: map[string][]scripted{
		"/openapi/v3":                 {ok(hashedRoot(refHash))},
		metricsP + "?hash=" + refHash: {ok(metricsDoc(t))},
		"/version":                    {ok(versionBody)},
	}}
	res := runLookup(t.Context(), t, refProvider(), rd, listOp)
	if res.Outcome != apiref.OutcomeFound || res.Reference.Connector != "kubernetes" ||
		res.Reference.AuthField != "" || res.Reference.AuthArgs != nil {
		t.Errorf("reference %+v", res.Reference)
	}
}

// TestManagedProviders_AreTargetDocumentersAndPointAtTheLookup pins that the routing finds each managed connector's
// TargetDocumenter, and that each description names the lookup with the connector's own block.
func TestManagedProviders_AreTargetDocumentersAndPointAtTheLookup(t *testing.T) {
	t.Parallel()
	providers := []Provider{
		newEKSProvider(aws.Config{}), newGKEProvider(mockTokenSource(&oauth2.Token{}, nil)),
		newAKSProvider(mockCredential(azcore.AccessToken{}, nil), cloud.Configuration{}),
	}
	for _, p := range providers {
		if _, td, err := TargetDocumenterFor(providers, p.Name()); err != nil || td == nil {
			t.Errorf("%s: TargetDocumenterFor = %v, %v", p.Name(), td, err)
		}
		want := `call api_reference with connector "` + p.Name() + `", the same ` + p.Name() + `_auth, model set to ` +
			`the apiVersion and the operationId.`
		if !strings.Contains(p.Description(), want) {
			t.Errorf("%s description %q lacks %q", p.Name(), p.Description(), want)
		}
	}
}
