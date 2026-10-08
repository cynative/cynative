package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"golang.org/x/oauth2"
	"google.golang.org/api/container/v1"
	"google.golang.org/api/option"
)

// captureRT records every request it sees and answers each with one fixed status and body, so a test can read the
// exact URL a pinned SDK builds without any network I/O.
type captureRT struct {
	mu     sync.Mutex
	urls   []*url.URL
	status int
	body   string
}

func (c *captureRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	u := *req.URL
	c.urls = append(c.urls, &u)
	c.mu.Unlock()
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	return &http.Response{
		StatusCode: c.status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Request:    req,
	}, nil
}

func (c *captureRT) seen() []*url.URL {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*url.URL(nil), c.urls...)
}

// staticAzureCredential is an azcore.TokenCredential that always returns one token.
type staticAzureCredential struct{}

func (staticAzureCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "t", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

const testSubscription = "00000000-1111-2222-3333-444444444444"

func TestManagedClusterIdentifierGrammars(t *testing.T) {
	t.Parallel()
	gke := func(p, l, c string) error { return (&GKEAuthArgs{Project: p, Location: l, ClusterName: c}).validate() }
	eks := func(c, r string) error { return (&EKSAuthArgs{ClusterName: c, Region: r}).validate() }
	aks := func(s, g, c string) error {
		return (&AKSAuthArgs{SubscriptionID: s, ResourceGroup: g, ClusterName: c}).validate()
	}
	for _, tc := range []struct {
		name string
		err  error
		ok   bool
	}{
		{"gke regional", gke("my-project", "us-central1", "prod-1"), true},
		{"gke zonal", gke("my-project", "us-central1-a", "c"), true},
		{"gke project number", gke("123456789012", "europe-west10", "c1"), true},
		{"gke slash in cluster", gke("my-project", "us-central1", "c/nodePools"), false},
		{"gke dot segment cluster", gke("my-project", "us-central1", ".."), false},
		{"gke single dot cluster", gke("my-project", "us-central1", "."), false},
		{"gke colon in cluster", gke("my-project", "us-central1", "c:setLocations"), false},
		{"gke uppercase cluster", gke("my-project", "us-central1", "Prod"), false},
		{"gke cluster ends with hyphen", gke("my-project", "us-central1", "prod-"), false},
		{"gke slash in project", gke("p/locations/x", "us-central1", "c"), false},
		{"gke domain-scoped project", gke("example.com:proj", "us-central1", "c"), false},
		{"gke slash in location", gke("my-project", "us-central1/x", "c"), false},
		{"gke dot segment location", gke("my-project", "..", "c"), false},
		{"eks default region", eks("prod", ""), true},
		{"eks name with underscore", eks("Prod_1", "us-east-1"), true},
		{"eks china region", eks("prod", "cn-north-1"), true},
		{"eks govcloud region", eks("prod", "us-gov-west-1"), true},
		{"eks slash in name", eks("a/b", "us-east-1"), false},
		{"eks dot segment name", eks("..", "us-east-1"), false},
		{"eks dot in name", eks("a.b", "us-east-1"), false},
		{"eks dotted region", eks("prod", "us-east-1.example"), false},
		{"eks iso region", eks("prod", "us-iso-east-1"), false},
		{"eks uppercase region", eks("prod", "US-EAST-1"), false},
		{"aks plain", aks(testSubscription, "rg-prod", "aks-1"), true},
		{"aks resource group with parens and dots", aks(testSubscription, "rg.(team)_x", "aks_1"), true},
		{"aks unicode resource group", aks(testSubscription, "gruppe-ä", "aks"), true},
		{"aks dot segment resource group", aks(testSubscription, "..", "aks"), false},
		{"aks single dot resource group", aks(testSubscription, ".", "aks"), false},
		{"aks resource group ends with dot", aks(testSubscription, "rg.", "aks"), false},
		{"aks slash in resource group", aks(testSubscription, "rg/x", "aks"), false},
		{"aks dot segment cluster", aks(testSubscription, "rg", ".."), false},
		{"aks slash in cluster", aks(testSubscription, "rg", "a/b"), false},
		{"aks cluster starts with hyphen", aks(testSubscription, "rg", "-aks"), false},
		{"aks subscription not a uuid", aks("my-sub", "rg", "aks"), false},
		{"aks dot segment subscription", aks("..", "rg", "aks"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.ok && tc.err != nil {
				t.Errorf("rejected a valid identifier: %v", tc.err)
			}
			if !tc.ok && !errors.Is(tc.err, ErrInvalidClusterIdentifier) {
				t.Errorf("err = %v, want ErrInvalidClusterIdentifier", tc.err)
			}
		})
	}
}

func TestEKSRegionStaysInTheConfiguredPartition(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		configured, requested string
		ok                    bool
	}{
		{"us-east-1", "", true},
		{"us-east-1", "eu-west-1", true},
		{"us-east-1", "cn-north-1", false},
		{"us-east-1", "us-gov-west-1", false},
		{"cn-north-1", "cn-northwest-1", true},
		{"cn-north-1", "us-east-1", false},
		{"us-gov-west-1", "us-gov-east-1", true},
		{"", "us-east-1", true},
		{"", "cn-north-1", false},
	} {
		t.Run(tc.configured+"->"+tc.requested, func(t *testing.T) {
			t.Parallel()
			p := newEKSProvider(aws.Config{Region: tc.configured})
			err := p.validateArgs(&EKSAuthArgs{ClusterName: "prod", Region: tc.requested})
			if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrInvalidClusterIdentifier)) {
				t.Errorf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// gkeRequestURL runs the default GKE resolution against a capturing transport and returns the URL it sent.
func gkeRequestURL(t *testing.T, project, location, cluster string) *url.URL {
	t.Helper()
	rt := &captureRT{status: http.StatusNotFound, body: `{"error":{"code":404,"message":"not found"}}`}
	factory := func(ctx context.Context, _ oauth2.TokenSource) (*container.Service, error) {
		return container.NewService(ctx, option.WithHTTPClient(&http.Client{Transport: rt}))
	}
	_, _ = defaultGKEGetCluster(t.Context(), factory, oauth2.StaticTokenSource(&oauth2.Token{}),
		project, location, cluster)
	urls := rt.seen()
	if len(urls) != 1 {
		t.Fatalf("GKE resolution sent %d requests, want 1", len(urls))
	}
	return urls[0]
}

// eksRequestURL runs the default EKS DescribeCluster against a capturing transport and returns the URL it sent.
func eksRequestURL(t *testing.T, region, cluster string) *url.URL {
	t.Helper()
	rt := &captureRT{status: http.StatusNotFound, body: `{"message":"not found"}`}
	cfg := aws.Config{
		Region:      region,
		Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", ""),
		HTTPClient:  &http.Client{Transport: rt},
	}
	_, _ = defaultEKSDescribeCluster(t.Context(), cfg, cluster)
	urls := rt.seen()
	if len(urls) != 1 {
		t.Fatalf("EKS resolution sent %d requests, want 1", len(urls))
	}
	return urls[0]
}

// aksRequestURLs runs the default AKS credential listing against a capturing transport answering status/body.
func aksRequestURLs(t *testing.T, sub, group, cluster string, status int, body string) []*url.URL {
	t.Helper()
	rt := &captureRT{status: status, body: body}
	client, err := defaultAKSNewManagedClustersClient(sub, staticAzureCredential{},
		azcore.ClientOptions{Transport: &http.Client{Transport: rt}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = client.ListClusterUserCredentials(t.Context(), group, cluster, nil)
	return rt.seen()
}

func TestManagedClusterResolutionURLs(t *testing.T) {
	t.Parallel()
	if u := gkeRequestURL(t, "my-project", "us-central1-a", "prod-1"); u.Host != "container.googleapis.com" ||
		u.EscapedPath() != "/v1/projects/my-project/locations/us-central1-a/clusters/prod-1" {
		t.Errorf("GKE URL = %s", u)
	}
	if u := eksRequestURL(t, "eu-west-1", "Prod_1"); u.Host != "eks.eu-west-1.amazonaws.com" ||
		u.EscapedPath() != "/clusters/Prod_1" {
		t.Errorf("EKS URL = %s", u)
	}
	urls := aksRequestURLs(t, testSubscription, "gruppe-ä", "aks_1", http.StatusNotFound, `{}`)
	want := "/subscriptions/" + testSubscription + "/resourceGroups/gruppe-%C3%A4" +
		"/providers/Microsoft.ContainerService/managedClusters/aks_1/listClusterUserCredential"
	if len(urls) != 1 || urls[0].Host != "management.azure.com" || urls[0].EscapedPath() != want {
		t.Errorf("AKS URLs = %v, want one request to %s", urls, want)
	}
}

// TestAKSClientNeverRegistersAResourceProvider pins DisableRPRegistration: ARM's 409 MissingSubscriptionRegistration
// must come back as an error, never as a provider registration POST (a write) followed by a retry.
func TestAKSClientNeverRegistersAResourceProvider(t *testing.T) {
	t.Parallel()
	urls := aksRequestURLs(t, testSubscription, "rg", "aks", http.StatusConflict,
		`{"error":{"code":"MissingSubscriptionRegistration","message":"not registered"}}`)
	if len(urls) != 1 {
		t.Errorf("AKS client sent %d requests, want exactly the credentials POST: %v", len(urls), urls)
	}
}
