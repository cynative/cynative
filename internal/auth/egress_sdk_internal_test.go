package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/smithy-go/logging"
	"golang.org/x/oauth2"
)

// TestAWSConfigOptions_CarryTheSilentLoggerAndTheRoutedClients pins the option
// list the registration shell hands LoadDefaultConfig. Every AWS client built
// from the resulting config inherits it, so dropping the routed clients here
// would send STS, IAM, EKS, assume-role and the credential providers direct
// under a proxy-only policy with no other test noticing.
func TestAWSConfigOptions_CarryTheSilentLoggerAndTheRoutedClients(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp:3128", "NO_PROXY": "direct.example"})
	var lo awsconfig.LoadOptions
	for _, fn := range e.awsConfigOptions() {
		if err := fn(&lo); err != nil {
			t.Fatal(err)
		}
	}

	if _, ok := lo.Logger.(logging.Nop); !ok {
		t.Errorf("Logger is %T, want logging.Nop so the SDK stays silent", lo.Logger)
	}

	bc, ok := lo.HTTPClient.(*awshttp.BuildableClient)
	if !ok {
		t.Fatalf("LoadOptions.HTTPClient is %T, want *awshttp.BuildableClient", lo.HTTPClient)
	}
	tr := bc.GetTransport()
	if tr.Proxy == nil {
		t.Fatal("the shared AWS client must carry the selector")
	}
	proxied, _ := tr.Proxy(httptest.NewRequest(http.MethodGet, "https://sts.amazonaws.com/", nil))
	direct, _ := tr.Proxy(httptest.NewRequest(http.MethodGet, "https://direct.example/", nil))
	if proxied == nil || proxied.Host != "proxy.corp:3128" || direct != nil {
		t.Fatalf("selection: proxied=%v direct=%v", proxied, direct)
	}

	if lo.EndpointCredentialOptions == nil {
		t.Fatal("the container-credential provider needs its own client option")
	}
	var eo endpointcreds.Options
	lo.EndpointCredentialOptions(&eo)
	if eo.HTTPClient != bc {
		t.Error("the container-credential provider must use the same routed client")
	}
}

func TestAWSHTTPClient_RoutesPerPolicy(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp:3128", "NO_PROXY": "direct.example"})
	tr := e.awsHTTPClient().GetTransport()
	if tr.Proxy == nil {
		t.Fatal("the AWS transport must carry the selector")
	}
	proxied, _ := tr.Proxy(httptest.NewRequest(http.MethodGet, "https://sts.amazonaws.com/", nil))
	direct, _ := tr.Proxy(httptest.NewRequest(http.MethodGet, "https://direct.example/", nil))
	if proxied == nil || proxied.Host != "proxy.corp:3128" || direct != nil {
		t.Fatalf("selection: proxied=%v direct=%v", proxied, direct)
	}
	// The SDK's own dialer survives the Proxy swap.
	if tr.DialContext == nil {
		t.Fatal("WithTransportOptions must keep the SDK's dialer")
	}
}

func TestAWSLoadOptions_InjectTheClientEverywhere(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp:3128"})
	var lo awsconfig.LoadOptions
	for _, fn := range e.awsLoadOptions() {
		if err := fn(&lo); err != nil {
			t.Fatal(err)
		}
	}
	bc, ok := lo.HTTPClient.(*awshttp.BuildableClient)
	if !ok {
		t.Fatalf("LoadOptions.HTTPClient is %T, want *awshttp.BuildableClient", lo.HTTPClient)
	}
	if lo.EndpointCredentialOptions == nil {
		t.Fatal("the container-credential provider needs its own client option")
	}
	var eo endpointcreds.Options
	lo.EndpointCredentialOptions(&eo)
	if eo.HTTPClient != bc {
		t.Fatal("the container-credential provider must use the same routed client")
	}
}

func TestWithRefreshClient_CarriesBoundedRoutedClient(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp:3128", "NO_PROXY": "direct.example"})
	ctx := e.withRefreshClient(context.Background())
	hc, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if !ok || hc.Timeout != gcpTokenRefreshOverallTimeout {
		t.Fatalf("refresh client = %+v, want the bounded client", hc)
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok || tr.ResponseHeaderTimeout != gcpTokenRefreshResponseHeaderTimeout {
		t.Fatalf("refresh transport = %+v, want the response-header bound", hc.Transport)
	}
	proxied, _ := tr.Proxy(httptest.NewRequest(http.MethodGet, "https://oauth2.googleapis.com/token", nil))
	direct, _ := tr.Proxy(httptest.NewRequest(http.MethodGet, "https://direct.example/", nil))
	if proxied == nil || direct != nil {
		t.Fatalf("refresh selection: proxied=%v direct=%v", proxied, direct)
	}
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		t.Fatal("withRefreshClient must not add a deadline")
	}
}

func TestAzureClientOptions_CarryTheRoutedTransportAndCloud(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp:3128"})
	sdkCloud := cloud.Configuration{ActiveDirectoryAuthorityHost: "https://login.example"}
	opts := e.azureClientOptions(sdkCloud)
	if opts.Cloud.ActiveDirectoryAuthorityHost != sdkCloud.ActiveDirectoryAuthorityHost {
		t.Fatal("azureClientOptions must keep the resolved cloud")
	}
	hc, ok := opts.Transport.(*http.Client)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Client", opts.Transport)
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Fatal("the Azure transport must carry the selector")
	}
	if got, _ := tr.Proxy(httptest.NewRequest(http.MethodGet, "https://management.azure.com/", nil)); got == nil {
		t.Fatal("ARM traffic must follow the configured proxy")
	}
}

func TestAPIClient_BuildsOnTheRoutedTransport(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp:3128"})
	hc := e.apiClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"}))
	otr, ok := hc.Transport.(*oauth2.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *oauth2.Transport", hc.Transport)
	}
	base, ok := otr.Base.(*http.Transport)
	if !ok || base.Proxy == nil {
		t.Fatalf("Base is %T, want the routed *http.Transport", otr.Base)
	}
	if hc.Timeout != 0 {
		t.Fatalf("Timeout = %v, want none (callers set their own)", hc.Timeout)
	}
}

func TestWithAPIClient_CarriesUnboundedRoutedClient(t *testing.T) {
	t.Parallel()

	e := mustEgress(t, map[string]string{"HTTPS_PROXY": "http://proxy.corp:3128"})
	hc, ok := e.withAPIClient(context.Background()).Value(oauth2.HTTPClient).(*http.Client)
	if !ok || hc.Timeout != 0 {
		t.Fatalf("API base client = %+v, want no overall timeout", hc)
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok || tr.ResponseHeaderTimeout != 0 || tr.Proxy == nil {
		t.Fatalf("API base transport = %+v, want no header bound and the selector", hc.Transport)
	}
}
