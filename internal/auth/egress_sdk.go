package auth

import (
	"context"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/smithy-go/logging"
	"golang.org/x/oauth2"
)

// awsHTTPClient is the AWS SDK's own buildable client with only its proxy
// selector replaced, so the SDK keeps its dialer, TLS settings, redirect
// policy and the IMDS timeout adjustments that require this concrete type.
func (e *Egress) awsHTTPClient() *awshttp.BuildableClient {
	return awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
		tr.Proxy = e.proxyForRequest
	})
}

// awsLoadOptions are the LoadDefaultConfig options that route every AWS SDK
// client through the policy: the shared HTTP client, and the container
// credential provider's own client, which LoadDefaultConfig does not copy from
// the shared one.
func (e *Egress) awsLoadOptions() []func(*awsconfig.LoadOptions) error {
	client := e.awsHTTPClient()

	return []func(*awsconfig.LoadOptions) error{
		awsconfig.WithHTTPClient(client),
		awsconfig.WithEndpointCredentialOptions(func(o *endpointcreds.Options) { o.HTTPClient = client }),
	}
}

// awsConfigOptions is the full option list LoadDefaultConfig gets: the silent
// logger, then the routed clients. Every AWS client the resulting aws.Config
// produces (STS, IAM, EKS, assume-role and the credential providers) inherits
// them, so the composition is core rather than shell.
func (e *Egress) awsConfigOptions() []func(*awsconfig.LoadOptions) error {
	return append(
		[]func(*awsconfig.LoadOptions) error{awsconfig.WithLogger(logging.Nop{})},
		e.awsLoadOptions()...,
	)
}

// azureClientOptions are the azcore client options every Azure SDK client and
// credential gets: the resolved cloud and the routed transport. The routed
// transport replaces azcore's default one, so azcore's Renegotiation
// (RenegotiateFreelyAsClient), its MaxIdleConnsPerHost of 10 and its HTTP/2 ping
// health check (ReadIdleTimeout 10s, PingTimeout 5s) do not apply, and the TLS
// 1.2 floor it sets is Go's client default anyway. The connector's ARM and login
// calls are short-lived and need none of them.
func (e *Egress) azureClientOptions(sdkCloud cloud.Configuration) azcore.ClientOptions {
	return azcore.ClientOptions{Cloud: sdkCloud, Transport: e.HTTPClient(0)}
}

// withAPIClient returns ctx carrying an unbounded routed client under the
// oauth2.HTTPClient key, the base oauth2.NewClient copies for a Google API
// client. Callers keep setting their own overall timeouts on the result.
func (e *Egress) withAPIClient(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, e.HTTPClient(0))
}

// apiClient is the authenticated Google API client: token refreshes go through
// ts, API calls through the routed base transport, no overall timeout (callers
// set their own).
func (e *Egress) apiClient(ctx context.Context, ts oauth2.TokenSource) *http.Client {
	return oauth2.NewClient(e.withAPIClient(ctx), ts)
}
