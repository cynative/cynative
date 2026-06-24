package auth

import (
	"net/http"
	"testing"
)

func TestSigningRegion(t *testing.T) {
	t.Parallel()

	const sdk = "eu-west-1" // a non-canonical ambient region, to prove it is not used for global hosts.

	newReq := func(rawURL, hostOverride string) *http.Request {
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if hostOverride != "" {
			req.Host = hostOverride
		}
		return req
	}

	cases := map[string]struct {
		url, host, claim, want string
	}{
		"regional omitted":         {"https://s3.us-west-2.amazonaws.com/x", "", "", "us-west-2"},
		"regional explicit match":  {"https://s3.us-west-2.amazonaws.com/x", "", "us-west-2", "us-west-2"},
		"global omitted":           {"https://iam.amazonaws.com/", "", "", "us-east-1"},
		"global aws-global claim":  {"https://iam.amazonaws.com/", "", "aws-global", "us-east-1"},
		"global china cross-claim": {"https://iam.amazonaws.com.cn/", "", "us-east-1", "cn-north-1"},
		"global govcloud omitted":  {"https://iam.us-gov.amazonaws.com/", "", "", "us-gov-west-1"},
		"host override region": {
			"https://s3.us-west-2.amazonaws.com/x",
			"bkt.s3.us-east-1.amazonaws.com",
			"",
			"us-east-1",
		},
		// Unparseable (non-AWS) host: ParseHost errors → claim-or-SDK fallback. This
		// case is required to cover the err branch of signingRegion for the 100% gate.
		"unparseable falls back to claim": {"https://not-aws.example.com/x", "", "ca-central-1", "ca-central-1"},
		"unparseable falls back to sdk":   {"https://not-aws.example.com/x", "", "", sdk},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := newReq(tc.url, tc.host)
			args := &AWSAuthArgs{
				Service: "s3",
				Region:  tc.claim,
			} //nolint:exhaustruct // Service unused by signingRegion
			if got := signingRegion(args, req, sdk); got != tc.want {
				t.Errorf("signingRegion = %q, want %q", got, tc.want)
			}
		})
	}
}
