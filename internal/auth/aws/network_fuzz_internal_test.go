package aws

import (
	"errors"
	"testing"
)

// FuzzParseHost pins panic-freedom and the host-pinning reject contract over
// arbitrary authority strings (#181). A successful parse must name a service;
// every failure must be ErrHostPattern (fail closed, never a bare error).
func FuzzParseHost(f *testing.F) {
	f.Add("ec2.us-east-1.amazonaws.com")
	f.Add("iam.amazonaws.com")
	f.Add("127.0.0.1")
	f.Add("s3.us-east-1.amazonaws.com.attacker.com")
	f.Add("localhost")
	f.Add("")
	f.Add("[::1]")
	f.Add("bucket.s3.us-west-2.amazonaws.com")

	f.Fuzz(func(t *testing.T, host string) {
		got, err := ParseHost(host)
		if err == nil {
			if got.Service == "" {
				t.Fatalf("accepted host %q with empty service", host)
			}

			return
		}
		if !errors.Is(err, ErrHostPattern) {
			t.Fatalf("ParseHost(%q) err = %v, want ErrHostPattern", host, err)
		}
	})
}
