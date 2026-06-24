package aws

import (
	"errors"
	"strings"
	"testing"
)

func TestCanonicalGlobalRegion(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		host string
		want string
	}{
		"public":           {"iam.amazonaws.com", "us-east-1"},
		"china":            {"iam.amazonaws.com.cn", "cn-north-1"},
		"govcloud":         {"iam.us-gov.amazonaws.com", "us-gov-west-1"},
		"mixed-case-china": {"IAM.AMAZONAWS.COM.CN", "cn-north-1"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ph, err := ParseHost(strings.ToLower(tc.host))
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", tc.host, err)
			}
			if ph.Region != "" {
				t.Fatalf("expected global host (empty Region), got %q", ph.Region)
			}
			if got := CanonicalGlobalRegion(ph); got != tc.want {
				t.Errorf("CanonicalGlobalRegion(%q) = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

func TestParseHost_emptyHostFails(t *testing.T) {
	t.Parallel()
	_, err := ParseHost("")
	if !errors.Is(err, ErrHostPattern) {
		t.Fatalf("ParseHost(\"\") err = %v, want ErrHostPattern", err)
	}
}

func TestParseHost_unknownSuffixFails(t *testing.T) {
	t.Parallel()
	cases := []string{
		"s3.us-east-1.amazon-aws.com",             // TLD typo
		"s3.us-east-1.amazonaws.com.attacker.com", // suffix masquerade
		"attacker.com",
		"127.0.0.1",
		"localhost",
	}
	for _, host := range cases {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			_, err := ParseHost(host)
			if !errors.Is(err, ErrHostPattern) {
				t.Errorf("ParseHost(%q) err = %v, want ErrHostPattern", host, err)
			}
		})
	}
}

func TestParseHost_standardRegional(t *testing.T) {
	t.Parallel()
	cases := []struct {
		host       string
		wantSvc    string
		wantRegion string
	}{
		{"ec2.us-east-1.amazonaws.com", "ec2", "us-east-1"},
		{"dynamodb.eu-west-3.amazonaws.com", "dynamodb", "eu-west-3"},
		{"kms.ap-southeast-2.amazonaws.com", "kms", "ap-southeast-2"},
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			t.Parallel()
			got, err := ParseHost(c.host)
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", c.host, err)
			}
			if got.Service != c.wantSvc || got.Region != c.wantRegion {
				t.Errorf("got (svc=%q, region=%q), want (%q, %q)",
					got.Service, got.Region, c.wantSvc, c.wantRegion)
			}
		})
	}
}

func TestParseHost_global(t *testing.T) {
	t.Parallel()
	cases := []struct {
		host    string
		wantSvc string
	}{
		{"iam.amazonaws.com", "iam"},
		{"sts.amazonaws.com", "sts"},
		{"cloudfront.amazonaws.com", "cloudfront"},
		{"route53.amazonaws.com", "route53"},
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			t.Parallel()
			got, err := ParseHost(c.host)
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", c.host, err)
			}
			if got.Service != c.wantSvc || got.Region != "" {
				t.Errorf("got (svc=%q, region=%q), want (%q, \"\")",
					got.Service, got.Region, c.wantSvc)
			}
		})
	}
}

func TestParseHost_s3Variants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		host       string
		wantSvc    string
		wantRegion string
	}{
		{"path-regional", "s3.us-east-1.amazonaws.com", "s3", "us-east-1"},
		{"path-global", "s3.amazonaws.com", "s3", "us-east-1"},
		{"virtual-regional", "my-bucket.s3.us-east-1.amazonaws.com", "s3", "us-east-1"},
		{"virtual-global", "my-bucket.s3.amazonaws.com", "s3", "us-east-1"},
		{"legacy-hyphenated", "s3-us-west-2.amazonaws.com", "s3", "us-west-2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseHost(c.host)
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", c.host, err)
			}
			if got.Service != c.wantSvc || got.Region != c.wantRegion {
				t.Errorf("got %+v, want svc=%q region=%q", got, c.wantSvc, c.wantRegion)
			}
		})
	}
}

func TestParseHost_specialPatterns(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		host       string
		wantSvc    string
		wantRegion string
	}{
		{"fips-regional", "s3-fips.us-east-1.amazonaws.com", "s3", "us-east-1"},
		{"fips-global", "iam-fips.amazonaws.com", "iam", ""},
		{"dualstack-svc", "dynamodb.us-east-1.api.aws", "dynamodb", "us-east-1"},
		{"dualstack-s3", "s3.dualstack.us-east-1.amazonaws.com", "s3", "us-east-1"},
		{"apigateway", "my-api-id.execute-api.us-east-1.amazonaws.com", "execute-api", "us-east-1"},
		{"lambda-url", "fnabc123.lambda-url.us-east-1.on.aws", "lambda", "us-east-1"},
		{"opensearch", "my-domain.us-east-1.es.amazonaws.com", "es", "us-east-1"},
		{"opensearch-single-label-fallthrough", "nodomain.es.amazonaws.com", "nodomain", "es"},
		{"iot-data", "abc123-ats.iot.us-east-1.amazonaws.com", "iotdata", "us-east-1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseHost(c.host)
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", c.host, err)
			}
			if got.Service != c.wantSvc || got.Region != c.wantRegion {
				t.Errorf("got %+v, want svc=%q region=%q", got, c.wantSvc, c.wantRegion)
			}
		})
	}
}

func TestParseHost_specialPatternRejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		host string
	}{
		// tryLambdaURL: .on.aws suffix but no .lambda-url. marker.
		{"lambda-url-no-marker", "fnabc123.wrongsegment.us-east-1.on.aws"},
		// tryDualstackAPIAWS: .api.aws suffix but wrong segment count (1 part).
		{"dualstack-api-aws-one-part", "dynamodb.api.aws"},
		// tryDualstackAPIAWS: .api.aws suffix but wrong segment count (3 parts).
		{"dualstack-api-aws-three-parts", "a.b.c.api.aws"},
		// tryS3Dualstack: s3.dualstack. prefix but no .amazonaws.com suffix.
		{"s3-dualstack-wrong-suffix", "s3.dualstack.us-east-1.other.com"},
		// Hosts with 3+ labels before the region (malformed execute-api / iot / fips
		// variants) now parse via the generic multi-label rule and are rejected by the
		// model archive index downstream — see TestParseHost_multiLabelPrefix.
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseHost(c.host)
			if !errors.Is(err, ErrHostPattern) {
				t.Errorf("ParseHost(%q) err = %v, want ErrHostPattern", c.host, err)
			}
		})
	}
}

func TestParseHost_multiLabelPrefix(t *testing.T) {
	t.Parallel()
	// The generic rule treats the last label before the suffix as the region and
	// joins the rest as the endpoint prefix. Genuine multi-label services resolve;
	// malformed special-pattern hosts also parse here and are rejected downstream by
	// the model archive index (fail-closed), not by ParseHost. The malformed cases
	// also exercise the special matchers' deeper false branches.
	cases := []struct {
		name, host, svc, region string
	}{
		{"ecr", "api.ecr.us-east-1.amazonaws.com", "api.ecr", "us-east-1"},
		{"sagemaker-runtime", "runtime.sagemaker.eu-west-1.amazonaws.com", "runtime.sagemaker", "eu-west-1"},
		{"dynamodb-streams", "streams.dynamodb.us-east-2.amazonaws.com", "streams.dynamodb", "us-east-2"},
		{
			"apigateway-extra-labels",
			"id.execute-api.us-east-1.extra.amazonaws.com",
			"id.execute-api.us-east-1",
			"extra",
		},
		{"opensearch-trailing-dot", "my-domain..es.amazonaws.com", "my-domain.", "es"},
		{"iot-extra-labels", "dev.iot.us-east-1.extra.amazonaws.com", "dev.iot.us-east-1", "extra"},
		{"fips-rest-not-dot", "s3-fipsxtra.us-east-1.extra.amazonaws.com", "s3-fipsxtra.us-east-1", "extra"},
		{"three-label", "a.b.c.amazonaws.com", "a.b", "c"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseHost(c.host)
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", c.host, err)
			}
			if got.Service != c.svc || got.Region != c.region {
				t.Errorf("ParseHost(%q) = (%q,%q), want (%q,%q)", c.host, got.Service, got.Region, c.svc, c.region)
			}
		})
	}
}

func TestParseHost_partitions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		host       string
		wantSvc    string
		wantRegion string
	}{
		{"s3.cn-north-1.amazonaws.com.cn", "s3", "cn-north-1"},
		{"iam.cn-north-1.amazonaws.com.cn", "iam", "cn-north-1"},
		{"s3.us-gov-west-1.us-gov.amazonaws.com", "s3", "us-gov-west-1"},
		{"iam.us-gov.amazonaws.com", "iam", ""},
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			t.Parallel()
			got, err := ParseHost(c.host)
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", c.host, err)
			}
			if got.Service != c.wantSvc || got.Region != c.wantRegion {
				t.Errorf("got %+v, want svc=%q region=%q", got, c.wantSvc, c.wantRegion)
			}
		})
	}
}

func TestParseHost_rejectEdgeCases(t *testing.T) {
	t.Parallel()
	cases := []string{
		".amazonaws.com", // empty prefix → body == "" branch.
		"8.8.8.8",        // cloudauth.IsIPLiteral (netip.ParseAddr) flags it as an IP literal (no .amazonaws.com suffix).
		"2001:db8::1",    // IPv6 colon.
	}
	for _, host := range cases {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			_, err := ParseHost(host)
			if !errors.Is(err, ErrHostPattern) {
				t.Errorf("ParseHost(%q) err = %v, want ErrHostPattern", host, err)
			}
		})
	}
}

func TestVerify_serviceMatch(t *testing.T) {
	t.Parallel()
	p := ParsedHost{Service: "s3", Region: "us-east-1"}
	if err := Verify(p, "s3", "us-east-1"); err != nil {
		t.Errorf("matching claim returned err: %v", err)
	}
}

func TestVerify_serviceMismatch(t *testing.T) {
	t.Parallel()
	p := ParsedHost{Service: "s3", Region: "us-east-1"}
	err := Verify(p, "iam", "us-east-1")
	if !errors.Is(err, ErrHostClaimMismatch) {
		t.Errorf("got %v, want ErrHostClaimMismatch", err)
	}
}

func TestVerify_regionMismatch(t *testing.T) {
	t.Parallel()
	p := ParsedHost{Service: "s3", Region: "us-east-1"}
	err := Verify(p, "s3", "eu-west-1")
	if !errors.Is(err, ErrHostClaimMismatch) {
		t.Errorf("got %v, want ErrHostClaimMismatch", err)
	}
}

func TestVerify_globalServiceAcceptsCanonicalRegions(t *testing.T) {
	t.Parallel()
	p := ParsedHost{Service: "iam", Region: ""}
	canonical := []string{"", "aws-global", "us-east-1", "us-gov-west-1", "cn-north-1"}
	for _, region := range canonical {
		if err := Verify(p, "iam", region); err != nil {
			t.Errorf("global service rejected canonical region %q: %v", region, err)
		}
	}
}

func TestVerify_globalServiceRejectsNonCanonicalRegion(t *testing.T) {
	t.Parallel()
	p := ParsedHost{Service: "iam", Region: ""}
	if err := Verify(p, "iam", "eu-west-1"); !errors.Is(err, ErrHostClaimMismatch) {
		t.Errorf("got %v, want ErrHostClaimMismatch", err)
	}
}

// TestParseHost_hardenedLiteralRejects pins the B2 hardening: AWS ParseHost must
// reject IP-literal smuggle forms and non-ASCII hosts. DWORD/octal/hex are
// rejected via no-suffix-match (netip cannot parse them), non-ASCII via
// cloudauth.NormalizeHost step 5, and bracketed/bare/IPv4-mapped IPv6 via
// cloudauth.IsIPLiteral.
func TestParseHost_hardenedLiteralRejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		host string
	}{
		{name: "dword", host: "2130706433"},
		{name: "octal", host: "0177.0.0.1"},
		{name: "hex", host: "0x7f.0.0.1"},
		{name: "fullwidth-digit smuggle", host: "１９２．１６８．１．１"},
		{name: "cyrillic homoglyph", host: "ѕ3.amazonaws.com"},
		{name: "bracketed ipv6 loopback", host: "[::1]"},
		{name: "bare colon ipv6", host: "::1"},
		{name: "bare ipv4-mapped imds", host: "::ffff:169.254.169.254"},
		{name: "bracketed ipv4-mapped imds", host: "[::ffff:169.254.169.254]"},
		{name: "ipv4 imds literal", host: "169.254.169.254"},
		{name: "ipv4 loopback dotted", host: "127.0.0.1"},
		{name: "localhost", host: "localhost"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseHost(c.host)
			if !errors.Is(err, ErrHostPattern) {
				t.Errorf("ParseHost(%q) err = %v, want ErrHostPattern", c.host, err)
			}
		})
	}
}

func TestParseHost_rejectVPCEndpoints(t *testing.T) {
	t.Parallel()
	cases := []string{
		"vpce-0a1b.s3.us-east-1.amazonaws.com",
		"vpce-0a1b2c3d.execute-api.us-east-1.vpce.amazonaws.com",
		"vpce-12345.kms.us-east-1.amazonaws.com",
	}
	for _, host := range cases {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			_, err := ParseHost(host)
			if !errors.Is(err, ErrHostPattern) {
				t.Errorf("ParseHost(%q) err = %v, want ErrHostPattern", host, err)
			}
		})
	}
}

func TestParseHost_s3ControlAccountScoped(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, host, wantRegion string
	}{
		{"plain", "123456789012.s3-control.us-east-1.amazonaws.com", "us-east-1"},
		{"fips", "123456789012.s3-control-fips.us-east-1.amazonaws.com", "us-east-1"},
		{"dualstack", "123456789012.s3-control.dualstack.eu-west-1.amazonaws.com", "eu-west-1"},
		{"fips-dualstack", "123456789012.s3-control-fips.dualstack.eu-west-1.amazonaws.com", "eu-west-1"},
		{"china", "123456789012.s3-control.cn-north-1.amazonaws.com.cn", "cn-north-1"},
		{"gov", "123456789012.s3-control.us-gov-west-1.amazonaws.com", "us-gov-west-1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseHost(c.host)
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", c.host, err)
			}
			if got.Service != "s3-control" || got.Region != c.wantRegion {
				t.Errorf("got (%q,%q), want (s3-control,%q)", got.Service, got.Region, c.wantRegion)
			}
		})
	}
}

func TestParseHost_s3ControlNonAccountPassthrough(t *testing.T) {
	t.Parallel()
	// No 12-digit account prefix: the matcher declines and the generic rule
	// parses it correctly (service "s3-control", region from the trailing label).
	got, err := ParseHost("s3-control.us-east-1.amazonaws.com")
	if err != nil {
		t.Fatalf("ParseHost: %v", err)
	}
	if got.Service != "s3-control" || got.Region != "us-east-1" {
		t.Errorf("got (%q,%q), want (s3-control,us-east-1)", got.Service, got.Region)
	}
}

func TestVerify_s3ControlClaimSpellings(t *testing.T) {
	t.Parallel()
	p := ParsedHost{Service: "s3-control", Region: "us-east-1"}
	for _, claim := range []string{"s3-control", "s3control", "S3Control", "S3-CONTROL"} {
		if err := Verify(p, claim, "us-east-1"); err != nil {
			t.Errorf("Verify(s3-control, %q) = %v, want nil", claim, err)
		}
	}
}

func TestVerify_s3ControlRejectsWrongService(t *testing.T) {
	t.Parallel()
	p := ParsedHost{Service: "s3-control", Region: "us-east-1"}
	if err := Verify(p, "iam", "us-east-1"); !errors.Is(err, ErrHostClaimMismatch) {
		t.Errorf("Verify(s3-control, iam) = %v, want ErrHostClaimMismatch", err)
	}
}

func TestVerify_s3ControlRejectsWrongRegion(t *testing.T) {
	t.Parallel()
	// Hyphen-variant service claim still must match the region exactly.
	p := ParsedHost{Service: "s3-control", Region: "us-east-1"}
	if err := Verify(p, "s3control", "eu-west-1"); !errors.Is(err, ErrHostClaimMismatch) {
		t.Errorf("Verify(s3-control, s3control, eu-west-1) = %v, want ErrHostClaimMismatch", err)
	}
}

func TestParseHost_s3ControlRejects(t *testing.T) {
	t.Parallel()
	// Each declines tryS3Control; it then either falls through to another matcher
	// or is rejected with ErrHostPattern. We assert it is NOT parsed as s3-control.
	cases := []struct{ name, host string }{
		{"non-numeric-prefix", "notanaccount.s3-control.us-east-1.amazonaws.com"},
		{"twelve-with-letter", "12345678901a.s3-control.us-east-1.amazonaws.com"},
		{"wrong-length-prefix", "12345.s3-control.us-east-1.amazonaws.com"},
		{"no-region", "123456789012.s3-control.amazonaws.com"},
		{"empty-region", "123456789012.s3-control..amazonaws.com"},
		{"multi-label-region", "123456789012.s3-control.us.east.1.amazonaws.com"},
		{"wrong-suffix", "123456789012.s3-control.us-east-1.example.com"},
		{"wrong-prefix-body", "123456789012.s3-data.us-east-1.amazonaws.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseHost(c.host)
			if err == nil && got.Service == "s3-control" {
				t.Errorf("ParseHost(%q) wrongly matched s3-control: %+v", c.host, got)
			}
		})
	}
}

func TestParseHost_s3AccessPointAccountScoped(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, host, wantRegion string
	}{
		{"plain", "myendpoint-111122223333.s3-accesspoint.us-east-1.amazonaws.com", "us-east-1"},
		{"fips", "myendpoint-111122223333.s3-accesspoint-fips.us-east-1.amazonaws.com", "us-east-1"},
		{"dualstack", "myendpoint-111122223333.s3-accesspoint.dualstack.eu-west-1.amazonaws.com", "eu-west-1"},
		{"fips-dualstack", "ep-111122223333.s3-accesspoint-fips.dualstack.eu-west-1.amazonaws.com", "eu-west-1"},
		{"china", "ep-111122223333.s3-accesspoint.cn-north-1.amazonaws.com.cn", "cn-north-1"},
		{"gov", "ep-111122223333.s3-accesspoint.us-gov-west-1.amazonaws.com", "us-gov-west-1"},
		{"hyphenated-name", "my-access-point-111122223333.s3-accesspoint.us-east-1.amazonaws.com", "us-east-1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseHost(c.host)
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", c.host, err)
			}
			if got.Service != "s3" || got.Region != c.wantRegion {
				t.Errorf("got (%q,%q), want (s3,%q)", got.Service, got.Region, c.wantRegion)
			}
		})
	}
}

func TestParseHost_s3AccessPointRejects(t *testing.T) {
	t.Parallel()
	// Each declines tryS3AccessPoint; ParseHost then falls through to another
	// matcher or is rejected. We assert it is NOT parsed as service "s3" via the
	// access-point path (i.e. either an error, or a different/derived service).
	cases := []struct{ name, host string }{
		{"no-account-suffix", "notanaccount.s3-accesspoint.us-east-1.amazonaws.com"},
		{"bare-no-name-account", "s3-accesspoint.us-east-1.amazonaws.com"},
		{"eleven-digit-suffix", "ep-11112222333.s3-accesspoint.us-east-1.amazonaws.com"},
		{"thirteen-digit-suffix", "ep-1111222233334.s3-accesspoint.us-east-1.amazonaws.com"},
		{"empty-name", "-111122223333.s3-accesspoint.us-east-1.amazonaws.com"},
		{"no-region", "ep-111122223333.s3-accesspoint.amazonaws.com"},
		{"empty-region", "ep-111122223333.s3-accesspoint..amazonaws.com"},
		{"multi-label-region", "ep-111122223333.s3-accesspoint.us.east.1.amazonaws.com"},
		{"wrong-tld", "ep-111122223333.s3-accesspoint.us-east-1.example.com"},
		{"wrong-infix-body", "my-ap-111122223333.s3-data.us-east-1.amazonaws.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseHost(c.host)
			if err == nil && got.Service == "s3" {
				t.Errorf("ParseHost(%q) wrongly matched s3 via access-point path: %+v", c.host, got)
			}
		})
	}
}

func TestParseHost_s3AccessPointDualstackOnly(t *testing.T) {
	t.Parallel()
	// Degenerate inherited edge: "…s3-accesspoint.dualstack.amazonaws.com" with no
	// trailing region label parses with region "dualstack" (the dualstack strip
	// only fires when a region follows). It parses, but fails closed at Verify
	// against any real region claim — documented as intentional, not a bug.
	const host = "ep-111122223333.s3-accesspoint.dualstack.amazonaws.com"
	got, err := ParseHost(host)
	if err != nil {
		t.Fatalf("ParseHost(%q): %v", host, err)
	}
	if got.Service != "s3" || got.Region != "dualstack" {
		t.Fatalf("got (%q,%q), want (s3,dualstack)", got.Service, got.Region)
	}
	if verifyErr := Verify(got, "s3", "us-east-1"); !errors.Is(verifyErr, ErrHostClaimMismatch) {
		t.Errorf("Verify(dualstack-region, us-east-1) = %v, want ErrHostClaimMismatch", verifyErr)
	}
}

func TestVerify_s3AccessPoint(t *testing.T) {
	t.Parallel()
	p := ParsedHost{Service: "s3", Region: "us-east-1"}
	if err := Verify(p, "s3", "us-east-1"); err != nil {
		t.Errorf("Verify(s3, s3, us-east-1) = %v, want nil", err)
	}
	if err := Verify(p, "iam", "us-east-1"); !errors.Is(err, ErrHostClaimMismatch) {
		t.Errorf("Verify(s3, iam) = %v, want ErrHostClaimMismatch", err)
	}
	if err := Verify(p, "s3", "eu-west-1"); !errors.Is(err, ErrHostClaimMismatch) {
		t.Errorf("Verify(s3, s3, eu-west-1) = %v, want ErrHostClaimMismatch", err)
	}
	// Asymmetry vs. s3-control: there is no s3↔s3-accesspoint dehyphen alias, so a
	// literal "s3-accesspoint" claim is correctly rejected (fail closed).
	if err := Verify(p, "s3-accesspoint", "us-east-1"); !errors.Is(err, ErrHostClaimMismatch) {
		t.Errorf("Verify(s3, s3-accesspoint) = %v, want ErrHostClaimMismatch", err)
	}
}

func TestVerify_EmptyRegionAccepted(t *testing.T) {
	t.Parallel()

	regional := ParsedHost{Service: "s3", Region: "us-west-2"} //nolint:exhaustruct // only fields under test
	// Omitted region on a regional host: accepted (derived from host).
	if err := Verify(regional, "s3", ""); err != nil {
		t.Errorf("omitted region on regional host: got %v, want nil", err)
	}
	// A non-empty mismatched region is still rejected.
	if err := Verify(regional, "s3", "eu-west-1"); !errors.Is(err, ErrHostClaimMismatch) {
		t.Errorf("mismatched region: got %v, want ErrHostClaimMismatch", err)
	}
}

func TestParseHost_BucketInHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		host string
		want bool
	}{
		// Virtual-hosted / access-point: the bucket lives in the host.
		{"vhost-global", "my-bucket.s3.amazonaws.com", true},
		{"vhost-regional", "my-bucket.s3.us-east-1.amazonaws.com", true},
		{"access-point", "myendpoint-111122223333.s3-accesspoint.us-east-1.amazonaws.com", true},
		{"access-point-china", "ep-111122223333.s3-accesspoint.cn-north-1.amazonaws.com.cn", true},
		// Path-style and non-vhost: the bucket (if any) is in the path.
		{"path-regional", "s3.us-east-1.amazonaws.com", false},
		{"path-global", "s3.amazonaws.com", false},
		{"legacy-hyphenated", "s3-us-west-2.amazonaws.com", false},
		{"dualstack-path-style", "s3.dualstack.us-east-1.amazonaws.com", false},
		{"s3-control", "111122223333.s3-control.us-east-1.amazonaws.com", false},
		{"non-s3", "dynamodb.us-east-1.amazonaws.com", false},
		// Out-of-scope vhost shapes parse to a nonsense prefix (they fail closed
		// later at model resolution); they must NOT set BucketInHost.
		{"vhost-dualstack-out-of-scope", "my-bucket.s3.dualstack.us-east-1.amazonaws.com", false},
		{"vhost-fips-out-of-scope", "my-bucket.s3-fips.us-east-1.amazonaws.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseHost(c.host)
			if err != nil {
				t.Fatalf("ParseHost(%q): %v", c.host, err)
			}
			if got.BucketInHost != c.want {
				t.Errorf("ParseHost(%q).BucketInHost = %v, want %v", c.host, got.BucketInHost, c.want)
			}
		})
	}
}
