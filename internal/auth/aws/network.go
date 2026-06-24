// Package aws implements AWS-specific hardening that layers on top of the
// generic auth.Provider contract.
package aws

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cynative/cynative/internal/auth/cloudauth"
)

// ParsedHost is the structured result of ParseHost — the (service, region)
// tuple the host resolves to.
type ParsedHost struct {
	Service string // canonical Smithy endpointPrefix (e.g. "s3", "iam", "execute-api").
	Region  string // empty for global services (iam, sts, cloudfront, route53, ...).

	// Partition is the AWS partition the host belongs to, set by
	// parseStandardPartition from the matched suffix. Authoritative for
	// global-service signing region; regional hosts (Region != "") ignore it.
	Partition Partition

	// BucketInHost is true when the host carries the bucket/access-point
	// (virtual-hosted addressing), so the path-style URI templates omit the
	// leading {Bucket} segment. Set only by the S3 virtual-hosted and
	// access-point matchers; classification prepends a synthetic {Bucket} segment
	// when it is set. Additive: Verify and ResolveSigningName ignore it.
	BucketInHost bool
}

// Partition identifies the AWS partition a host belongs to. It is set during
// parsing from the matched host suffix and is authoritative for global-service
// signing-region derivation.
type Partition string

const (
	PartitionStandard Partition = "aws"        // .amazonaws.com
	PartitionChina    Partition = "aws-cn"     // .amazonaws.com.cn
	PartitionGovCloud Partition = "aws-us-gov" // .us-gov.amazonaws.com
)

// CanonicalGlobalRegion returns the single SigV4 signing region AWS uses for a
// global service (iam, sts, cloudfront, route53, ...) in p's partition.
func CanonicalGlobalRegion(p ParsedHost) string {
	switch p.Partition { //nolint:exhaustive // default covers PartitionStandard and any zero value.
	case PartitionChina:
		return "cn-north-1"
	case PartitionGovCloud:
		return "us-gov-west-1"
	default:
		return s3GlobalRegion
	}
}

// ErrHostPattern indicates the host did not match any known AWS endpoint
// pattern. Returned by ParseHost. Wrapped with %w when surfaced upstream.
var ErrHostPattern = errors.New("aws_hardening: unrecognized host pattern")

const (
	// partsGlobalService is the segment count for "<service>" (global, e.g. iam).
	partsGlobalService = 1
	// partsStandardRegional is the segment count for "<service>.<region>" (regional).
	partsStandardRegional = 2
	// s3GlobalRegion is the canonical SigV4 region for global S3 endpoints.
	s3GlobalRegion = "us-east-1"
)

// ParseHost classifies host. It rejects IP literals and non-ASCII / IDN hosts up
// front via cloudauth.IsIPLiteral + cloudauth.NormalizeHost (which also lower-cases
// and port-strips), then returns the structured ParsedHost on a successful match,
// or ErrHostPattern wrapped with descriptive context on failure. Pure: no I/O.
func ParseHost(host string) (ParsedHost, error) {
	if host == "" {
		return ParsedHost{}, fmt.Errorf("%w: host is empty", ErrHostPattern)
	}
	if cloudauth.IsIPLiteral(host) {
		return ParsedHost{}, fmt.Errorf("%w: %q (IP literal)", ErrHostPattern, host)
	}
	norm, err := cloudauth.NormalizeHost(host)
	if err != nil {
		return ParsedHost{}, fmt.Errorf("%w: %w", ErrHostPattern, err)
	}
	host = norm
	if host == "localhost" {
		return ParsedHost{}, fmt.Errorf("%w: %q (localhost)", ErrHostPattern, host)
	}

	if isVPCEndpoint(host) {
		return ParsedHost{}, fmt.Errorf(
			"%w: %q (VPC endpoint — host alone does not identify target service)",
			ErrHostPattern, host)
	}

	// Account-scoped S3 Control must be matched before the partition branches so
	// the China form (…amazonaws.com.cn) is not folded into the generic parser.
	if parsed, ok := tryS3Control(host); ok {
		return parsed, nil
	}

	// Account-prefixed S3 access points (always virtual-hosted) resolve to the
	// ordinary "s3" prefix; matched before the partition branches so the China
	// form is not folded into the generic parser.
	if parsed, ok := tryS3AccessPoint(host); ok {
		return parsed, nil
	}

	if strings.HasSuffix(host, ".amazonaws.com.cn") {
		return parseStandardPartition(host, ".amazonaws.com.cn")
	}
	if strings.HasSuffix(host, ".us-gov.amazonaws.com") {
		return parseStandardPartition(host, ".us-gov.amazonaws.com")
	}

	if parsed, ok := tryS3Patterns(host); ok {
		return parsed, nil
	}

	if parsed, ok := tryLambdaURL(host); ok {
		return parsed, nil
	}
	if parsed, ok := tryDualstackAPIAWS(host); ok {
		return parsed, nil
	}
	if parsed, ok := tryS3Dualstack(host); ok {
		return parsed, nil
	}
	if parsed, ok := tryInfixService(host, ".execute-api.", "execute-api"); ok {
		return parsed, nil
	}
	if parsed, ok := tryOpenSearch(host); ok {
		return parsed, nil
	}
	if parsed, ok := tryInfixService(host, ".iot.", "iotdata"); ok {
		return parsed, nil
	}
	if parsed, ok := tryFIPS(host); ok {
		return parsed, nil
	}

	const standardSuffix = ".amazonaws.com"
	if strings.HasSuffix(host, standardSuffix) {
		return parseStandardPartition(host, standardSuffix)
	}

	return ParsedHost{}, fmt.Errorf("%w: %q", ErrHostPattern, host)
}

// partitionForSuffix maps an amazonaws.com host suffix to its AWS partition.
func partitionForSuffix(suffix string) Partition {
	switch suffix {
	case ".amazonaws.com.cn":
		return PartitionChina
	case ".us-gov.amazonaws.com":
		return PartitionGovCloud
	default:
		return PartitionStandard
	}
}

// parseStandardPartition handles hosts ending in .amazonaws.com,
// .amazonaws.com.cn, or .us-gov.amazonaws.com — the suffix is supplied by the
// caller.
func parseStandardPartition(host, suffix string) (ParsedHost, error) {
	body := strings.TrimSuffix(host, suffix)
	body = strings.TrimPrefix(body, ".") // safety
	if body == "" {
		return ParsedHost{}, fmt.Errorf("%w: %q (empty prefix)", ErrHostPattern, host)
	}

	part := partitionForSuffix(suffix)
	parts := strings.Split(body, ".")
	if len(parts) == partsGlobalService {
		// <service>.amazonaws.com → global service.
		return ParsedHost{Service: parts[0], Region: "", Partition: part}, nil
	}
	// <label…>.<region>.amazonaws.com → multi-label endpoint prefix plus the
	// trailing region label (e.g. api.ecr, runtime.sagemaker, streams.dynamodb).
	// Unknown prefixes are rejected downstream by the model archive index, not here.
	region := parts[len(parts)-1]
	service := strings.Join(parts[:len(parts)-1], ".")
	return ParsedHost{Service: service, Region: region, Partition: part}, nil
}

// tryS3Patterns matches the three S3-specific host shapes that don't follow
// the generic <service>.<region>.amazonaws.com pattern. Ordering matters: the
// hyphenated form is checked before the virtual-hosted form because
// "s3-us-west-2" can be misparsed as a bucket name.
func tryS3Patterns(host string) (ParsedHost, bool) {
	const stdSuffix = ".amazonaws.com"

	// s3-<region>.amazonaws.com (legacy hyphenated path-style).
	if body, ok := strings.CutSuffix(host, stdSuffix); ok {
		if strings.HasPrefix(body, "s3-") && !strings.Contains(body, ".") {
			return ParsedHost{Service: "s3", Region: strings.TrimPrefix(body, "s3-")}, true
		}
	}

	// Path-style global: s3.amazonaws.com → us-east-1 path-style.
	if host == "s3.amazonaws.com" {
		return ParsedHost{Service: "s3", Region: s3GlobalRegion}, true
	}

	// Path-style regional: s3.<region>.amazonaws.com.
	if strings.HasPrefix(host, "s3.") && strings.HasSuffix(host, stdSuffix) {
		body := strings.TrimSuffix(strings.TrimPrefix(host, "s3."), stdSuffix)
		if body != "" && !strings.Contains(body, ".") {
			return ParsedHost{Service: "s3", Region: body}, true
		}
	}

	// Virtual-hosted global: <bucket>.s3.amazonaws.com → us-east-1.
	if strings.HasSuffix(host, ".s3.amazonaws.com") {
		return ParsedHost{Service: "s3", Region: s3GlobalRegion, BucketInHost: true}, true
	}

	// Virtual-hosted regional: <bucket>.s3.<region>.amazonaws.com.
	if strings.Contains(host, ".s3.") && strings.HasSuffix(host, stdSuffix) {
		if _, afterS3Dot, ok := strings.Cut(host, ".s3."); ok {
			if region, suffixOK := strings.CutSuffix(afterS3Dot, stdSuffix); suffixOK &&
				region != "" && !strings.Contains(region, ".") {
				return ParsedHost{Service: "s3", Region: region, BucketInHost: true}, true
			}
		}
	}

	return ParsedHost{}, false
}

func tryLambdaURL(host string) (ParsedHost, bool) {
	const suffix = ".on.aws"
	body, ok := strings.CutSuffix(host, suffix)
	if !ok {
		return ParsedHost{}, false
	}
	// expected shape: <fn-id>.lambda-url.<region>.
	_, region, ok := strings.Cut(body, ".lambda-url.")
	if !ok || region == "" || strings.Contains(region, ".") {
		return ParsedHost{}, false
	}
	return ParsedHost{Service: "lambda", Region: region}, true
}

func tryDualstackAPIAWS(host string) (ParsedHost, bool) {
	const suffix = ".api.aws"
	body, ok := strings.CutSuffix(host, suffix)
	if !ok {
		return ParsedHost{}, false
	}
	parts := strings.Split(body, ".")
	if len(parts) != partsStandardRegional {
		return ParsedHost{}, false
	}
	return ParsedHost{Service: parts[0], Region: parts[1]}, true
}

func tryS3Dualstack(host string) (ParsedHost, bool) {
	const prefix = "s3.dualstack."
	after, ok := strings.CutPrefix(host, prefix)
	if !ok {
		return ParsedHost{}, false
	}
	region, ok := strings.CutSuffix(after, ".amazonaws.com")
	if !ok || region == "" || strings.Contains(region, ".") {
		return ParsedHost{}, false
	}
	return ParsedHost{Service: "s3", Region: region}, true
}

// tryInfixService matches hosts that carry an opaque leading label and identify
// their service through an infix marker (".execute-api." → execute-api,
// ".iot." → iotdata): <opaque>[.…]<marker><region>.amazonaws.com.
func tryInfixService(host, marker, svc string) (ParsedHost, bool) {
	_, after, ok := strings.Cut(host, marker)
	if !ok {
		return ParsedHost{}, false
	}
	region, ok := strings.CutSuffix(after, ".amazonaws.com")
	if !ok || region == "" || strings.Contains(region, ".") {
		return ParsedHost{}, false
	}
	return ParsedHost{Service: svc, Region: region}, true
}

func tryOpenSearch(host string) (ParsedHost, bool) {
	const suffix = ".es.amazonaws.com"
	body, ok := strings.CutSuffix(host, suffix)
	if !ok {
		return ParsedHost{}, false
	}
	// body = <domain>.<region>; we want the LAST label as region.
	lastDot := strings.LastIndex(body, ".")
	if lastDot <= 0 {
		return ParsedHost{}, false
	}
	region := body[lastDot+1:]
	if region == "" || strings.Contains(region, ".") {
		return ParsedHost{}, false
	}
	return ParsedHost{Service: "es", Region: region}, true
}

func tryFIPS(host string) (ParsedHost, bool) {
	const suffix = ".amazonaws.com"
	body, ok := strings.CutSuffix(host, suffix)
	if !ok {
		return ParsedHost{}, false
	}
	svc, rest, ok := strings.Cut(body, "-fips")
	if !ok || svc == "" {
		return ParsedHost{}, false
	}
	switch {
	case rest == "":
		return ParsedHost{Service: svc, Region: ""}, true
	case strings.HasPrefix(rest, "."):
		region := rest[1:]
		if region != "" && !strings.Contains(region, ".") {
			return ParsedHost{Service: svc, Region: region}, true
		}
	}
	return ParsedHost{}, false
}

// isVPCEndpoint reports whether host's leading label starts with "vpce-".
// VPC endpoints share the .amazonaws.com suffix with public endpoints but
// the host alone does not identify the target service (it's an opaque
// endpoint ID), so they must be rejected. Documented as a v1 limit.
func isVPCEndpoint(host string) bool {
	return strings.HasPrefix(host, "vpce-")
}

// matchAccountScopedS3 matches the shared account-prefixed S3 host shape
//
//	<leading>.{infix}[-fips][.dualstack].{region}.amazonaws.com[.cn]
//
// returning (region, true) on a match. leadingOK validates the leading label
// (exactly the account id for S3 Control; the {name}-{account} alias for access
// points). The -fips variant is a prefix superset of the base infix, so it is
// checked first. Pure: no I/O.
func matchAccountScopedS3(host, infix string, leadingOK func(string) bool) (string, bool) {
	leading, rest, ok := strings.Cut(host, ".")
	if !ok || !leadingOK(leading) {
		return "", false
	}
	var body string
	var matched bool
	for _, suffix := range []string{".amazonaws.com.cn", ".amazonaws.com"} {
		if b, cut := strings.CutSuffix(rest, suffix); cut {
			body, matched = b, true
			break
		}
	}
	if !matched {
		return "", false
	}
	// body == {infix}[-fips][.dualstack].{region}. The -fips variant is a prefix
	// superset of {infix}, so it is checked first.
	for _, prefix := range []string{infix + "-fips", infix} {
		after, cut := strings.CutPrefix(body, prefix)
		if !cut {
			continue
		}
		region, hasDot := strings.CutPrefix(after, ".")
		if !hasDot {
			return "", false
		}
		region = strings.TrimPrefix(region, "dualstack.")
		if region == "" || strings.Contains(region, ".") {
			return "", false
		}
		return region, true
	}
	return "", false
}

// tryS3Control matches account-scoped S3 Control control-plane hosts, which
// carry a leading 12-digit {AccountId} label the generic rule would otherwise
// fold into the endpoint prefix:
//
//	{AccountId}.s3-control[-fips][.dualstack].{region}.amazonaws.com[.cn]
//
// It returns the canonical endpoint prefix "s3-control" and the trailing region
// so the model archive resolves the S3 Control model. The leading label must be
// a valid AWS account id, so non-account "s3-control.{region}…" hosts decline
// here and parse via the generic rule.
func tryS3Control(host string) (ParsedHost, bool) {
	if region, ok := matchAccountScopedS3(host, "s3-control", isAWSAccountID); ok {
		return ParsedHost{Service: "s3-control", Region: region}, true
	}
	return ParsedHost{}, false
}

// tryS3AccessPoint matches account-prefixed S3 access-point data-plane hosts,
// which carry a leading {name}-{AccountId} alias label the generic rule would
// otherwise fold into the endpoint prefix:
//
//	{name}-{AccountId}.s3-accesspoint[-fips][.dualstack].{region}.amazonaws.com[.cn]
//
// Access points are ordinary S3 (they sign as "s3" and use s3:* IAM actions, only
// the resource ARN differs), so this returns the plain "s3" endpoint prefix; the
// unchanged signing/action path resolves the rest. A host whose leading label is
// not a {name}-{12-digit-account} alias declines here and parses via the generic
// rule (which resolves no model and denies — fail closed).
func tryS3AccessPoint(host string) (ParsedHost, bool) {
	if region, ok := matchAccountScopedS3(host, "s3-accesspoint", hasAccountSuffix); ok {
		return ParsedHost{Service: "s3", Region: region, BucketInHost: true}, true
	}
	return ParsedHost{}, false
}

// hasAccountSuffix reports whether label is an access-point alias label of the
// form {name}-{AccountId}: a non-empty name, a hyphen, then exactly 12 digits.
// LastIndex handles names that themselves contain hyphens (e.g. "my-ap-…").
func hasAccountSuffix(label string) bool {
	i := strings.LastIndex(label, "-")
	if i <= 0 { // no hyphen, or empty name before it.
		return false
	}
	return isAWSAccountID(label[i+1:])
}

// isAWSAccountID reports whether s is a literal AWS account id: exactly 12 ASCII
// digits.
func isAWSAccountID(s string) bool {
	const awsAccountIDLen = 12
	if len(s) != awsAccountIDLen {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ErrHostClaimMismatch is returned when ParsedHost does not match the
// (service, region) declared via the aws_auth tool args.
var ErrHostClaimMismatch = errors.New("aws_hardening: host does not match aws_auth claim")

// serviceClaimEqual compares an aws_auth.service claim to the host's endpoint
// prefix case- and hyphen-insensitively. The same AWS service is spelled
// differently across the endpoint prefix ("s3-control"), the SDK id
// ("s3control"), and the signing name ("s3"); the claim is only a host↔claim
// consistency hint (action authorization and SigV4 signing both derive from the
// host, never the claim), so accepting an alternate spelling of the host's own
// service cannot broaden access. The signing-name spelling is reconciled
// separately by awsProvider.AuthorizesHost.
func serviceClaimEqual(host, claim string) bool {
	return dehyphenLower(host) == dehyphenLower(claim)
}

// dehyphenLower lowercases s and removes ASCII hyphens.
func dehyphenLower(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "-", "")
}

// Verify enforces that the ParsedHost is consistent with the (service, region)
// claim the LLM provided via aws_auth. Pure: no I/O.
func Verify(p ParsedHost, claimedService, claimedRegion string) error {
	if !serviceClaimEqual(p.Service, claimedService) {
		return fmt.Errorf("%w: host implies service %q but aws_auth.service is %q",
			ErrHostClaimMismatch, p.Service, claimedService)
	}
	if claimedRegion == "" {
		return nil // Region derived from the pinned host; nothing to cross-check.
	}
	if p.Region == "" {
		// Global service — accept canonical region claims only.
		switch strings.ToLower(claimedRegion) {
		case "", "aws-global", "us-east-1", "us-gov-west-1", "cn-north-1":
			return nil
		default:
			return fmt.Errorf("%w: global service %q got non-canonical region claim %q",
				ErrHostClaimMismatch, p.Service, claimedRegion)
		}
	}
	if !strings.EqualFold(p.Region, claimedRegion) {
		return fmt.Errorf("%w: host implies region %q but aws_auth.region is %q",
			ErrHostClaimMismatch, p.Region, claimedRegion)
	}
	return nil
}
