package auth

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrInvalidClusterIdentifier reports a managed-cluster identifier outside its vendor's naming rules. The identifiers
// reach a control-plane SDK call that resolves the cluster (GKE clusters.get, EKS DescribeCluster, AKS
// ListClusterUserCredentials) with the connector's credentials, and some SDKs carry a slash or a dot segment into the
// request path, so a value is checked before any resolution call.
var ErrInvalidClusterIdentifier = errors.New("invalid managed cluster identifier")

// The grammars are conservative allowlists taken from the vendors' naming rules: what they accept is a subset of what
// the vendor allows, and every accepted value reaches the SDK's request path unchanged.
var (
	// GCP project ID: 6 to 30 lowercase letters, digits or hyphens, starting with a letter and not ending with a
	// hyphen. Legacy domain-scoped ids (example.com:project) are not accepted.
	gcpProjectID = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	// GCP project number.
	gcpProjectNumber = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	// GCP region (us-central1) or zone (us-central1-a).
	gcpLocation = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+(-[a-z])?$`)
	// GKE cluster name: up to 40 lowercase letters, digits or hyphens, starting with a letter and not ending with a
	// hyphen.
	gkeClusterName = regexp.MustCompile(`^[a-z](?:[-a-z0-9]{0,38}[a-z0-9])?$`)
	// EKS cluster name: 1 to 100 letters, digits, hyphens or underscores, starting with a letter or digit.
	eksClusterName = regexp.MustCompile(`^[0-9A-Za-z][A-Za-z0-9_-]{0,99}$`)
	// AWS regions of the three partitions the AWS gate supports.
	awsChinaRegion    = regexp.MustCompile(`^cn-[a-z]+-[0-9]+$`)
	awsGovCloudRegion = regexp.MustCompile(`^us-gov-[a-z]+-[0-9]+$`)
	awsStandardRegion = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[0-9]+$`)
	// Azure subscription ID: a GUID.
	azureSubscriptionID = regexp.MustCompile(`^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`)
	// Azure resource group: 1 to 90 letters, digits, underscores, parentheses, hyphens or periods, not ending with a
	// period (which also rules out "." and "..").
	azureResourceGroup = regexp.MustCompile(`^[\p{L}\p{Nd}_().-]{0,89}[\p{L}\p{Nd}_()-]$`)
	// AKS cluster name: 1 to 63 letters, digits, hyphens or underscores, starting and ending with a letter or digit.
	aksClusterName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$`)
)

// checkIdentifier returns ErrInvalidClusterIdentifier naming field when value does not match.
func checkIdentifier(field, value string, accept ...*regexp.Regexp) error {
	for _, re := range accept {
		if re.MatchString(value) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is outside the vendor's naming rules", ErrInvalidClusterIdentifier, field)
}

// awsPartition names the partition of a region the AWS gate supports, or "" for any other value. A region naming a
// FIPS variant is never accepted: the SDK rewrites "fips-", "-fips-" and "-fips" out of a region before it resolves
// the partition (MapFIPSRegion), so the region it resolves would not be the one checked here.
func awsPartition(region string) string {
	switch {
	case strings.Contains(region, "fips"):
		return ""
	case awsChinaRegion.MatchString(region):
		return "aws-cn"
	case awsGovCloudRegion.MatchString(region):
		return "aws-us-gov"
	case awsStandardRegion.MatchString(region):
		return "aws"
	}
	return ""
}

// checkEKSRegionPartition keeps a requested region in the configured region's partition, so the model cannot send
// the signed DescribeCluster request to another partition's endpoint. An unset configured region counts as the
// standard partition, the SDK default; a configured region outside the three supported partitions admits no
// model-supplied region at all, since its partition cannot be compared.
func checkEKSRegionPartition(requested, configured string) error {
	if requested == "" {
		return nil
	}
	want := "aws"
	if configured != "" {
		want = awsPartition(configured)
	}
	if want == "" {
		return fmt.Errorf("%w: eks_auth.region cannot be overridden when the configured region is outside the "+
			"supported AWS partitions", ErrInvalidClusterIdentifier)
	}
	if awsPartition(requested) != want {
		return fmt.Errorf("%w: eks_auth.region must be a region of the configured partition (%s)",
			ErrInvalidClusterIdentifier, want)
	}
	return nil
}
