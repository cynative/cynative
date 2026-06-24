package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Identity carries the resolved caller identity facts: the display principal and
// the home tenant GUID. Resolved from the operator's ARM token claims.
type Identity struct {
	Principal string
	TenantID  string
}

// identityProber resolves the caller's Identity from the home-tenant-authority
// ARM token. Real impl (token acquisition + DecodeClaims) in identity_shell.go.
type identityProber interface {
	Probe(ctx context.Context) (Identity, error)
}

// jwtSegments is the required number of dot-separated segments in a JWT.
const jwtSegments = 3

// DecodeClaims decodes a JWT's claims (second) segment and returns the tenant
// id (tid) and a display principal. No signature verification is performed —
// this is the operator's own token, parsed only for its claims. The principal
// prefers upn, then preferred_username, then unique_name, then appid (service
// principals), then oid as a last resort.
func DecodeClaims(jwt string) (string, string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != jwtSegments {
		return "", "", fmt.Errorf("%w: malformed JWT (want 3 segments, got %d)", ErrTenantUnresolved, len(parts))
	}
	raw, derr := decodeSegment(parts[1])
	if derr != nil {
		return "", "", fmt.Errorf("%w: decode claims segment: %w", ErrTenantUnresolved, derr)
	}
	var c struct {
		TID               string `json:"tid"`
		OID               string `json:"oid"`
		UPN               string `json:"upn"`
		PreferredUsername string `json:"preferred_username"`
		UniqueName        string `json:"unique_name"`
		AppID             string `json:"appid"`
	}
	if uerr := json.Unmarshal(raw, &c); uerr != nil {
		return "", "", fmt.Errorf("%w: unmarshal claims: %w", ErrTenantUnresolved, uerr)
	}
	return c.TID, firstNonEmpty(c.UPN, c.PreferredUsername, c.UniqueName, c.AppID, c.OID), nil
}

// decodeSegment decodes a JWT segment tolerant of both raw-url (unpadded) and
// standard (padded) base64.
func decodeSegment(seg string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(seg); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(seg)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// probeIdentity acquires the home-tenant ARM token for the given scope via token,
// decodes its claims into an Identity, and fails closed if the token has no
// resolvable tenant. The scope is the resolved cloud's ARM audience, so the
// identity probe targets the same cloud as the rest of the connector.
func probeIdentity(ctx context.Context, token tokenFunc, scope string) (Identity, error) {
	jwt, err := token(ctx, scope)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %w", ErrTenantUnresolved, err)
	}
	tid, principal, err := DecodeClaims(jwt)
	if err != nil {
		return Identity{}, err
	}
	if tid == "" {
		return Identity{}, fmt.Errorf("%w: token carries no tid claim", ErrTenantUnresolved)
	}
	return Identity{Principal: principal, TenantID: tid}, nil
}
