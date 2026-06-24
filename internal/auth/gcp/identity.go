// Package gcp implements GCP-specific hardening that layers on top of the
// generic auth.Provider contract.
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// quotaProjectIDFromJSON extracts quota_project_id from an ADC credential JSON
// (e.g. a gcloud authorized_user file). Returns "" when absent or unparseable.
// Used as a project fallback when Credentials.ProjectID is empty.
func quotaProjectIDFromJSON(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var hdr struct {
		QuotaProjectID string `json:"quota_project_id"`
	}
	if json.Unmarshal(raw, &hdr) != nil {
		return ""
	}
	return hdr.QuotaProjectID
}

func credTypeFromJSON(raw []byte) string {
	if len(raw) == 0 {
		return "" // Metadata / attached-SA case.
	}
	var hdr struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &hdr) != nil {
		return ""
	}
	return hdr.Type
}

// identityProber resolves the caller's identity facts: principal email and
// project ID. Real impl (FindDefaultCredentials + tokeninfo + metadata) in
// identity_shell.go.
type identityProber interface {
	Probe(ctx context.Context) (principal, projectID string, err error)
}

// metadataProber probes the GCE metadata server. Real impl wraps
// cloud.google.com/go/compute/metadata in identity_shell.go; faked in tests.
type metadataProber interface {
	OnGCE() bool
	Email(ctx context.Context) (string, error)     // wraps metadata.EmailWithContext(ctx, "default").
	ProjectID(ctx context.Context) (string, error) // wraps metadata.ProjectIDWithContext(ctx).
}

// credFacts is the credential-resolution result the pure identity logic consumes.
// It is the seam between FindDefaultCredentials/ProbeTokeninfo (shell) and the
// decision logic (core).
type credFacts struct {
	credJSON  []byte // creds.JSON.
	projectID string // creds.ProjectID (may be empty).
}

// tokeninfoProbe resolves the ADC principal email (shell wraps ProbeTokeninfo).
type tokeninfoProbe func(ctx context.Context) (string, error)

// resolveIdentity applies the ADC identity decision logic: derive the credential
// type, fall back to quota_project_id when creds.ProjectID is empty, and — for the
// metadata/attached-SA case (credType=="" && OnGCE) — prefer the metadata email
// (and metadata project when still empty), otherwise probe tokeninfo. Pure; the
// two I/O dependencies are injected via md and tokeninfo.
func resolveIdentity(
	ctx context.Context, facts credFacts, md metadataProber, tokeninfo tokeninfoProbe,
) (string, string, error) {
	credType := credTypeFromJSON(facts.credJSON)
	projectID := facts.projectID
	if projectID == "" {
		// gcloud authorized_user ADC files carry no project_id; fall back to the
		// quota_project_id the credential JSON records (the active gcloud project).
		projectID = quotaProjectIDFromJSON(facts.credJSON)
	}

	if credType == "" && md.OnGCE() {
		if email, merr := md.Email(ctx); merr == nil {
			if projectID == "" {
				projectID, _ = md.ProjectID(ctx)
			}
			return email, projectID, nil
		}
	}
	principal, perr := tokeninfo(ctx)
	if perr != nil {
		return "", "", fmt.Errorf("tokeninfo principal probe: %w", perr)
	}
	return principal, projectID, nil
}

// principalFromTokeninfo parses a tokeninfo response body and status into the
// principal: the email if present, else the sub. Non-200 → error.
func principalFromTokeninfo(body []byte, statusCode int) (string, error) {
	if statusCode != http.StatusOK {
		return "", fmt.Errorf("tokeninfo status %d", statusCode)
	}
	var info struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", err
	}
	if info.Email != "" {
		return info.Email, nil
	}
	return info.Sub, nil
}
