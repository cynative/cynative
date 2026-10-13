package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestParseGitLabMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		raw        []byte
		wantVer    string
		wantErr    bool
		errMessage string
	}{
		{
			name:    "valid EE metadata",
			raw:     []byte(`{"version":"18.9.0-ee","revision":"abc123","enterprise":true}`),
			wantVer: "18.9.0-ee",
			wantErr: false,
		},
		{
			name:    "valid CE metadata",
			raw:     []byte(`{"version":"18.10.0","revision":"def456","enterprise":false}`),
			wantVer: "18.10.0",
			wantErr: false,
		},
		{
			name:    "pre version",
			raw:     []byte(`{"version":"19.5.0-pre","revision":"xyz789","enterprise":true}`),
			wantVer: "19.5.0-pre",
			wantErr: false,
		},
		{
			name:       "missing version",
			raw:        []byte(`{"revision":"abc123","enterprise":true}`),
			wantVer:    "",
			wantErr:    true,
			errMessage: "metadata response has no version",
		},
		{
			name:       "empty version",
			raw:        []byte(`{"version":"","revision":"abc123","enterprise":true}`),
			wantVer:    "",
			wantErr:    true,
			errMessage: "metadata response has no version",
		},
		{
			name:       "invalid JSON",
			raw:        []byte(`not json`),
			wantVer:    "",
			wantErr:    true,
			errMessage: "invalid metadata JSON",
		},
		{
			name:       "empty response",
			raw:        []byte(``),
			wantVer:    "",
			wantErr:    true,
			errMessage: "invalid metadata JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			version, err := parseGitLabMetadata(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseGitLabMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if !errors.Is(err, errGitLabMetadata) || !strings.Contains(err.Error(), tt.errMessage) {
					t.Errorf(
						"parseGitLabMetadata() error = %v, want errGitLabMetadata containing %q",
						err,
						tt.errMessage,
					)
				}

				return
			}
			if version != tt.wantVer {
				t.Errorf("parseGitLabMetadata() version = %q, want %q", version, tt.wantVer)
			}
		})
	}
}
