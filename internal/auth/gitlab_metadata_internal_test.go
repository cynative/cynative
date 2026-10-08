package auth

import (
	"testing"
)

func TestParseGitLabMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		raw        []byte
		wantVer    string
		wantEE     bool
		wantErr    bool
		errMessage string
	}{
		{
			name:    "valid EE metadata",
			raw:     []byte(`{"version":"18.9.0-ee","revision":"abc123","enterprise":true}`),
			wantVer: "18.9.0-ee",
			wantEE:  true,
			wantErr: false,
		},
		{
			name:    "valid CE metadata",
			raw:     []byte(`{"version":"18.10.0","revision":"def456","enterprise":false}`),
			wantVer: "18.10.0",
			wantEE:  false,
			wantErr: false,
		},
		{
			name:    "pre version",
			raw:     []byte(`{"version":"19.5.0-pre","revision":"xyz789","enterprise":true}`),
			wantVer: "19.5.0-pre",
			wantEE:  true,
			wantErr: false,
		},
		{
			name:       "missing version",
			raw:        []byte(`{"revision":"abc123","enterprise":true}`),
			wantVer:    "",
			wantEE:     false,
			wantErr:    true,
			errMessage: "metadata response has no version",
		},
		{
			name:       "empty version",
			raw:        []byte(`{"version":"","revision":"abc123","enterprise":true}`),
			wantVer:    "",
			wantEE:     false,
			wantErr:    true,
			errMessage: "metadata response has no version",
		},
		{
			name:       "invalid JSON",
			raw:        []byte(`not json`),
			wantVer:    "",
			wantEE:     false,
			wantErr:    true,
			errMessage: "invalid metadata JSON",
		},
		{
			name:       "empty response",
			raw:        []byte(``),
			wantVer:    "",
			wantEE:     false,
			wantErr:    true,
			errMessage: "invalid metadata JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			md, err := parseGitLabMetadata(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseGitLabMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseGitLabMetadata() expected error containing %q", tt.errMessage)
				}

				return
			}
			if md.version != tt.wantVer {
				t.Errorf("parseGitLabMetadata() version = %q, want %q", md.version, tt.wantVer)
			}
			if md.enterprise != tt.wantEE {
				t.Errorf("parseGitLabMetadata() enterprise = %v, want %v", md.enterprise, tt.wantEE)
			}
		})
	}
}
