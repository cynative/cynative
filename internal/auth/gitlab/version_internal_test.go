package gitlab

import (
	"testing"
)

func TestParseVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		want    *parsedVersion
		wantOK  bool
	}{
		{
			name:    "valid EE version",
			version: "18.9.0-ee",
			want:    &parsedVersion{major: 18, minor: 9, patch: 0, suffix: "-ee"},
			wantOK:  true,
		},
		{
			name:    "valid plain version",
			version: "18.10.0",
			want:    &parsedVersion{major: 18, minor: 10, patch: 0, suffix: ""},
			wantOK:  true,
		},
		{
			name:    "valid pre version",
			version: "19.5.0-pre",
			want:    &parsedVersion{major: 19, minor: 5, patch: 0, suffix: "-pre"},
			wantOK:  true,
		},
		{
			name:    "valid high version",
			version: "9999.9999.9999-ee",
			want:    &parsedVersion{major: 9999, minor: 9999, patch: 9999, suffix: "-ee"},
			wantOK:  true,
		},
		{
			name:    "leading zeros rejected",
			version: "018.9.0-ee",
			want:    nil,
			wantOK:  false,
		},
		{
			name:    "leading zeros in minor rejected",
			version: "18.09.0-ee",
			want:    nil,
			wantOK:  false,
		},
		{
			name:    "leading zeros in patch rejected",
			version: "18.9.00-ee",
			want:    nil,
			wantOK:  false,
		},
		{
			name:    "too many digits rejected",
			version: "10000.9.0-ee",
			want:    nil,
			wantOK:  false,
		},
		{
			name:    "RC version rejected",
			version: "18.9.0-rc42-ee",
			want:    nil,
			wantOK:  false,
		},
		{
			name:    "custom suffix rejected",
			version: "18.9.0-custom",
			want:    nil,
			wantOK:  false,
		},
		{
			name:    "empty version rejected",
			version: "",
			want:    nil,
			wantOK:  false,
		},
		{
			name:    "malformed version",
			version: "not.a.version",
			want:    nil,
			wantOK:  false,
		},
		{
			name:    "missing patch",
			version: "18.9",
			want:    nil,
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := parseVersion(tt.version)
			if ok != tt.wantOK {
				t.Errorf("parseVersion() ok = %v, want %v", ok, tt.wantOK)
				return
			}
			if !ok {
				return
			}
			if got.major != tt.want.major || got.minor != tt.want.minor ||
				got.patch != tt.want.patch || got.suffix != tt.want.suffix {
				t.Errorf("parseVersion() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestClassifyVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		version    string
		hostname   string
		port       string
		wantClass  VersionClassification
		wantRef    string
		wantReason string
	}{
		{
			name:       "below floor major 17",
			version:    "17.12.0-ee",
			hostname:   "selfmanaged.example.com",
			port:       "443",
			wantClass:  VersionBelowFloor,
			wantRef:    "",
			wantReason: `GitLab 18.9 or later required (instance reports "17.12.0-ee")`,
		},
		{
			name:       "below floor 18.8.0",
			version:    "18.8.0-ee",
			hostname:   "selfmanaged.example.com",
			port:       "443",
			wantClass:  VersionBelowFloor,
			wantRef:    "",
			wantReason: `GitLab 18.9 or later required (instance reports "18.8.0-ee")`,
		},
		{
			name:       "below floor pre on gitlab.com",
			version:    "18.8.0-pre",
			hostname:   "gitlab.com",
			port:       "443",
			wantClass:  VersionBelowFloor,
			wantRef:    "",
			wantReason: `GitLab 18.9 or later required (instance reports "18.8.0-pre")`,
		},
		{
			name:       "below floor pre on a self-managed host",
			version:    "18.8.0-pre",
			hostname:   "selfmanaged.example.com",
			port:       "443",
			wantClass:  VersionBelowFloor,
			wantRef:    "",
			wantReason: `GitLab 18.9 or later required (instance reports "18.8.0-pre")`,
		},
		{
			name:       "floor exactly 18.9.0",
			version:    "18.9.0-ee",
			hostname:   "selfmanaged.example.com",
			port:       "443",
			wantClass:  VersionTag,
			wantRef:    "v18.9.0-ee",
			wantReason: "",
		},
		{
			name:       "18.10.0",
			version:    "18.10.0",
			hostname:   "selfmanaged.example.com",
			port:       "443",
			wantClass:  VersionTag,
			wantRef:    "v18.10.0-ee",
			wantReason: "",
		},
		{
			name:       "19.0.0 above floor",
			version:    "19.0.0-ee",
			hostname:   "selfmanaged.example.com",
			port:       "443",
			wantClass:  VersionTag,
			wantRef:    "v19.0.0-ee",
			wantReason: "",
		},
		{
			name:       "pre on gitlab.com",
			version:    "19.5.0-pre",
			hostname:   "gitlab.com",
			port:       "443",
			wantClass:  VersionMaster,
			wantRef:    "master",
			wantReason: "",
		},
		{
			name:       "pre on GitLab.com (case insensitive)",
			version:    "19.5.0-pre",
			hostname:   "GitLab.com",
			port:       "443",
			wantClass:  VersionMaster,
			wantRef:    "master",
			wantReason: "",
		},
		{
			name:       "pre on gitlab.com explicit port 443",
			version:    "19.5.0-pre",
			hostname:   "gitlab.com",
			port:       "443",
			wantClass:  VersionMaster,
			wantRef:    "master",
			wantReason: "",
		},
		{
			name:       "pre on self-managed",
			version:    "19.5.0-pre",
			hostname:   "selfmanaged.example.com",
			port:       "443",
			wantClass:  VersionUnknown,
			wantRef:    "",
			wantReason: `instance reports development version "19.5.0-pre" (only gitlab.com's development builds are supported)`,
		},
		{
			name:       "pre on gitlab.com non-443 port",
			version:    "19.5.0-pre",
			hostname:   "gitlab.com",
			port:       "8443",
			wantClass:  VersionUnknown,
			wantRef:    "",
			wantReason: `instance reports development version "19.5.0-pre" (only gitlab.com's development builds are supported)`,
		},
		{
			name:       "RC version",
			version:    "18.9.0-rc42-ee",
			hostname:   "selfmanaged.example.com",
			port:       "443",
			wantClass:  VersionUnknown,
			wantRef:    "",
			wantReason: `instance reports unrecognized version "18.9.0-rc42-ee"`,
		},
		{
			name:       "custom version",
			version:    "18.9.0-custom",
			hostname:   "selfmanaged.example.com",
			port:       "443",
			wantClass:  VersionUnknown,
			wantRef:    "",
			wantReason: `instance reports unrecognized version "18.9.0-custom"`,
		},
		{
			name:       "unparseable version",
			version:    "not-a-version",
			hostname:   "selfmanaged.example.com",
			port:       "443",
			wantClass:  VersionUnknown,
			wantRef:    "",
			wantReason: `instance reports unrecognized version "not-a-version"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotClass, gotRef, gotReason := ClassifyVersion(tt.version, tt.hostname, tt.port)
			if gotClass != tt.wantClass {
				t.Errorf("ClassifyVersion() class = %v, want %v", gotClass, tt.wantClass)
			}
			if gotRef != tt.wantRef {
				t.Errorf("ClassifyVersion() ref = %q, want %q", gotRef, tt.wantRef)
			}
			if gotReason != tt.wantReason {
				t.Errorf("ClassifyVersion() reason = %q, want %q", gotReason, tt.wantReason)
			}
		})
	}
}
