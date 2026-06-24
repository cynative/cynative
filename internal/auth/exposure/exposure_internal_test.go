package exposure

import (
	"errors"
	"testing"
)

func TestParseLevel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    Level
		wantErr bool
	}{
		{"none", LevelNone, false},
		{"read", LevelRead, false},
		{"write", LevelWrite, false},
		{"", LevelNone, true},
		{"admin", LevelNone, true},
		{"Read", LevelNone, true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseLevel(c.in)
			if c.wantErr {
				if !errors.Is(err, ErrInvalidLevel) {
					t.Fatalf("ParseLevel(%q) err=%v want ErrInvalidLevel", c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseLevel(%q) err %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("ParseLevel(%q)=%v want %v", c.in, got, c.want)
			}
		})
	}
}

func TestLevelName_AllBranches(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		l    Level
		want string
	}{
		{"none", LevelNone, "none"},
		{"read", LevelRead, "read"},
		{"write", LevelWrite, "write"},
		{"invalid", Level(99), "none"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := LevelName(tt.l); got != tt.want {
				t.Errorf("LevelName(%v)=%q want %q", tt.l, got, tt.want)
			}
		})
	}
}

func TestAllows(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		ceiling, required Level
		want              bool
	}{
		{LevelWrite, LevelWrite, true},
		{LevelWrite, LevelRead, true},
		{LevelRead, LevelRead, true},
		{LevelRead, LevelWrite, false},
		{LevelNone, LevelRead, false},
		{LevelNone, LevelNone, true},
	} {
		if got := Allows(c.ceiling, c.required); got != c.want {
			t.Errorf("Allows(%v,%v)=%v want %v", c.ceiling, c.required, got, c.want)
		}
	}
}

func TestMergeExposure_overlay(t *testing.T) {
	t.Parallel()
	got := MergeExposure(
		Exposure{"issues": LevelRead, DefaultKey: LevelRead},
		Exposure{"issues": LevelWrite, "x": LevelNone},
	)
	if got["issues"] != LevelWrite || got[DefaultKey] != LevelRead || got["x"] != LevelNone {
		t.Fatalf("merge=%v", got)
	}
}

func TestBuildExposure(t *testing.T) {
	t.Parallel()
	base := Exposure{DefaultKey: LevelRead}
	e := BuildExposure(base, map[string]string{"issues": "write", "bogus": "nope"})
	if e["issues"] != LevelWrite {
		t.Errorf("issues=%v", e["issues"])
	}
	if _, ok := e["bogus"]; ok {
		t.Errorf("invalid value should be skipped")
	}
	if e[DefaultKey] != LevelRead {
		t.Errorf("default=%v want read", e[DefaultKey])
	}
}

func TestCompactCeiling(t *testing.T) {
	t.Parallel()

	for _, c := range []struct {
		name      string
		e         Exposure
		sensitive string
		want      string
	}{
		{
			name:      "baseline",
			e:         Exposure{DefaultKey: LevelRead, "secret-scanning": LevelNone},
			sensitive: "secret-scanning",
			want:      "default=read,secret-scanning=none",
		},
		{
			name:      "override between default and sensitive, sorted",
			e:         Exposure{DefaultKey: LevelRead, "issues": LevelWrite, "actions": LevelRead, "secret-scanning": LevelNone},
			sensitive: "secret-scanning",
			want:      "default=read,actions=read,issues=write,secret-scanning=none",
		},
		{
			name:      "opened sensitive shows its level last",
			e:         Exposure{DefaultKey: LevelRead, "secret-scanning": LevelRead},
			sensitive: "secret-scanning",
			want:      "default=read,secret-scanning=read",
		},
		{
			name:      "missing sensitive key prints none",
			e:         Exposure{DefaultKey: LevelWrite},
			sensitive: "ci-variables",
			want:      "default=write,ci-variables=none",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := CompactCeiling(c.e, c.sensitive); got != c.want {
				t.Errorf("CompactCeiling(%v,%q) = %q, want %q", c.e, c.sensitive, got, c.want)
			}
		})
	}
}
