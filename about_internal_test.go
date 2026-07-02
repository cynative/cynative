package cynative

import (
	"strings"
	"testing"
)

func TestExtractAbout(t *testing.T) {
	t.Parallel()

	const begin = "<!-- BEGIN agent-about -->"
	const end = "<!-- END agent-about -->"

	tests := []struct {
		name string
		src  string
		want string
	}{
		{"both markers", "pre\n" + begin + "\n  body text  \n" + end + "\npost", "body text"},
		{"missing begin", "no markers here\n" + end + "\n", ""},
		{"missing end", begin + "\nbody but no end\n", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := extractAbout(tt.src); got != tt.want {
				t.Errorf("extractAbout() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAbout_FromEmbeddedREADME(t *testing.T) {
	t.Parallel()

	if !strings.Contains(readme, aboutBeginMarker) || !strings.Contains(readme, aboutEndMarker) {
		t.Fatal("README.md is missing the agent-about markers")
	}
	got := About()
	if got == "" {
		t.Fatal("About() returned empty; markers present but extraction failed")
	}
	if !strings.Contains(got, "Cynative runs frontier models") {
		t.Errorf("About() missing intro sentence; got:\n%s", got)
	}
	if strings.Contains(got, aboutBeginMarker) || strings.Contains(got, aboutEndMarker) {
		t.Errorf("About() leaked a marker; got:\n%s", got)
	}
}

func TestQuickstartExample_FromEmbeddedREADME(t *testing.T) {
	t.Parallel()
	if len(QuickstartExample()) == 0 {
		t.Fatal("QuickstartExample() returned no lines; check the quickstart markers in README.md")
	}
}

func TestExtractQuickstart(t *testing.T) {
	t.Parallel()

	const begin = "<!-- BEGIN quickstart-example -->"
	const end = "<!-- END quickstart-example -->"

	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"both markers", "pre\n" + begin + "\nexport X=1\n" + end + "\npost", []string{"export X=1"}},
		{"missing begin", "no markers here\n" + end + "\n", nil},
		{"missing end", begin + "\nexport X=1\n", nil},
		{"empty", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := extractQuickstart(tt.src)
			if len(got) != len(tt.want) {
				t.Errorf("extractQuickstart() = %#v, want %#v", got, tt.want)
				return
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("line %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
