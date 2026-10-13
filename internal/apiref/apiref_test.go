package apiref_test

import (
	"encoding/json"
	"testing"

	"github.com/cynative/cynative/internal/apiref"
)

func TestOutcomeOf(t *testing.T) {
	t.Parallel()

	if got := apiref.OutcomeOf(&apiref.Reference{}); got != apiref.OutcomeFound {
		t.Errorf("no gaps: %q", got)
	}
	if got := apiref.OutcomeOf(&apiref.Reference{Gaps: []string{"x"}}); got != apiref.OutcomeIncomplete {
		t.Errorf("gaps: %q", got)
	}
}

func TestReferenceShape(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ref  apiref.Reference
		want string
	}{
		{
			name: "form body",
			ref: apiref.Reference{
				Protocol:     "awsQuery",
				Method:       "POST",
				PathTemplate: "/",
				BodyEncoding: apiref.BodyForm,
				FixedForm: []apiref.Param{
					{Key: "Action", Value: "ListRoles"},
					{Key: "Version", Value: "2010-05-08"},
				},
				FixedHeaders: []apiref.Param{
					{Key: "Content-Type", Value: "application/x-www-form-urlencoded; charset=utf-8"},
				},
				Response: apiref.Response{Encoding: "xml"},
			},
			want: "awsQuery: POST / with header Content-Type: application/x-www-form-urlencoded; charset=utf-8 " +
				"and form body Action=ListRoles&Version=2010-05-08; responses are xml",
		},
		{
			name: "rest no body",
			ref: apiref.Reference{
				Protocol: "restXml", Method: "GET", PathTemplate: "/2013-04-01/hostedzone",
				BodyEncoding: apiref.BodyNone, Response: apiref.Response{Encoding: "xml"},
			},
			want: "restXml: GET /2013-04-01/hostedzone; responses are xml",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := c.ref.Shape(); got != c.want {
				t.Errorf("Shape() =\n%q\nwant\n%q", got, c.want)
			}
		})
	}
}

func TestSource_TargetedFieldsAreOmittedWhenEmpty(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(apiref.Source{Name: "n", Document: "d"})
	if err != nil || string(b) != `{"name":"n","document":"d"}` {
		t.Fatalf("Source = %s, %v", b, err)
	}
	b, _ = json.Marshal(apiref.Source{Name: "n", Document: "d", Target: "t", ServerHash: "h", ObservedAt: "o"})
	if want := `{"name":"n","document":"d","target":"t","server_hash":"h","observed_at":"o"}`; string(b) != want {
		t.Fatalf("Source = %s, want %s", b, want)
	}
}
