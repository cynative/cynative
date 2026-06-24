package sandbox_test

import (
	"strings"
	"testing"
)

func TestRun_XMLParse(t *testing.T) {
	t.Parallel()

	got := run(t, newSandbox(t, nil, nil),
		`console.log(JSON.stringify(xml.parse('<a><b>hi</b></a>')))`)
	if got != `{"a":{"b":"hi"}}`+"\n" {
		t.Errorf("got %q", got)
	}
}

func TestRun_XMLParseMissingArgThrows(t *testing.T) {
	t.Parallel()

	got := run(t, newSandbox(t, nil, nil),
		`try { xml.parse(); } catch (e) { console.log("ERR:" + e); }`)
	if !strings.Contains(got, "ERR:") || !strings.Contains(got, "expected an XML string") {
		t.Errorf("expected a thrown TypeError, got %q", got)
	}
}

func TestRun_XMLParseMalformedThrows(t *testing.T) {
	t.Parallel()

	got := run(t, newSandbox(t, nil, nil),
		`try { xml.parse('<a>'); } catch (e) { console.log("ERR:" + e); }`)
	if !strings.Contains(got, "ERR:") || !strings.Contains(got, "parse xml") {
		t.Errorf("expected a thrown parse error, got %q", got)
	}
}

func TestRun_JMESPathSearch(t *testing.T) {
	t.Parallel()

	got := run(t, newSandbox(t, nil, nil),
		`console.log(JSON.stringify(jmespath.search({a:{b:[10,20,30]}}, 'a.b[1]')))`)
	if got != "20\n" {
		t.Errorf("got %q", got)
	}
}

func TestRun_JMESPathNumericFilter(t *testing.T) {
	t.Parallel()

	// Pins the int64->float64 normalization: without it the filter matches nothing.
	got := run(t, newSandbox(t, nil, nil),
		"console.log(JSON.stringify(jmespath.search([{n:1},{n:50}], '[?n > `30`].n')))")
	if got != "[50]\n" {
		t.Errorf("got %q", got)
	}
}

func TestRun_JMESPathNoMatch(t *testing.T) {
	t.Parallel()

	got := run(t, newSandbox(t, nil, nil),
		`console.log(JSON.stringify(jmespath.search({a:1}, 'b')))`)
	if got != "null\n" {
		t.Errorf("got %q", got)
	}
}

func TestRun_JMESPathMissingExprThrows(t *testing.T) {
	t.Parallel()

	got := run(t, newSandbox(t, nil, nil),
		`try { jmespath.search({a:1}); } catch (e) { console.log("ERR:" + e); }`)
	if !strings.Contains(got, "ERR:") || !strings.Contains(got, "expected (data, expression)") {
		t.Errorf("expected a thrown TypeError, got %q", got)
	}
}

func TestRun_JMESPathInvalidExprThrows(t *testing.T) {
	t.Parallel()

	got := run(t, newSandbox(t, nil, nil),
		`try { jmespath.search({a:1}, '[0'); } catch (e) { console.log("ERR:" + e); }`)
	if !strings.Contains(got, "ERR:") || !strings.Contains(got, "jmespath search") {
		t.Errorf("expected a thrown search error, got %q", got)
	}
}
