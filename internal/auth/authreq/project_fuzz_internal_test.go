package authreq

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzProjectBlock is a differential target: projectBlock must agree with the
// map[string]json.RawMessage decode it replaced, on both the error verdict and
// the extracted bytes. The scanner is the only hand-written JSON walk in the
// auth path, so pinning it against encoding/json is what makes it trustworthy;
// an agreement failure is a divergence between what a gate reads and what the
// tool schema decoded, which is the failure this narrowing exists to prevent.
//
// make check never passes -fuzz and no corpus is committed, so the seeds below
// are the whole gate and have to reach every branch of the walk: escapes in
// names and values, structural bytes inside strings, nesting, every scalar
// shape, insignificant whitespace, duplicate keys, and the non-object and
// malformed top levels that fall through to encoding/json.
func FuzzProjectBlock(f *testing.F) {
	seeds := []string{
		// Ordinary shapes.
		`{"aws_auth":{"service":"s3"}}`,
		`{"method":"GET","url":"https://x/y","aws_auth":{"service":"s3"}}`,
		`{}`,
		`{"aws_auth":null}`,
		`null`,
		// Whitespace in every insignificant position.
		"{ \"aws_auth\" : { \"a\" : 1 } , \"b\" : 2 }",
		"\t\r\n{\"aws_auth\":1}\n",
		// Every scalar value shape, including ones ended by a brace not a comma.
		`{"aws_auth":12}`,
		`{"aws_auth":-1.5e10}`,
		`{"aws_auth":true}`,
		`{"aws_auth":false}`,
		`{"aws_auth":"plain"}`,
		`{"aws_auth":[]}`,
		`{"aws_auth":[1,{"x":2}]}`,
		// Structural bytes inside strings must not end a value early.
		`{"aws_auth":{"s":"}{][,"}}`,
		`{"body":"{\"a\":1}","aws_auth":{"service":"s3"}}`,
		`{"body":"\\","aws_auth":1}`,
		`{"body":"\"","aws_auth":1}`,
		// Escaped and lookalike member names.
		`{"aws_auth":{"service":"s3"}}`,
		`{"aws_auth\\":1,"aws_auth":2}`,
		`{"AWS_AUTH":1}`,
		`{"aws_autho":1}`,
		`{"":1}`,
		// Invalid UTF-8 in a name: encoding/json substitutes U+FFFD, so bytes
		// that look equal to the key are not. Found by extended fuzzing.
		"{\"\xff\":[]}",
		"{\"aws\xff_auth\":1,\"aws_auth\":2}",
		"{\"�\":1}",
		// Duplicates: encoding/json keeps the last.
		`{"aws_auth":{"a":1},"aws_auth":{"b":2}}`,
		// Top levels that are not objects, plus malformed input.
		`5`,
		`"x"`,
		`[]`,
		`true`,
		`{`,
		``,
		`{"aws_auth":}`,
		`{"a":1}trailing`,
	}
	for _, s := range seeds {
		f.Add(s, "aws_auth")
		// Probe each seed with a key that is not valid UTF-8 as well: the
		// replacement encoding/json performs means such a key can never match a
		// decoded name, and the walk must agree.
		f.Add(s, "\xff")
	}

	f.Fuzz(func(t *testing.T, toolCall, key string) {
		got, gotErr := projectBlock(json.RawMessage(toolCall), key)

		var fields map[string]json.RawMessage
		wantErr := json.Unmarshal([]byte(toolCall), &fields)

		if (gotErr != nil) != (wantErr != nil) {
			t.Fatalf("projectBlock(%q, %q) error = %v, encoding/json error = %v", toolCall, key, gotErr, wantErr)
		}

		if wantErr != nil {
			if got != nil {
				t.Errorf("projectBlock(%q, %q) = %q alongside an error, want nil", toolCall, key, got)
			}

			return
		}

		if want := fields[key]; !bytes.Equal(got, want) {
			t.Errorf("projectBlock(%q, %q) = %q, encoding/json = %q", toolCall, key, got, want)
		}
	})
}
