package redact_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/redact"
)

// FuzzRedact pins panic-freedom and the fail-closed redaction contract over
// arbitrary response bytes (#181). Seed corpus covers known secret shapes and
// benign prose so go test exercises the interesting branches without -fuzz.
func FuzzRedact(f *testing.F) {
	f.Add("token=ghp_" + strings.Repeat("a", 36) + " end")
	f.Add("a perfectly ordinary sentence with no secrets")
	f.Add(`{"access_token":"abc123secretvalue","expires_in":3600}`)
	f.Add("Bearer eyJhbGci.eyJzdWIi.sig123_-")
	f.Add("")
	f.Add(string([]byte{0xff, 0xfe, 'h', 'i'}))
	f.Add(`{"Variables":{"DB_PASSWORD":"hunter2","nextPageToken":"CgwI"}}`)
	f.Add(`[{"name":"DB_PASSWORD","value":"hunter2"},{"name":"DB_HOST","value":"db.internal"}]`)
	f.Add(`[{"value":"hunter2","name":"API_KEY"}]`)
	f.Add(`[{"name":"DB_PASSWORD","value":"hunt`)
	f.Add("env:\n  - name: DB_PASSWORD\n    value: hunter2\n")
	f.Add(`{"args":["--token","hunter2","--password=hunter2","--token-file","/t"]}`)
	f.Add(`["--generate-secret","--password","x",{"text":"--token","public":"d"}]`)
	f.Add("{\"password\":\"sig=x\\\nTAIL")
	f.Add(`{"service-api-key":"a","x":1,"--token=k":2,"a":["--token=v"]}`)
	f.Add("- value: v\n  name: DB_PASSWORD\n")
	f.Add("- name: DB_PASSWORD # c\n  meta:\n    a: b\n  value: |\n    x\n\n    y\n- name: N\n")
	f.Add("password: \"a\\\" \nb\"\ntoken: 'it''s\n  x'\napi_key:\n\n  v\nsecret:\n  k: v\n")
	f.Add(`{"DB_PASSW\u004fRD":"a","value":"b","value":1,"n\u0061me":"API_KEY","x":[{"y":2e999}]}`)
	f.Add(`{"name":"DB_PASSWORD","meta":{},"value":"hunt`)
	f.Add(`["sh","-c","app --token 'a b' --password=\"c\\\" d\" e\\ f --api-key","--password","--x"]`)
	f.Add(`["bash","-ec","app --token 'abc`)
	f.Add("00000000,\"--token\",\"--pAsswd=")
	f.Add(",\"sh\",\"-c\",\"--pAsswd= ")
	f.Add("pAsswd: \"\"\n 00")
	f.Add("0: \"\ntoken:\n 0ApikeY:\"")
	f.Add("pAsswd=,\"\r,\"--pAsswd=")
	f.Add("\"password\": |\n  a\n- 'name': API_KEY\n  'value': \"b\nc")
	f.Add(`["sh","-c","a --token $(e \") (\" ` + "`x`" + `) b --password ` + "`y")
	f.Add(`["bash","--noprofile","-o","pipefail","+O","x","-ec","app --password --p in"],` +
		`["\u002d\u002dtoken","--no-x","--no-token","v"]`)
	f.Add(",\"--pAsswd\",\"sh\",\"-c\",\"--token= ")
	f.Add(`["sh","--password","-o","sh","--rcfile","bash","-c","--token=a b","sh","+o","sh","-x"]`)
	f.Add("password:\n  \"a: b\"\nx:\n  'c: d'\n")
	f.Add(`["--password","[REDACTED:jwt]\q","sh","-c","app --token [REDACTED:jwt]\qs"]`)
	f.Add(",\"sh\",\"-c\",\"--pAsswd\\\"=\\\" ")
	f.Add(
		"data:\n  c: |\n    - name: DB_PASSWORD\n        # c\n      value: x\npassword:\n# c\n  \"a\nb\"\nsecret:\n  \"k\": v\ntoken: [\n  a\n]\n",
	)
	f.Add(`["sh","-c","a \"--pass\"word x; b --pass\\word=\"y z\" # --token q\r\n--token \u00`)
	f.Add("{\"public\":\"cynative-loc-0\",\"Location\":[\"https://e.test/x?sig=abc\"]}")
	f.Add(`"{\"DB_PASSWORD\":\"hunter2\"}"`)
	f.Add(`{"r":"\"{\\\"token\\\":\\\"t\\\"}\"","n":[1,"{\"name\":\"API_KEY\",\"value\":\"k\"}"]}`)
	f.Add(`{"r": "{\"password\":\"hunt\u00`)
	f.Add(`{"r":"{\"password\":\"hunt\`)
	f.Add(`{"a" "b\"c"}`)
	f.Add(`["sh","-c","bash -c 'sh -c \"app --password=$X <(y)\"' --token ${a:-b c}; app --api-key $'x\\' y'"]`)
	f.Add(
		"? \"pass\\x77ord\"\n: a\n'token': b\nenv: [{name: DB_PASSWORD, value: &a c # d\n}, [api_key: e], {? secret : \"f",
	)
	f.Add(`["sh","-c","-e","-o","x","--","bash -c -x -- 'a --token b'"],"\"api\x5fkey\": \"c\""`)
	f.Add("x: {password: [REDACTED:jwt]x, \"name\": \"API_KEY\", value: \"g\"}]")
	f.Add(`"\u003cpassword>x"`)
	f.Add(`["token: x\npassword:\n  y\nend: \u0041","a\nAPI_KEY=k1\n\u0073ig=zz\nPASSWORD=p2"]`)
	f.Add(`["sig=x\"tail","{\"DB_PASSWORD\":\"hunter2\"}"]`)
	f.Add("{\"u\":\"sig=ab\\\\\\\"c\"}\nsig=ab\\\npassword: x\nsig=ab\\&t=1")
	f.Add(`[1e1000,"\u0073ig=x\n{\"password\":\"x\"}"]`)
	f.Add(`{"a":"-----BEGIN PRIVATE KEY-----","b":{"c":"-----END PRIVATE KEY-----"},"r":"{\"token\":\"t\"}"}`)
	f.Add(`{"r":"{\"k\":\"-----BEGIN PRIVATE KEY-----\\\nMII\\\"}\"}","t":"-----BEGIN PRIVATE KEY-----\`)
	f.Add("[\"-----BEGIN PRIVATE KEY-----\\nComment: \\\"x\\\" \\n\"\n]\necho \"-----BEGIN PRIVATE KEY-----\" k")
	f.Add(`"-----BEGIN PRIVATE KEY-----"MIIE-----END PRIVATE KEY-----`)
	f.Add(`{"k":"-----BEGIN PRIVATE KEY-----\ud83d\ude00x\u005d","p":"PRIVATE KEY a<b \/"}`)
	f.Add(`{"a":"<password>","b":{"c":"</password>"},"r":"{\"password\":\"hunter2\"}"}`)
	f.Add(`{"a":"<password>","b":"</password>","c":"<token>hunt`)
	f.Add("{\"\":\"<pAsswd>\",\"<token>\x00")
	f.Add(`{"x":"<secret>p\"q</secret>"}<token>v`)
	f.Add(`0 "{\"x\":\"<password>p</password> \u0067hp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}"` +
		` ["<token>","t","</token>"]`)
	f.Add(`{"x":"<password>p</password> \u0067hp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","y":"<token>h\u003cx</token>"}`)
	f.Add(`{"r":"{\"h\":\"<b>x</b>\"}\u0020","s":"<password>hunter2 sig=abc<xyz"}`)
	f.Add(`{"k":"LS0tLS1CRUdJTiBQ\r\n` + strings.Repeat("QUJD", 16) + `\nname","r":"{\"k\":\"LS0tLS1CRUdJTi\\nx\"}"}`)
	f.Add("[\"LS0tLS1CRUdJTi\"\n" + strings.Repeat("QUJD", 8) + ",LS0tLS1CRUdJTi\\")
	f.Add(`got {"DB_PASSW\u004fRD":"hunter2"} {name} [1] x {"a b {"t\u006fken":"v"} {"a":NaN}`)
	f.Add(`"a\"b" x "{\"password\":\"p\"}" 5" {"r":"{\"token\":\"t\"}"} {"API_KEY":"hunt`)
	f.Add("HTTP/1.1 200 OK\r\nX: {\"a\r\n\r\n[{\"n\\u0061me\":\"API_KEY\",\"value\":\"k\"}]")
	f.Add(`{"a":"\\","b":"\"NaN","x":[NaN,-Infinity,Infinity],"DB_PASSW\u004fRD":"v"} -NaN 1NaN [Infinit`)
	f.Add(`[NaN,"a {"DB_PASSW\u004fRD":"v"} {}1NaN"b {"t\u006fken":"w"}`)
	f.Add(`"token:\b"\u0073ig=0`)
	f.Add("\"\x00\\\"pAsswd\\\":\\\"\\\"pAsswd\\\":\\\"")
	f.Add(`<token>["--token","<p`)
	f.Add(`x["--token","<token>":0`)

	r := redact.New()
	f.Fuzz(func(t *testing.T, s string) {
		got := r.Redact(s)
		if again := r.Redact(got); again != got {
			t.Fatalf("Redact is not idempotent: first=%q second=%q", got, again)
		}
		// A fired rule must leave a labeled placeholder, never the raw secret
		// shape we seeded. Only assert on inputs we know contain a classic PAT.
		const pat = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		if strings.Contains(s, pat) && strings.Contains(got, pat) {
			t.Fatalf("classic GitHub PAT survived redaction: %q", got)
		}
		if strings.Contains(s, pat) && !strings.Contains(got, "[REDACTED:") {
			t.Fatalf("classic GitHub PAT matched but left no placeholder: %q", got)
		}
	})
}

// FuzzRedactHeader pins panic-freedom and denylist / Location-exemption
// behavior over arbitrary header values (#181).
func FuzzRedactHeader(f *testing.F) {
	f.Add("Authorization", "Bearer abc")
	f.Add("Location", "https://x/o?X-Amz-Signature=keepme&t=1")
	f.Add("X-Custom", "token=ghp_"+strings.Repeat("a", 36))
	f.Add("Content-Type", "application/json")
	f.Add("Set-Cookie", "session=topsecret; Path=/")

	r := redact.New()
	f.Fuzz(func(t *testing.T, name, value string) {
		if name == "" {
			return
		}
		h := http.Header{}
		h.Set(name, value)
		locBefore := h.Get("Location")
		r.RedactHeader(h)

		canon := http.CanonicalHeaderKey(strings.ReplaceAll(name, "_", "-"))
		switch canon {
		case "Authorization", "Set-Cookie", "Proxy-Authorization",
			"Private-Token", "Job-Token", "Deploy-Token",
			"X-Gitlab-Static-Object-Token", "X-Amz-Security-Token",
			"X-Ms-Authorization-Auxiliary":
			if value == "" {
				return
			}
			if got := h.Get(name); got != "[REDACTED:header]" {
				t.Fatalf("%s denylist miss: %q", canon, got)
			}
		case "Location":
			if got := h.Get("Location"); got != locBefore {
				t.Fatalf("Location must stay exempt: before=%q after=%q", locBefore, got)
			}
		}
	})
}
