package aws

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

// tarEntry is one file (or directory) to place in a synthetic tarball.
type tarEntry struct {
	name    string
	content string
	isDir   bool
}

// makeTarGzEntries builds an in-memory .tar.gz from ordered entries (order
// matters for the latest-version tie-break test).
func makeTarGzEntries(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.content)), Typeflag: tar.TypeReg}
		if e.isDir {
			hdr.Typeflag = tar.TypeDir
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if !e.isDir {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// makeTarGz builds an in-memory .tar.gz from name→content entries (unordered).
func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	entries := make([]tarEntry, 0, len(files))
	for name, content := range files {
		entries = append(entries, tarEntry{name: name, content: content})
	}
	return makeTarGzEntries(t, entries)
}

// gzipBytes returns b gzipped (used to craft malformed tar streams).
func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	if _, err := gz.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// model renders a minimal Smithy service model with the given identifiers.
func model(sdkID, arn, ep, proto string) string {
	svc := `"aws.api#service":{"sdkId":"` + sdkID + `","arnNamespace":"` + arn + `"`
	if ep != "" {
		svc += `,"endpointPrefix":"` + ep + `"`
	}
	svc += `}`
	return `{"smithy":"2.0","shapes":{"com.x#Svc":{"type":"service","traits":{` + svc +
		`,"aws.protocols#` + proto + `":{}}}}}`
}

func TestBuildIndex(t *testing.T) {
	t.Parallel()
	// Ordered so the newer cloudwatch version is seen before the older one,
	// exercising the "version <= current" skip; includes a directory entry and
	// a non-model file to exercise the typeflag and parse-path skips.
	entries := []tarEntry{
		{name: "api-models-aws-main/", isDir: true},
		{name: "api-models-aws-main/README.md", content: "ignore"},
		{
			name:    "api-models-aws-main/models/cloudwatch/service/2010-08-01/cloudwatch-2010-08-01.json",
			content: model("CloudWatch", "monitoring", "monitoring", "awsQuery"),
		},
		{
			name:    "api-models-aws-main/models/cloudwatch/service/2009-01-01/cloudwatch-2009-01-01.json",
			content: model("CloudWatch", "monitoring", "monitoring", "awsQuery"),
		},
		{
			name:    "api-models-aws-main/models/ses/service/2010-12-01/ses-2010-12-01.json",
			content: model("SES", "ses", "email", "restXml"),
		},
		{
			name:    "api-models-aws-main/models/sesv2/service/2019-09-27/sesv2-2019-09-27.json",
			content: model("SESv2", "ses", "email", "restJson1"),
		},
	}
	idx, err := buildIndex(makeTarGzEntries(t, entries), "deadbeef")
	if err != nil {
		t.Fatalf("buildIndex: %v", err)
	}
	if idx.SHA256 != "deadbeef" {
		t.Errorf("SHA256 = %q, want deadbeef", idx.SHA256)
	}
	if got := idx.Prefixes["monitoring"]; len(got) != 1 || got[0].Dir != "cloudwatch" ||
		got[0].Version != "2010-08-01" {
		t.Errorf("monitoring -> %+v, want [{cloudwatch 2010-08-01}]", got)
	}
	if got := idx.Prefixes["email"]; len(got) != 2 {
		t.Errorf("email -> %+v, want 2 entries (ses+sesv2 collision)", got)
	}
}

func TestBuildIndex_skipsNonModelsAndUnparseable(t *testing.T) {
	t.Parallel()
	entries := []tarEntry{
		{
			name:    "x/README.md",
			content: "ignore",
		}, // no "models/" → parseArchivePath i<0.
		{
			name:    "x/models/foo.json",
			content: "ignore",
		}, // "models/" but wrong shape → parseModelPath false.
		{
			name:    "x/models/aaa/service/2020-01-01/aaa-2020-01-01.json",
			content: "not json",
		}, // doc unmarshal fail → prefix "".
		{
			name:    "x/models/bbb/service/2020-01-01/bbb-2020-01-01.json",
			content: `{"smithy":"2.0","shapes":{"com.x#Bad":123}}`,
		}, // sole shape fails to unmarshal → continue, then no service → "".
		{
			name:    "x/models/ccc/service/2020-01-01/ccc-2020-01-01.json",
			content: model("C", "c", "ccc", "restXml"),
		}, // valid service → indexed.
	}
	idx, err := buildIndex(makeTarGzEntries(t, entries), "x")
	if err != nil {
		t.Fatalf("buildIndex: %v", err)
	}
	if got := idx.Prefixes["ccc"]; len(got) != 1 || got[0].Dir != "ccc" {
		t.Errorf("ccc -> %+v, want [{ccc 2020-01-01}]", got)
	}
	if _, ok := idx.Prefixes[""]; ok {
		t.Error("empty-prefix services must not be indexed")
	}
}

func TestBuildIndex_gzipError(t *testing.T) {
	t.Parallel()
	if _, err := buildIndex([]byte("not a gzip stream"), "x"); err == nil {
		t.Error("expected error for non-gzip input")
	}
}

func TestBuildIndex_tarError(t *testing.T) {
	t.Parallel()
	// A valid gzip whose payload is not a valid tar header (non-zero block) makes
	// tar.Next return a non-EOF error.
	if _, err := buildIndex(gzipBytes(t, bytes.Repeat([]byte{1}, 512)), "x"); err == nil {
		t.Error("expected error for corrupt tar")
	}
}

func TestBuildIndex_noModels(t *testing.T) {
	t.Parallel()
	if _, err := buildIndex(makeTarGz(t, map[string]string{"x/README.md": "ignore"}), "x"); err == nil {
		t.Error("expected error when the archive has no models")
	}
}

func TestBuildIndex_readError(t *testing.T) {
	t.Parallel()
	// Header declares 500 bytes but only 5 are present, so io.ReadAll on the
	// entry hits an unexpected EOF.
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	hdr := &tar.Header{
		Name:     "x/models/s3/service/2006-03-01/s3-2006-03-01.json",
		Mode:     0o644,
		Size:     500,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	// Deliberately do NOT close tw: raw holds the 512-byte header + 5 body bytes.
	if _, err := buildIndex(gzipBytes(t, raw.Bytes()), "x"); err == nil {
		t.Error("expected error for a truncated tar entry")
	}
}

func TestParseModelPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path    string
		wantDir string
		wantVer string
		wantOK  bool
	}{
		{"models/s3/service/2006-03-01/s3-2006-03-01.json", "s3", "2006-03-01", true},
		{"models/s3/service/2006-03-01/s3-2006-03-01.xml", "", "", false}, // non-.json suffix.
		{"models/s3/service/2006-03-01/extra/s3.json", "", "", false},     // too many parts.
		{"models/s3/notservice/2006-03-01/s3.json", "", "", false},        // wrong middle.
		{"README.md", "", "", false},                                      // no models prefix.
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			dir, ver, ok := parseModelPath(tc.path)
			if ok != tc.wantOK || dir != tc.wantDir || ver != tc.wantVer {
				t.Errorf("parseModelPath(%q) = (%q,%q,%v), want (%q,%q,%v)",
					tc.path, dir, ver, ok, tc.wantDir, tc.wantVer, tc.wantOK)
			}
		})
	}
}

func TestSha256Hex(t *testing.T) {
	t.Parallel()
	got := sha256Hex([]byte("x"))
	// echo -n x | sha256sum
	want := "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
	if got != want {
		t.Errorf("sha256Hex = %q, want %q", got, want)
	}
}
