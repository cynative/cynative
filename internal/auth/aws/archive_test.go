package aws_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	awsh "github.com/cynative/cynative/internal/auth/aws"
	"github.com/cynative/cynative/internal/cache"
)

func newArchive(
	t *testing.T,
	fetcher func(context.Context) ([]byte, error),
	clock func() time.Time,
) *awsh.ModelArchive {
	t.Helper()
	return awsh.NewModelArchive(awsh.ModelArchiveConfig{
		Config:  cache.Config{Dir: t.TempDir(), TTL: time.Hour, Clock: clock},
		Fetcher: fetcher,
	})
}

// fixedClock returns a clock func that always returns t.
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// shaHex mirrors the archive's internal sha256Hex so tests can seed an
// index.json whose recorded SHA matches the tarball it was built from.
func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// s3Path is a well-formed model path inside the synthetic tarball.
const s3Path = "x/models/s3/service/2006-03-01/s3-2006-03-01.json"

// s3TarGz builds a one-service archive whose only model resolves on prefix s3.
func s3TarGz(t *testing.T) []byte {
	t.Helper()
	return awsh.TarGzForTest(t, map[string]string{
		s3Path: awsh.ModelJSONForTest("S3", "s3", "s3", "restXml"),
	})
}

// seedArchiveDisk runs one ModelArchive against tgz on cacheDir, populating the
// on-disk repo.tar.gz, repo.meta, and index.json exactly as persist* would.
func seedArchiveDisk(t *testing.T, cacheDir string, tgz []byte, fetchedAt time.Time) {
	t.Helper()
	seed := awsh.NewModelArchive(awsh.ModelArchiveConfig{
		Config:  cache.Config{Dir: cacheDir, TTL: time.Hour, Clock: fixedClock(fetchedAt)},
		Fetcher: func(context.Context) ([]byte, error) { return tgz, nil },
	})
	if _, err := seed.Resolve(t.Context(), "s3"); err != nil {
		t.Fatalf("seed Resolve: %v", err)
	}
}

// seedRawArchive plants an arbitrary (possibly malformed) tarball on disk with a
// matching repo.meta and a hand-written index.json that maps prefix→{dir,version}
// at the tarball's real SHA, then returns a fresh archive (fetcher must NOT run).
// Because tryLoadIndex accepts the seeded index, useArchive skips buildIndex and
// Resolve hands a.raw straight to extractModel — letting us exercise extractModel's
// own gzip/tar/typeflag/read branches independently of buildIndex.
func seedRawArchive(t *testing.T, raw []byte, prefix, modelDir, version string) *awsh.ModelArchive {
	t.Helper()
	cacheDir := t.TempDir()
	d := filepath.Join(cacheDir, "archive")
	if err := os.MkdirAll(d, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "repo.tar.gz"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	meta := `{"service":"archive","sha256":"` + shaHex(raw) + `","fetched_at":"` +
		time.Unix(1000, 0).UTC().Format(time.RFC3339Nano) + `"}`
	if err := os.WriteFile(filepath.Join(d, "repo.meta"), []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}
	idx := `{"prefixes":{"` + prefix + `":[{"dir":"` + modelDir + `","version":"` + version +
		`"}]},"sha256":"` + shaHex(raw) + `"}`
	if err := os.WriteFile(filepath.Join(d, "index.json"), []byte(idx), 0o600); err != nil {
		t.Fatal(err)
	}
	return awsh.NewModelArchive(awsh.ModelArchiveConfig{
		Config: cache.Config{Dir: cacheDir, TTL: time.Hour, Clock: fixedClock(time.Unix(1000, 10))},
		Fetcher: func(context.Context) ([]byte, error) {
			t.Error("fetcher must not be called when disk is fresh")
			return nil, errors.New("unexpected")
		},
	})
}

// gzipOf returns b wrapped in a gzip stream (used to craft malformed tar payloads).
func gzipOf(t *testing.T, b []byte) []byte {
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

func TestModelArchive_Resolve_fetchesAndResolves(t *testing.T) {
	t.Parallel()
	a := newArchive(t, func(context.Context) ([]byte, error) { return s3TarGz(t), nil }, fixedClock(time.Unix(1000, 0)))
	models, err := a.Resolve(t.Context(), "s3")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(models) != 1 || models[0].Dir != "s3" || models[0].EndpointPrefix != "s3" {
		t.Fatalf("Resolve = %+v", models)
	}
}

func TestModelArchive_Resolve_memoizesFetch(t *testing.T) {
	t.Parallel()
	var calls int
	a := newArchive(t, func(context.Context) ([]byte, error) {
		calls++
		return s3TarGz(t), nil
	}, fixedClock(time.Unix(1000, 0)))
	if _, err := a.Resolve(t.Context(), "s3"); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	if _, err := a.Resolve(t.Context(), "s3"); err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if calls != 1 {
		t.Errorf("fetcher called %d times, want 1 (memoized index)", calls)
	}
}

func TestModelArchive_Resolve_unsupportedService(t *testing.T) {
	t.Parallel()
	a := newArchive(t, func(context.Context) ([]byte, error) { return s3TarGz(t), nil }, fixedClock(time.Unix(1000, 0)))
	_, err := a.Resolve(t.Context(), "dynamodb")
	if !errors.Is(err, awsh.ErrUnsupportedService) {
		t.Errorf("err = %v, want ErrUnsupportedService", err)
	}
}

func TestModelArchive_Resolve_collision(t *testing.T) {
	t.Parallel()
	// Two dirs share endpoint prefix "email" → Resolve returns both.
	tgz := awsh.TarGzForTest(t, map[string]string{
		"x/models/ses/service/2010-12-01/ses-2010-12-01.json": awsh.ModelJSONForTest(
			"SES",
			"ses",
			"email",
			"restXml",
		),
		"x/models/sesv2/service/2019-09-27/sesv2-2019-09-27.json": awsh.ModelJSONForTest(
			"SESv2",
			"ses",
			"email",
			"restJson1",
		),
	})
	a := newArchive(t, func(context.Context) ([]byte, error) { return tgz, nil }, fixedClock(time.Unix(1000, 0)))
	models, err := a.Resolve(t.Context(), "email")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(models) != 2 {
		t.Fatalf("Resolve email = %d models, want 2 (collision)", len(models))
	}
}

func TestModelArchive_Resolve_loadErrorNoDisk(t *testing.T) {
	t.Parallel()
	a := newArchive(t, func(context.Context) ([]byte, error) {
		return nil, errors.New("boom")
	}, fixedClock(time.Unix(1000, 0)))
	_, err := a.Resolve(t.Context(), "s3")
	if !errors.Is(err, awsh.ErrSmithyUnavailable) {
		t.Errorf("err = %v, want ErrSmithyUnavailable", err)
	}
	if err != nil && !strings.Contains(err.Error(), "fetch archive failed") {
		t.Errorf("err = %v, want message containing %q", err, "fetch archive failed")
	}
}

func TestModelArchive_Resolve_buildIndexError(t *testing.T) {
	t.Parallel()
	// Non-gzip bytes from the fetcher make buildIndex (gzip.NewReader) fail.
	a := newArchive(t, func(context.Context) ([]byte, error) {
		return []byte("not a gzip stream"), nil
	}, fixedClock(time.Unix(1000, 0)))
	if _, err := a.Resolve(t.Context(), "s3"); err == nil {
		t.Error("expected error when the fetched tarball is not gzip")
	}
}

func TestModelArchive_Resolve_freshDiskSkipsFetch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tgz := s3TarGz(t)
	seedArchiveDisk(t, dir, tgz, time.Unix(1000, 0))
	a := awsh.NewModelArchive(awsh.ModelArchiveConfig{
		Config: cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(time.Unix(1000, 30))},
		Fetcher: func(context.Context) ([]byte, error) {
			t.Error("fetcher must not be called when disk is fresh")
			return nil, errors.New("unexpected")
		},
	})
	models, err := a.Resolve(t.Context(), "s3")
	if err != nil || len(models) != 1 {
		t.Errorf("Resolve = (%+v,%v), want 1 model from fresh disk", models, err)
	}
}

func TestModelArchive_Resolve_staleDiskRefetches(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	seedArchiveDisk(t, dir, s3TarGz(t), time.Unix(1000, 0))
	var calls int
	a := awsh.NewModelArchive(awsh.ModelArchiveConfig{
		Config: cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(time.Unix(1000, 0).Add(2 * time.Hour))},
		Fetcher: func(context.Context) ([]byte, error) {
			calls++
			return s3TarGz(t), nil
		},
	})
	models, err := a.Resolve(t.Context(), "s3")
	if err != nil || len(models) != 1 {
		t.Errorf("Resolve = (%+v,%v), want 1 model after stale refetch", models, err)
	}
	if calls != 1 {
		t.Errorf("fetcher called %d times, want 1 (stale disk forces refetch)", calls)
	}
}

func TestModelArchive_Resolve_staleDiskFallbackOnFetchError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	seedArchiveDisk(t, dir, s3TarGz(t), time.Unix(1000, 0))
	a := awsh.NewModelArchive(awsh.ModelArchiveConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(time.Unix(1000, 0).Add(2 * time.Hour))},
		Fetcher: func(context.Context) ([]byte, error) { return nil, errors.New("network down") },
	})
	models, err := a.Resolve(t.Context(), "s3")
	if err != nil || len(models) != 1 {
		t.Errorf("stale fallback = (%+v,%v), want 1 model", models, err)
	}
}

func TestModelArchive_Resolve_loadsPersistedIndexWithoutRebuild(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tgz := s3TarGz(t)
	seedArchiveDisk(t, dir, tgz, time.Unix(1000, 0))
	// Fresh archive on the same dir within TTL: tarball + index both load from
	// disk, so useArchive takes the persisted-index branch (no rebuild).
	a := awsh.NewModelArchive(awsh.ModelArchiveConfig{
		Config: cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(time.Unix(1000, 10))},
		Fetcher: func(context.Context) ([]byte, error) {
			t.Error("fetcher must not be called when disk is fresh")
			return nil, errors.New("unexpected")
		},
	})
	models, err := a.Resolve(t.Context(), "s3")
	if err != nil || len(models) != 1 {
		t.Errorf("Resolve = (%+v,%v), want 1 model from persisted index", models, err)
	}
}

func TestModelArchive_tryLoadIndex_malformedJSONRebuilds(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tgz := s3TarGz(t)
	d := filepath.Join(dir, "archive")
	if err := os.MkdirAll(d, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "index.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No tarball on disk → fetch, then tryLoadIndex sees malformed JSON → rebuild.
	a := awsh.NewModelArchive(awsh.ModelArchiveConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(time.Unix(1000, 0))},
		Fetcher: func(context.Context) ([]byte, error) { return tgz, nil },
	})
	models, err := a.Resolve(t.Context(), "s3")
	if err != nil || len(models) != 1 {
		t.Errorf("Resolve = (%+v,%v), want 1 model after rebuild from malformed index", models, err)
	}
}

func TestModelArchive_tryLoadIndex_shaMismatchRebuilds(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tgz := s3TarGz(t)
	d := filepath.Join(dir, "archive")
	if err := os.MkdirAll(d, 0o750); err != nil {
		t.Fatal(err)
	}
	// Valid index JSON but SHA references a different tarball → mismatch → rebuild.
	stale := `{"prefixes":{"s3":[{"dir":"s3","version":"2006-03-01"}]},"sha256":"deadbeef"}`
	if err := os.WriteFile(filepath.Join(d, "index.json"), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	a := awsh.NewModelArchive(awsh.ModelArchiveConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(time.Unix(1000, 0))},
		Fetcher: func(context.Context) ([]byte, error) { return tgz, nil },
	})
	models, err := a.Resolve(t.Context(), "s3")
	if err != nil || len(models) != 1 {
		t.Errorf("Resolve = (%+v,%v), want 1 model after rebuild on sha mismatch", models, err)
	}
}

func TestModelArchive_tryLoadIndex_emptyPrefixesRebuilds(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tgz := s3TarGz(t)
	d := filepath.Join(dir, "archive")
	if err := os.MkdirAll(d, 0o750); err != nil {
		t.Fatal(err)
	}
	// Matching SHA but zero prefixes → tryLoadIndex rejects → rebuild.
	idx := `{"prefixes":{},"sha256":"` + shaHex(tgz) + `"}`
	if err := os.WriteFile(filepath.Join(d, "index.json"), []byte(idx), 0o600); err != nil {
		t.Fatal(err)
	}
	a := awsh.NewModelArchive(awsh.ModelArchiveConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(time.Unix(1000, 0))},
		Fetcher: func(context.Context) ([]byte, error) { return tgz, nil },
	})
	models, err := a.Resolve(t.Context(), "s3")
	if err != nil || len(models) != 1 {
		t.Errorf("Resolve = (%+v,%v), want 1 model after rebuild on empty prefixes", models, err)
	}
}

func TestModelArchive_persistIndex_mkdirFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// <dir>/archive is a file: byteCache's MkdirAll (best-effort persist) fails AND
	// persistIndex's MkdirAll fails. Resolve still resolves in-memory.
	if err := os.WriteFile(filepath.Join(dir, "archive"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := awsh.NewModelArchive(awsh.ModelArchiveConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(time.Unix(1000, 0))},
		Fetcher: func(context.Context) ([]byte, error) { return s3TarGz(t), nil },
	})
	models, err := a.Resolve(t.Context(), "s3")
	if err != nil || len(models) != 1 {
		t.Errorf("Resolve = (%+v,%v), want 1 model despite persistIndex mkdir failure", models, err)
	}
}

func TestModelArchive_persistIndex_writeFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// <dir>/archive/index.json is a directory so persistIndex's WriteFile fails,
	// while byteCache (repo.tar.gz / repo.meta) succeeds. Resolve still resolves.
	if err := os.MkdirAll(filepath.Join(dir, "archive", "index.json"), 0o750); err != nil {
		t.Fatal(err)
	}
	a := awsh.NewModelArchive(awsh.ModelArchiveConfig{
		Config:  cache.Config{Dir: dir, TTL: time.Hour, Clock: fixedClock(time.Unix(1000, 0))},
		Fetcher: func(context.Context) ([]byte, error) { return s3TarGz(t), nil },
	})
	models, err := a.Resolve(t.Context(), "s3")
	if err != nil || len(models) != 1 {
		t.Errorf("Resolve = (%+v,%v), want 1 model despite index write failure", models, err)
	}
}

func TestModelArchive_Resolve_memoReturnsSameModel(t *testing.T) {
	t.Parallel()
	a := newArchive(t, func(context.Context) ([]byte, error) { return s3TarGz(t), nil }, fixedClock(time.Unix(1000, 0)))
	first, err := a.Resolve(t.Context(), "s3")
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	second, err := a.Resolve(t.Context(), "s3")
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	// modelFor memoizes by dir, so the same *ServiceModel pointer is returned.
	if first[0] != second[0] {
		t.Error("expected memoized model pointer identity across Resolve calls")
	}
}

func TestModelArchive_Resolve_parseModelError(t *testing.T) {
	t.Parallel()
	// A model with an endpointPrefix trait (so buildIndex indexes it on "broken")
	// but smithy version 1.0 (so ParseModel rejects it) → modelFor error propagates.
	badModel := `{"smithy":"1.0","shapes":{"com.x#Svc":{"type":"service","traits":` +
		`{"aws.api#service":{"sdkId":"X","arnNamespace":"x","endpointPrefix":"broken"},` +
		`"aws.protocols#restXml":{}}}}}`
	tgz := awsh.TarGzForTest(t, map[string]string{
		"x/models/broken/service/2020-01-01/broken-2020-01-01.json": badModel,
	})
	a := newArchive(t, func(context.Context) ([]byte, error) { return tgz, nil }, fixedClock(time.Unix(1000, 0)))
	_, err := a.Resolve(t.Context(), "broken")
	if !errors.Is(err, awsh.ErrSmithyUnavailable) {
		t.Errorf("err = %v, want ErrSmithyUnavailable from ParseModel", err)
	}
}

func TestModelArchive_Resolve_extractModelNotFound(t *testing.T) {
	t.Parallel()
	// Index entry points at a (dir,version) absent from the tarball: extractModel
	// iterates every real entry without a match and reaches EOF (loop exhaustion).
	a := seedRawArchive(t, s3TarGz(t), "ghost", "ghost", "1999-01-01")
	_, err := a.Resolve(t.Context(), "ghost")
	if !errors.Is(err, awsh.ErrSmithyUnavailable) {
		t.Errorf("err = %v, want ErrSmithyUnavailable from extractModel not-found", err)
	}
}

func TestModelArchive_Resolve_extractModelGzipError(t *testing.T) {
	t.Parallel()
	// a.raw is not a gzip stream → extractModel's gzip.NewReader fails.
	a := seedRawArchive(t, []byte("not a gzip stream"), "ghost", "ghost", "1999-01-01")
	_, err := a.Resolve(t.Context(), "ghost")
	if !errors.Is(err, awsh.ErrSmithyUnavailable) {
		t.Errorf("err = %v, want ErrSmithyUnavailable from extractModel gzip error", err)
	}
}

func TestModelArchive_Resolve_extractModelTarError(t *testing.T) {
	t.Parallel()
	// Valid gzip whose payload is not a valid tar header → tr.Next returns a
	// non-EOF error inside extractModel.
	a := seedRawArchive(t, gzipOf(t, bytes.Repeat([]byte{1}, 512)), "ghost", "ghost", "1999-01-01")
	_, err := a.Resolve(t.Context(), "ghost")
	if !errors.Is(err, awsh.ErrSmithyUnavailable) {
		t.Errorf("err = %v, want ErrSmithyUnavailable from extractModel tar error", err)
	}
}

func TestModelArchive_Resolve_extractModelSkipsDirEntry(t *testing.T) {
	t.Parallel()
	// A tarball whose first entry is a directory exercises extractModel's
	// typeflag!=TypeReg continue before the matching model file is reached.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "x/models/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	body := awsh.ModelJSONForTest("S3", "s3", "s3", "restXml")
	hdr := &tar.Header{Name: s3Path, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	a := seedRawArchive(t, buf.Bytes(), "s3", "s3", "2006-03-01")
	models, err := a.Resolve(t.Context(), "s3")
	if err != nil || len(models) != 1 {
		t.Errorf("Resolve = (%+v,%v), want 1 model past the directory entry", models, err)
	}
}

func TestModelArchive_Resolve_extractModelReadError(t *testing.T) {
	t.Parallel()
	// The matching entry declares more bytes than are present, so io.ReadAll on
	// it hits an unexpected EOF inside extractModel.
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	hdr := &tar.Header{Name: s3Path, Mode: 0o644, Size: 500, Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	// Deliberately do NOT close tw: the body is truncated mid-entry.
	a := seedRawArchive(t, gzipOf(t, raw.Bytes()), "s3", "s3", "2006-03-01")
	_, err := a.Resolve(t.Context(), "s3")
	if !errors.Is(err, awsh.ErrSmithyUnavailable) {
		t.Errorf("err = %v, want ErrSmithyUnavailable from extractModel read error", err)
	}
}

func TestModelArchive_NamespaceShadowed(t *testing.T) {
	t.Parallel()
	// An archive containing both S3 (owns prefix "s3") and S3 Control (prefix
	// "s3-control", namespace "s3"): S3 Control is shadowed; S3 is not.
	s3JSON := awsh.ModelJSONForTest("S3", "s3", "s3", "restXml")
	ctrlJSON := awsh.ModelJSONForTest("S3 Control", "s3", "s3-control", "restXml")
	noarnJSON := awsh.ModelJSONForTest("NoArn", "", "noarn", "restXml")
	tgz := awsh.TarGzForTest(t, map[string]string{
		"x/models/s3/service/2006-03-01/s3-2006-03-01.json":                 s3JSON,
		"x/models/s3-control/service/2018-08-20/s3-control-2018-08-20.json": ctrlJSON,
		"x/models/noarn/service/2020-01-01/noarn-2020-01-01.json":           noarnJSON,
	})
	a := newArchive(t, func(context.Context) ([]byte, error) { return tgz, nil }, time.Now)

	ctrl, err := a.Resolve(t.Context(), "s3-control")
	if err != nil {
		t.Fatalf("Resolve(s3-control): %v", err)
	}
	if len(ctrl) != 1 || !ctrl[0].NamespaceShadowed {
		t.Errorf("s3-control NamespaceShadowed = %v, want true", ctrl[0].NamespaceShadowed)
	}

	s3, err := a.Resolve(t.Context(), "s3")
	if err != nil {
		t.Fatalf("Resolve(s3): %v", err)
	}
	if len(s3) != 1 || s3[0].NamespaceShadowed {
		t.Errorf("s3 NamespaceShadowed = %v, want false (it owns the namespace)", s3[0].NamespaceShadowed)
	}

	noarn, err := a.Resolve(t.Context(), "noarn")
	if err != nil {
		t.Fatalf("Resolve(noarn): %v", err)
	}
	if len(noarn) != 1 || noarn[0].NamespaceShadowed {
		t.Errorf("noarn NamespaceShadowed = %v, want false (empty ARN namespace)", noarn[0].NamespaceShadowed)
	}
}
