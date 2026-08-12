package agentcatalog_test

import (
	"io"
	"io/fs"
	"testing/fstest"
)

// faultFS wraps a [fstest.MapFS] and fails a chosen operation, so the catalog's
// fail-closed branches are reachable. [fstest.MapFS] alone cannot produce
// ReadDir, Open, Lstat or mid-read failures, and every one of those has a
// return statement the coverage gate requires a test to reach.
type faultFS struct {
	fstest.MapFS

	failReadDir error
	failOpen    error
	failLstat   error
	failRead    error
}

func (f faultFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if f.failReadDir != nil {
		return nil, f.failReadDir
	}

	return f.MapFS.ReadDir(name)
}

func (f faultFS) Lstat(name string) (fs.FileInfo, error) {
	if f.failLstat != nil {
		return nil, f.failLstat
	}

	return f.MapFS.Lstat(name)
}

func (f faultFS) Open(name string) (fs.File, error) {
	if f.failOpen != nil {
		return nil, f.failOpen
	}

	file, err := f.MapFS.Open(name)
	if err != nil || f.failRead == nil {
		return file, err
	}

	return faultFile{File: file, failRead: f.failRead}, nil
}

// faultFile fails on read, modelling a file that opens but cannot be drained.
type faultFile struct {
	fs.File

	failRead error
}

func (f faultFile) Read([]byte) (int, error) {
	return 0, f.failRead
}

// vanishingFS lists an entry on the FIRST ReadDir and hides it on every later
// one, modelling a file deleted between enumeration and read. A one-shot fault
// FS cannot reach that arm, because candidateNames and readFrom each call
// ReadDir and a static double answers both the same way.
type vanishingFS struct {
	fstest.MapFS

	calls int
}

func (f *vanishingFS) ReadDir(name string) ([]fs.DirEntry, error) {
	f.calls++
	if f.calls > 1 {
		return nil, nil
	}

	return f.MapFS.ReadDir(name)
}

var (
	_ fs.ReadDirFS  = faultFS{}      //nolint:exhaustruct // interface assertion only.
	_ fs.ReadLinkFS = faultFS{}      //nolint:exhaustruct // interface assertion only.
	_ io.Reader     = faultFile{}    //nolint:exhaustruct // interface assertion only.
	_ fs.ReadDirFS  = &vanishingFS{} //nolint:exhaustruct // interface assertion only.
)
