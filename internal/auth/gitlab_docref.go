package auth

import (
	"github.com/cynative/cynative/internal/apiref"
	gitlabclass "github.com/cynative/cynative/internal/auth/gitlab"
	"github.com/cynative/cynative/internal/auth/openapidoc"
	"github.com/cynative/cynative/internal/cache"
)

// gitlabDocsUnloaded is the reason api_reference gives when the selected docs cannot be loaded and no cause was
// recorded.
const gitlabDocsUnloaded = "GitLab OpenAPI documentation could not be loaded"

// gitlabDocsChoice is the GitLab OpenAPI document api_reference reads, chosen at registration from the version
// the instance reports. The zero value reads master's document with no instance version recorded.
type gitlabDocsChoice struct {
	ref         string // the release tag to read; "" reads master.
	version     string // the version the instance reported; "" when it was not read or not recognized.
	unavailable string // why no document matches the instance; "" when one does.
}

// chooseGitLabDocs selects the document for the instance from its metadata and served authority (api_host when
// set, else host). It returns the version's classification too, since a version below the floor also skips the
// connector. Only a version that parsed is kept, and a ref comes only from the classifier, which builds it from the
// parsed numbers, so no text the instance sends reaches the document URL.
func chooseGitLabDocs(
	md metadataOutcome, served string, scrub func(string) string,
) (gitlabclass.VersionClassification, gitlabDocsChoice) {
	if !md.ok {
		return gitlabclass.VersionUnknown, gitlabDocsChoice{
			unavailable: "the instance's GitLab version could not be read: " + md.reason,
		}
	}
	class, ref, reason := gitlabclass.ClassifyVersion(md.version, stripHostPort(served), portOfAuthority(served), scrub)
	if reason != "" {
		return class, gitlabDocsChoice{unavailable: reason}
	}
	if class == gitlabclass.VersionMaster {
		ref = ""
	}

	return class, gitlabDocsChoice{ref: ref, version: md.version}
}

// useDocs records the choice and, for a release, builds that release's own docs cache. Its file stem names the
// ref, so docs read for one release, or for master in docs.json, are never served for another. Nothing loads
// until a lookup needs it. The provider holds one choice for its life, so at most one release cache exists. A
// choice other than master never reads master's docs, so the table's download is not kept for them.
func (p *gitlabProvider) useDocs(c gitlabDocsChoice) {
	p.docsChoice = c
	if c.ref != "" || c.unavailable != "" {
		p.handoff.drop()
	}
	if c.ref == "" {
		return
	}
	docs := cache.NewNamedCache(p.docsCfg, "docs-"+c.ref, p.releaseFetch(c.ref), gitlabclass.DistillReleaseDocs,
		(*openapidoc.OperationDocs).Serialize, openapidoc.Unmarshal, openapidoc.Admit)
	p.release = &openAPIDocs{cache: docs} //nolint:exhaustruct // hint latch zero-valued by design.
	p.releaseFailure = cache.RecordLoadFailure(docs)
}

// selectedDocs returns the docs the choice names and their failure recorder, or the reason no docs apply.
func (p *gitlabProvider) selectedDocs() (*openAPIDocs, *cache.LoadFailure, string) {
	switch {
	case p.docsChoice.unavailable != "":
		return nil, nil, apiref.Truncate(p.egress.Scrub("no GitLab OpenAPI document matches this instance: "+
			p.docsChoice.unavailable), apiref.MaxReason)
	case p.release != nil:
		return p.release, p.releaseFailure, ""
	}

	return &p.docs, p.docsFailure, ""
}

// statement names the document a reference was read from and the version the instance reported.
func (c gitlabDocsChoice) statement() string {
	ref := c.ref
	if ref == "" {
		ref = "master"
	}
	version := "the instance's version was not read"
	if c.version != "" {
		version = "the instance reports GitLab " + c.version
	}

	return "documentation read from gitlab-org/gitlab at ref " + ref + "; " + version
}

// unloadedReason is the reason api_reference gives when the selected docs did not load. A proxy credential in the
// recorded cause is scrubbed, as the transport scrubs its own errors.
func (p *gitlabProvider) unloadedReason(failure *cache.LoadFailure) string {
	if p.docsChoice.ref == "" {
		return failureReason(failure, gitlabDocsUnloaded, p.egress.Scrub)
	}

	return failureReason(
		failure,
		"GitLab OpenAPI documentation for "+p.docsChoice.ref+" could not be loaded",
		p.egress.Scrub,
	)
}

// failureReason returns base with the cause f recorded appended, passed through scrub and then bounded to
// [apiref.MaxReason], so a cut never leaves part of a scrubbed credential behind; base alone when nothing was
// recorded or f is nil.
func failureReason(f *cache.LoadFailure, base string, scrub func(string) string) string {
	err := f.Err()
	if err == nil {
		return base
	}

	return apiref.Truncate(scrub(base+": "+err.Error()), apiref.MaxReason)
}
