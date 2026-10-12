package azure

import (
	"net/http"

	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

// openUploadSession opens a smart-HTTP upload-pack session on repoURL through client. go-git follows no redirect:
// NoFollowRedirects refuses every hop, and client's own CheckRedirect still runs inside go-git's wrapper.
func openUploadSession(client *http.Client, repoURL string) (transport.UploadPackSession, error) {
	ep, err := transport.NewEndpoint(repoURL)
	if err != nil {
		return nil, err
	}

	return githttp.NewClientWithOptions(client, &githttp.ClientOptions{
		RedirectPolicy: githttp.NoFollowRedirects,
	}).NewUploadPackSession(ep, nil)
}
