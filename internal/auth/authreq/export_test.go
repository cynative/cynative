package authreq_test

import "net/http"

// setConflictingAuthority sets the wire authority to a value that disagrees
// with the URL, so the projection can be shown to ignore it. This is the only
// place in the package that touches the field, and it exists solely to prove
// the view does not.
func setConflictingAuthority(req *http.Request, authority string) {
	req.Host = authority //nolint:forbidigo // proving the view ignores this field is the test's whole purpose.
}
