package authreq

// UnmatchedRequestError marks a gate failure where the request matched no
// operation in the metadata the gate holds. It does not claim the request is
// wrong (the metadata can be stale) and it is never a permission decision.
// Error and Unwrap pass through to the gate's own error, so its text and
// [errors.Is] identity are unchanged.
type UnmatchedRequestError struct {
	// Service is a connector-specific namespace, such as the AWS endpoint
	// prefix. It is empty when the connector has one API.
	Service string
	Err     error
}

// Error returns the wrapped gate error's text unchanged.
func (e *UnmatchedRequestError) Error() string { return e.Err.Error() }

// Unwrap returns the gate's own error.
func (e *UnmatchedRequestError) Unwrap() error { return e.Err }
