package transport

// WithSystemCertPool returns an Option that replaces the system certificate pool
// function. Used in tests to inject a failing function and cover the fallback path.
func WithSystemCertPool(fn certPoolFunc) Option {
	return func(c *Client) { c.systemCertPool = fn }
}

// WithReadAll returns an Option that replaces the [io.ReadAll] function.
// Used in tests to inject a failing function and cover the error path.
func WithReadAll(fn readAllFunc) Option {
	return func(c *Client) { c.readAll = fn }
}

// WithRedactor returns an Option that replaces the response redactor. Used in
// tests to inject redact.New() explicitly or a fake that counts invocations.
func WithRedactor(r redactor) Option {
	return func(c *Client) { c.redactor = r }
}
