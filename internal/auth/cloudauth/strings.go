package cloudauth

import "strings"

// DefaultMaxErrorLen is the default byte cap for ShortenError — keeps an
// operator log line grep-friendly. The AWS cred-scope degrade warning uses it.
const DefaultMaxErrorLen = 120

// ShortenError flattens err into a single short token for an operator log:
// strips newlines and carriage returns, then truncates to n bytes, appending
// an ellipsis when truncated.
func ShortenError(err error, n int) string {
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
