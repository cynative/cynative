package auth

const defaultRegion = "us-east-1"

// resolveRegion returns the first non-empty region from the provided values,
// falling back to "us-east-1" if all are empty.
func resolveRegion(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}

	return defaultRegion
}
