package aws

import "testing"

// TarGzForTest builds an in-memory .tar.gz from name→content entries.
func TarGzForTest(t *testing.T, files map[string]string) []byte { return makeTarGz(t, files) }

// ModelJSONForTest renders a minimal Smithy service model.
func ModelJSONForTest(sdkID, arn, ep, proto string) string { return model(sdkID, arn, ep, proto) }
