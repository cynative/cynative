package azure

import (
	"strings"
	"testing"
)

// FuzzBuildIndex pins that any listed path either stays out of the index or lands where the layout rules put it,
// and that what BuildIndex returns always passes admission and survives a serialize round trip.
//
//nolint:gocognit // Fuzz targets check many properties.
func FuzzBuildIndex(f *testing.F) {
	f.Add(computeNew)   // new layout operation file
	f.Add(webClassic)   // classic layout operation file
	f.Add(commonTypesP) // common-types ref target only
	f.Add(localCommon)  // service-local ref target only
	f.Add("specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-07-01/examples/x.json")
	f.Add("specification/compute/resource-manager/Microsoft.Compute.Admin/Compute/stable/2024-07-01/c.json")
	f.Add("specification/compute/resource-manager/compute/Compute/stable/2024-07-01/c.json")
	f.Add("specification/compute/resource-manager/Microsoft.Compute/Compute/stable/v1/c.json")
	f.Add("specification/compute/resource-manager/Microsoft.Compute/Compute/stable/2024-07-01/c.yaml")
	f.Add("specification/compute/resource-manager/Microsoft.Compute/Compute/beta/2024-07-01/c.json")
	f.Add("specification/compute/resource-manager/Microsoft.Compute/stable/c.json")
	f.Add("specification/compute/resource-manager/Microsoft.Compute/Com pute/stable/2024-07-01/c.json")
	f.Add("specification/x/data-plane/Microsoft.X/stable/2024-07-01/c.json")
	// every part in its grammar, the selector over apiref.MaxChoice
	f.Add("specification/" + strings.Repeat("s", 90) + "/resource-manager/Microsoft.X/" + strings.Repeat("v", 90) +
		"/stable/2024-07-01/c.json")
	// longest filename that passes the selector check
	f.Add("specification/x/resource-manager/Microsoft.X/stable/2024-07-01/" + strings.Repeat("f", 175) + ".json")
	f.Add("README.md")
	f.Add("")
	f.Fuzz(func(t *testing.T, path string) {
		ix, err := BuildIndex(listingOf(path, computeNew))
		if err != nil {
			t.Fatalf("BuildIndex with %q: %v", path, err)
		}
		if err = admitIndex(ix); err != nil {
			t.Fatalf("admitIndex with %q: %v", path, err)
		}
		var back *Index
		back, err = unmarshalIndex(ix.Serialize())
		if err != nil || admitIndex(back) != nil {
			t.Fatalf("round trip with %q: %v", path, err)
		}
		if _, isRef := ix.Refs[path]; isRef != refTarget(path) {
			t.Fatalf("ref membership of %q = %v, refTarget = %v", path, isRef, refTarget(path))
		}
		if of, ok := parseOpPath(path); ok {
			if !refTarget(path) {
				t.Fatalf("operation file %q is not a ref target", path)
			}
			found := false
			for _, d := range ix.Namespaces[lowerASCII(of.namespace)].Groups[of.group].Dirs {
				for _, f := range d.Files {
					found = found || (f.Path == path && d.Kind == of.kind && d.Name == of.dir)
				}
			}
			if !found {
				t.Fatalf("operation file %q is not where the index puts it", path)
			}
		}
	})
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}

	return string(b)
}
