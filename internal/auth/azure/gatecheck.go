package azure

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
	"github.com/cynative/cynative/internal/auth/authreq"
)

// The gate check's texts. The api_reference docs quote them, so a change here is a docs change.
const (
	gateNotStatic      = "gate recognition not checked: the path's resource type is set by an input"
	gateDeniesPrefix   = "the azure gate denies this path: "
	gateRoleNotChecked = "the gate check classifies the path against the gate's catalog; it does not check whether " +
		"the configured role allows the action"
	// gateCheckFill is the value every name label takes for the check. It is no resource type and no RBAC verb.
	gateCheckFill = "x1"
	// gateCheckHost is any ARM host: the classifier reads only the method and the path.
	gateCheckHost = "management.azure.com"
)

// gateLabel matches one {label} inside a path segment.
var gateLabel = regexp.MustCompile(`\{[^{}]*\}`)

// applyGateCheck records on ref what the gate's already-loaded catalog says about its path: a gap when the gate
// denies it, or a limitation saying why the check did not run. It peeks only for a path whose shape is static, and
// never loads the catalog.
func applyGateCheck(ctx context.Context, gate func() Catalog, ref *apiref.Reference) {
	if !staticShape(ref.PathTemplate) {
		ref.Limitations = append(ref.Limitations, gateNotStatic)

		return
	}
	snap := gate()
	if snap == nil {
		ref.Limitations = append(ref.Limitations, gateNotLoaded)

		return
	}
	if _, err := checkGate(ctx, snap, ref.Method, ref.PathTemplate); err != nil {
		ref.Gaps = append(ref.Gaps, gateDeniesPrefix+apiref.Truncate(err.Error(), apiref.MaxGateDetail))
	}
	ref.Limitations = append(ref.Limitations, gateRoleNotChecked)
}

// checkGate classifies path, its labels filled with gateCheckFill, the way the gate does, against snap. It reports
// false, and no error, when the path's shape is not static, since a placeholder in a type position would classify
// as a different resource than the caller's value does.
func checkGate(ctx context.Context, snap Catalog, method, path string) (bool, error) {
	if !staticShape(path) {
		return false, nil
	}
	// The template path is escaped as it goes on the wire (a fixed enum value a/b is a%2Fb), so it is parsed the way
	// the transport parses a request URL, never put into url.URL.Path, which would escape it a second time.
	u, err := url.Parse("https://" + gateCheckHost + gateLabel.ReplaceAllString(path, gateCheckFill))
	if err != nil {
		return true, fmt.Errorf("%w: the template path does not parse: %w", ErrActionUnresolved, err)
	}
	v := authreq.NewView(&http.Request{Method: method, URL: u, Header: http.Header{}}, "")
	a, err := DeriveAction(ctx, v, snap)
	if err != nil {
		return true, err
	}

	return true, ValidateAction(ctx, snap, a)
}

// staticShape reports whether every label in path sits where the gate reads a resource name, so filling it with any
// value classifies the same way. A greedy label ({name+}) can span segments and is never static. With a namespace
// (resolveNamespace), the namespace and every type position after it (even offsets) must be literal. A provider-less
// path keeps its labels at the odd offsets, the {} slots of providerLessRoutes.
func staticShape(path string) bool {
	segs := splitPath(path)
	for _, s := range segs {
		if strings.Contains(s, "+}") {
			return false
		}
	}
	namespace, rest, ok := resolveNamespace(segs)
	if !ok {
		return labelsOnlyAtOdd(segs)
	}
	if hasLabel(namespace) {
		return false
	}

	return labelsOnlyAtOdd(rest)
}

// labelsOnlyAtOdd reports whether every segment at an even offset is literal.
func labelsOnlyAtOdd(segs []string) bool {
	for i := 0; i < len(segs); i += typeNameStride {
		if hasLabel(segs[i]) {
			return false
		}
	}

	return true
}

func hasLabel(seg string) bool { return strings.Contains(seg, "{") }
