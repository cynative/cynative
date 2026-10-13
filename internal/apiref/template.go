package apiref

import "strings"

// Placeholder names an input in a request template, marking one the reference could not render.
func Placeholder(in Input) string {
	if !in.Renderable {
		return "<" + in.Name + ":unrendered>"
	}

	return "<" + in.Name + ">"
}

// RequiredAt lists the required inputs at a location.
func RequiredAt(ref *Reference, loc Location) []Input {
	var out []Input
	for _, in := range ref.Inputs {
		if in.Required && in.Location == loc {
			out = append(out, in)
		}
	}

	return out
}

// ParamPairs renders fixed pairs as key=value, or the bare key when the value is empty. Keys and values are joined
// as given: a connector that puts them in FixedQuery escapes them first.
func ParamPairs(ps []Param) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if p.Value == "" {
			out = append(out, p.Key)
		} else {
			out = append(out, p.Key+"="+p.Value)
		}
	}

	return out
}

// TemplateURL is the URL an http_request template carries: the endpoint, the path with each {label} replaced by
// its placeholder, then the fixed query pairs and each required query input.
func TemplateURL(ref *Reference) string {
	segs := strings.Split(ref.PathTemplate, "/")
	for i, s := range segs {
		segs[i] = segmentPlaceholders(ref, s)
	}
	query := ParamPairs(ref.FixedQuery)
	for _, in := range RequiredAt(ref, LocationQuery) {
		query = append(query, in.WireName+"="+Placeholder(in))
	}
	u := ref.Endpoint + strings.Join(segs, "/")
	if len(query) > 0 {
		u += "?" + strings.Join(query, "&")
	}

	return u
}

// segmentPlaceholders replaces every {label} in one path segment with its placeholder: a whole-segment label as in
// /things/{Id}, or one inside literal text as in GitLab's {file_name}.tgz.
func segmentPlaceholders(ref *Reference, seg string) string {
	var b strings.Builder
	for {
		open := strings.IndexByte(seg, '{')
		if open < 0 {
			break
		}
		end := strings.IndexByte(seg[open:], '}')
		if end < 0 {
			break
		}
		name, greedy := strings.CutSuffix(seg[open+1:open+end], "+")
		b.WriteString(seg[:open])
		b.WriteString(pathPlaceholder(ref, name, greedy))
		seg = seg[open+end+1:]
	}
	b.WriteString(seg)

	return b.String()
}

// pathPlaceholder names a path label, keeping the '+' of a greedy label so the note can say its value spans
// segments, and marking it when the first path input of that name could not be rendered.
func pathPlaceholder(ref *Reference, name string, greedy bool) string {
	label := name
	if greedy {
		label += "+"
	}
	for _, in := range ref.Inputs {
		if in.Location == LocationPath && in.Name == name {
			if !in.Renderable {
				return "<" + label + ":unrendered>"
			}

			break
		}
	}

	return "<" + label + ">"
}
