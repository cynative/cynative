package apiref

import "slices"

// Choices sorts, truncates and bounds a list of ambiguity choices: at most MaxChoices, each at most MaxChoice runes.
func Choices(items []string) []string {
	out := slices.Clone(items)
	slices.Sort(out)
	if len(out) > MaxChoices {
		out = out[:MaxChoices]
	}
	for i, c := range out {
		out[i] = Truncate(c, MaxChoice)
	}
	return out
}
