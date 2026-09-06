#!/bin/sh
# agents-catalog.unit.test.sh - offline unit tests for the built-in agent
# catalog renderer (scripts/docs/agents-catalog.sh).
#
# Hermetic: no network, no credentials, no git. Renders synthetic agent files in
# a temporary tree and asserts the description cell carries the YAML value
# rather than its source spelling, and that a value containing the table
# delimiter cannot split the row. The agent parser (internal/agentcatalog)
# accepts a quoted scalar, so these spellings are all valid input.
# Run by `make sh-test`.
set -eu

here=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/.." && pwd)
render="$root/scripts/docs/agents-catalog.sh"

fails=0
pass() { printf 'ok: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/agents" "$tmp/docs"

# One agent per spelling under test. The slug prefix decides the group heading,
# so they all share one to keep the table in a single section.
write_agent() {
  printf -- '---\ndescription: %s\n---\n\nResearch something.\n' "$2" > "$tmp/agents/aws-$1.md"
}

write_agent plain 'Plain value.'
write_agent dquoted '"Double quoted value."'
write_agent squoted "'Single quoted value.'"
write_agent pipe 'Check x | y.'
write_agent dquoted-pipe '"Check x | y."'
write_agent dquoted-escape '"He said \"hi\" once."'
write_agent squoted-escape "'It''s here.'"
write_agent trailing '"Trailing space."   '

(cd "$tmp" && sh "$render" > /dev/null)
out="$tmp/docs/agents-catalog.md"

# cell <slug> prints the rendered description cell for that agent's row.
cell() { sed -n "s/^| \`aws-$1\` | \(.*\) |$/\1/p" "$out"; }

check() {
  got=$(cell "$1")
  if [ "$got" = "$2" ]; then pass "$1: $2"; else fail "$1: got [$got] want [$2]"; fi
}

check plain 'Plain value.'
check dquoted 'Double quoted value.'
check squoted 'Single quoted value.'
check dquoted-escape 'He said "hi" once.'
check squoted-escape "It's here."
check trailing 'Trailing space.'


# The delimiter is escaped, so every row keeps exactly three unescaped pipes:
# the two cell borders and the one between the name and the description.
check pipe 'Check x \| y.'
check dquoted-pipe 'Check x \| y.'

for slug in pipe dquoted-pipe; do
  row=$(grep -F "| \`aws-$slug\` |" "$out")
  bare=$(printf '%s\n' "$row" | sed 's/\\|//g' | tr -cd '|' | wc -c)
  if [ "$bare" -eq 3 ]; then
    pass "$slug: row keeps 3 unescaped delimiters"
  else
    fail "$slug: row has $bare unescaped delimiters, want 3"
  fi
done

# A code span survives verbatim: the pipe escape is valid Markdown inside one,
# so nothing else in the cell needs escaping. The backtick comes from a variable
# for the same reason the renderer builds one that way.
tick='`'
write_agent codespan "Inspect the ${tick}--flag${tick} value."
write_agent codespan-pipe "Inspect ${tick}a|b${tick} closely."
(cd "$tmp" && sh "$render" > /dev/null)
check codespan "Inspect the ${tick}--flag${tick} value."
check codespan-pipe "Inspect ${tick}a\\|b${tick} closely."

# An escape the renderer cannot decode faithfully fails loudly rather than
# emitting a corrupted value. Each is valid input to the agent parser, so
# silence here would ship a wrong catalog that --check then accepts.
reject() {
  write_agent bad "$1"
  if err=$(cd "$tmp" && sh "$render" 2>&1 >/dev/null); then
    fail "$2: rendered instead of failing"
  elif printf '%s' "$err" | grep -q 'aws-bad.md'; then
    pass "$2: fails and names the file"
  else
    fail "$2: failed without naming the file: $err"
  fi
  rm -f "$tmp/agents/aws-bad.md"
}

reject '"Check \x41 now."' 'hex escape'
reject 'Find exposures. # rationale' 'plain scalar carrying a comment'
reject 'Check issue #5 now.' 'comment that swallows the rest of the value'
reject '>-' 'folded block scalar'
reject '|' 'literal block scalar'
reject '' 'no value on the description line'
reject '!!str Tagged value.' 'explicit tag'
reject '&anchor Anchored value.' 'anchor'
reject '[a, b]' 'flow collection'
reject '"Not closed.' 'unclosed quote'

# A plain scalar continued on the following lines: YAML folds it into one value,
# so rendering the description line alone would truncate it silently.
write_agent cont 'Find exposures'
printf -- '---\ndescription: Find exposures\n  across accounts.\n---\n\nx\n' > "$tmp/agents/aws-cont.md"
if err=$(cd "$tmp" && sh "$render" 2>&1 >/dev/null); then
  fail "continued plain scalar: rendered instead of failing"
elif printf '%s' "$err" | grep -q 'aws-cont.md'; then
  pass "continued plain scalar: fails and names the file"
else
  fail "continued plain scalar: failed without naming the file: $err"
fi
rm -f "$tmp/agents/aws-cont.md"

# A file written on Windows carries CRLF. The agent parser tolerates it, so the
# renderer must too: the carriage return must not defeat the closing-fence match
# and leave a body line looking like a continuation.
printf -- '---\r\ndescription: Written on Windows.\r\n---\r\n\r\n    body line\r\n' > "$tmp/agents/aws-crlf.md"
(cd "$tmp" && sh "$render" > /dev/null)
check crlf 'Written on Windows.'
rm -f "$tmp/agents/aws-crlf.md"

# A bare carriage return is a YAML line break, so the value continues past it
# and the renderer would otherwise emit the source bytes.
printf -- '---\ndescription: \r  Value.\n---\nbody\n' > "$tmp/agents/aws-barecr.md"
if err=$(cd "$tmp" && sh "$render" 2>&1 >/dev/null); then
  fail "bare carriage return: rendered instead of failing"
elif printf '%s' "$err" | grep -q 'aws-barecr.md'; then
  pass "bare carriage return: fails and names the file"
else
  fail "bare carriage return: failed without naming the file: $err"
fi
rm -f "$tmp/agents/aws-barecr.md"
reject 'Inspect \\server\share.' 'backslash in a plain scalar'
reject '"Inspect \\\\server\\share."' 'backslash decoded from a quoted scalar'
reject '"Check \u0042 now."' 'unicode escape'
reject '"Ends in a backslash \"' 'trailing backslash'

# The renderer must not have left a partial catalog behind after a rejection.
(cd "$tmp" && sh "$render" > /dev/null)

[ "$fails" -eq 0 ] || { printf '%d failure(s)\n' "$fails" >&2; exit 1; }
printf 'OK: agents-catalog unit tests\n'
