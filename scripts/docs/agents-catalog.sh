#!/usr/bin/env sh
# Regenerates docs/agents-catalog.md from the frontmatter of agents/*.md.
# Run from the repository root:  sh scripts/docs/agents-catalog.sh
# Pass --check to render from the index (the agent files and the catalog as they
# are staged, which in CI is the commit under test) and compare the two, writing
# nothing; that is how the gate fails a stale catalog. Exit 1 means stale or not
# tracked, exit 2 means bad usage. With no argument it rewrites the working tree
# file. Commit the agent change and the regenerated catalog together.
set -eu

out="docs/agents-catalog.md"
mode="write"
if [ "${1:-}" = "--check" ]; then
  mode="check"
elif [ "$#" -gt 0 ]; then
  echo "usage: $(basename "$0") [--check]" >&2
  exit 2
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

if [ "$mode" = "check" ]; then
  # Both sides of the comparison are raw index blobs, so they describe the same
  # thing: the agents and the catalog exactly as staged. A working-tree copy an
  # earlier generate step rewrote never enters it, a partially staged edit can
  # neither fail the check spuriously nor slip a stale catalog past it, and no
  # end-of-line or smudge conversion touches either side, which checkout-index
  # would apply. quotePath is off so a non-ASCII name reaches cat-file as the
  # bytes the index holds rather than C-quoted.
  stage="$(mktemp -d)"
  trap 'rm -rf "$tmp" "$stage"' EXIT
  git -c core.quotePath=false ls-files -- agents "$out" | while IFS= read -r path; do
    mkdir -p "$stage/$(dirname "$path")"
    git cat-file blob ":$path" > "$stage/$path"
  done
  if [ ! -d "$stage/agents" ]; then
    echo "error: no agents/ entries in the index; run from the repository root" >&2
    exit 1
  fi
  if [ ! -f "$stage/$out" ]; then
    echo "error: $out is not in the index; run 'make generate' and git add it" >&2
    exit 1
  fi
  cd "$stage" || exit 1
fi

group_title() {
  case "$1" in
    aws) echo "AWS" ;;
    azure) echo "Azure" ;;
    gcp) echo "GCP" ;;
    github) echo "GitHub" ;;
    k8s) echo "Kubernetes" ;;
    *) echo "$1" ;;
  esac
}

# The frontmatter description, rendered for a Markdown table cell.
#
# This reads the frontmatter and reproduces the three scalar forms it can render
# exactly: plain, single-quoted, and double-quoted carrying only the quote and
# backslash escapes. Every other YAML form is refused by name rather than
# half-read, because the source spelling is not the value: a block scalar, a tag
# or an anchor put the value somewhere this does not read; a plain scalar ends
# at a comment, so `Check issue #5 now.` is the value `Check issue`; and a plain
# scalar continued on the following lines would otherwise render truncated.
# Reading the whole frontmatter rather than the description line alone is what
# makes that last one visible.
#
# Only the pipe is escaped on the way out. It ends the cell, and the escape is
# valid Markdown anywhere in one, a code span included. A backslash surviving
# into the value is refused instead: Markdown consumes it as an escape in prose
# and keeps it literally inside a code span, so it has no single rendering.
#
# The agent parser (internal/agentcatalog) is the authority on which files are
# valid; this is the narrower set the catalog can typeset. Each refusal names
# the file and says what to write instead.
description() {
  awk -v file="$1" -v sq="'" -v dq='"' '
      BEGIN { bs = "\\"; indicators = "-?:,[]{}#&*!|>%@`" bs sq dq }
      function fail(msg) {
        printf "error: %s: %s\n", file, msg > "/dev/stderr"
        exit 1
      }
      function unquote_double(s,   out, i, c, len) {
        len = length(s)
        for (i = 1; i <= len; i++) {
          c = substr(s, i, 1)
          if (c != bs) { out = out c; continue }
          if (i == len) fail("description ends in a backslash")
          i++
          c = substr(s, i, 1)
          if (c != dq && c != bs) {
            fail("description carries the escape " bs c ", which this renderer does not decode; write it plain or single-quoted")
          }
          out = out c
        }
        return out
      }
      function check_plain(s,   c) {
        if (s == "") {
          fail("the description line carries no value; this renderer reads the value from that line, so a block scalar or a continuation on the following lines is not read")
        }
        c = substr(s, 1, 1)
        if (index(indicators, c) > 0) {
          fail("description begins with " c ", which starts a YAML form this renderer does not read (a block scalar, tag, anchor, flow collection, or an unclosed quote); write it as a plain, single-quoted or double-quoted scalar")
        }
        if (s ~ /[ \t]#/) {
          fail("description carries a comment, which YAML drops from the value; remove it or quote the description")
        }
      }
      function escape_pipe(s,   out, i, c) {
        for (i = 1; i <= length(s); i++) {
          c = substr(s, i, 1)
          if (c == "|") out = out bs
          out = out c
        }
        return out
      }
      # A file written on Windows carries CRLF; the parser tolerates it, so the
      # fence match and the value must not see the carriage return.
      { sub(/\r$/, "") }
      NR == 1 { next }
      /^---[ \t]*$/ { exit }
      !found && index($0, "description:") == 1 {
        raw = substr($0, length("description:") + 1)
        sub(/^[ \t]+/, "", raw)
        found = 1
        next
      }
      # Inside the frontmatter, an indented line after the description is that
      # scalar continuing. Its text is part of the value and is not read here,
      # so rendering the first line alone would silently truncate it.
      found && /^[ \t]+[^ \t]/ {
        fail("description continues on the following line; write it on the description line alone")
      }
      END {
        if (!found) fail("no description line in the frontmatter")
        v = raw
        # A bare carriage return is a YAML line break, so the value carries on
        # past it and the trailing-CR strip above cannot reach it. Refuse rather
        # than render the source bytes.
        if (index(v, "\r") > 0) {
          fail("description carries a carriage return; write it on one line with Unix or Windows line endings")
        }
        sub(/[ \t]+$/, "", v)
        n = length(v)
        if (n >= 2 && substr(v, 1, 1) == dq && substr(v, n, 1) == dq) {
          v = unquote_double(substr(v, 2, n - 2))
        } else if (n >= 2 && substr(v, 1, 1) == sq && substr(v, n, 1) == sq) {
          v = substr(v, 2, n - 2)
          gsub(sq sq, sq, v)
        } else {
          check_plain(v)
        }
        if (v == "") fail("description is empty")
        if (index(v, bs) > 0) {
          fail("description carries a backslash, which Markdown renders differently in prose and in a code span; rewrite it without one")
        }
        print escape_pipe(v)
      }
    ' "$1"
}

# Number of arguments; called with a glob so the shell, not ls, does the counting.
count() {
  echo "$#"
}

bt='`'
total=$(count agents/*.md)

{
  echo "# Built-in agent catalog"
  echo
  echo "<!-- Generated by scripts/docs/agents-catalog.sh from agents/*.md. Do not edit by hand. -->"
  echo
  echo "Cynative ships with $total built-in agents. Run one with"
  echo "${bt}cynative -p --agent <name>${bt}, print it with ${bt}cynative agents show <name>${bt},"
  echo "and see [agents.md](agents.md) for how to write your own."
  echo

  prev=""
  for f in agents/*.md; do
    name=$(basename "$f" .md)
    group=${name%%-*}
    if [ "$group" != "$prev" ]; then
      [ -n "$prev" ] && echo
      n=$(count agents/"$group"-*.md)
      echo "## $(group_title "$group") ($n)"
      echo
      echo "| Agent | What it answers |"
      echo "|---|---|"
      prev=$group
    fi
    desc=$(description "$f") || exit 1
    printf '| %s%s%s | %s |\n' "$bt" "$name" "$bt" "$desc"
  done
} > "$tmp"

if [ "$mode" = "check" ]; then
  if ! cmp -s "$out" "$tmp"; then
    echo "error: $out is stale; run 'make generate' and commit the result" >&2
    diff -u "$out" "$tmp" >&2 || true
    exit 1
  fi
  echo "ok: $out is up to date ($total agents)"
else
  # mktemp creates the file 0600; restore the world-readable mode Git tracks so
  # make generate does not flip docs/agents-catalog.md to owner-only.
  chmod 0644 "$tmp"
  mv "$tmp" "$out"
  echo "wrote $out ($total agents)"
fi
