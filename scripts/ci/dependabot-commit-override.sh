#!/bin/sh
# dependabot-commit-override.sh - render a release-please commit-override block
# from a Dependabot commit message, so the changelog lists one Dependencies
# entry per updated package instead of the opaque group title.
#
# Usage: dependabot-commit-override.sh render <body-file> < commit-message
#
# stdin  - the Dependabot head commit's full message. The authoritative package
#          list is the machine-generated `updated-dependencies:` YAML fragment;
#          old versions are enriched from the "Updates `x` from A to B" prose,
#          the "| Package | From | To |" table, or the ungrouped "Bumps x from
#          A to B." line, whichever the message carries.
# arg    - file holding the current PR body. Any existing override block in it
#          is replaced, never appended to, so reruns after a rebase are
#          idempotent.
# stdout - the new full PR body, or NOTHING when no dependencies were parsed or
#          any entry failed sanitization (the caller must then skip the edit;
#          the squash title renders as before). Fail-safe: a complete accurate
#          list or nothing, never a partial one.
# stderr - when stdout is empty, a `skip: …` reason so the caller can distinguish
#          "no metadata" from "override alone exceeds the body budget".
#
# MAX_BODY (default 60000) caps the assembled body under GitHub's 65536-char
# limit. The override is assembled first (as if the PR body were empty) so as
# many packages as possible fit; an oversized Dependabot body is then truncated
# to leave room for that override. Overflow of the package list itself still
# collapses the tail into one "deps: bump N more dependencies" entry.
set -eu

[ "${1:-}" = "render" ] && [ -n "${2:-}" ] || {
	echo "usage: $0 render <body-file> < commit-message" >&2
	exit 2
}
body_file=$2
max_body=${MAX_BODY:-60000}

# Pass 1: parse the commit message into "NAME<TAB>OLD<TAB>NEW" lines (OLD may
# be empty). Emits nothing when the fragment is absent or any entry is unsafe.
parsed=$(awk '
	# Dependabot YAML-quotes numeric-looking scalars ('\''5'\'', "25.0"); strip a
	# matched surrounding quote pair so the sanitize charset sees the value.
	function dequote(s,    q) {
		q = substr(s, 1, 1)
		if ((q == "\"" || q == "'\''") && length(s) >= 2 && substr(s, length(s), 1) == q) {
			return substr(s, 2, length(s) - 2)
		}
		return s
	}
	# Prose enrichment: Updates `NAME` from OLD to NEW (versions may be
	# backticked for submodule bumps).
	/^Updates `[^`]+` from .* to .*$/ {
		line = $0
		sub(/^Updates `/, "", line)
		name = line; sub(/`.*/, "", name)
		sub(/^[^`]*` from /, "", line)
		gsub(/`/, "", line)
		old = line; sub(/ to .*/, "", old)
		nv = line; sub(/^.* to /, "", nv); sub(/\.$/, "", nv)
		from[name] = old; tonew[name] = nv
	}
	# Ungrouped enrichment: Bumps [NAME](url) from OLD to NEW.
	/^Bumps \[[^]]+\]\([^)]*\) from .* to .*\.$/ {
		line = $0
		sub(/^Bumps \[/, "", line)
		name = line; sub(/\].*/, "", name)
		sub(/^[^)]*\) from /, "", line)
		gsub(/`/, "", line)
		old = line; sub(/ to .*/, "", old)
		nv = line; sub(/^.* to /, "", nv); sub(/\.$/, "", nv)
		from[name] = old; tonew[name] = nv
	}
	# Ungrouped enrichment without a link: Bumps NAME from OLD to NEW.
	/^Bumps [^ []+ from [^ ]+ to [^ ]+\.$/ {
		name = $2; old = $4; nv = $6
		gsub(/`/, "", name); gsub(/`/, "", old); gsub(/`/, "", nv)
		sub(/\.$/, "", nv)
		from[name] = old; tonew[name] = nv
	}
	# Table enrichment: | [NAME](url) | `OLD` | `NEW` |.
	/^\| \[/ {
		nf = split($0, f, /\|/)
		if (nf >= 5) {
			name = f[2]
			sub(/^[ ]*\[/, "", name); sub(/\].*/, "", name)
			old = f[3]; gsub(/[ `]/, "", old)
			nv = f[4]; gsub(/[ `]/, "", nv)
			if (name != "") { from[name] = old; tonew[name] = nv }
		}
	}
	# Authoritative package list: the updated-dependencies YAML fragment.
	/^updated-dependencies:$/ { inyaml = 1; next }
	inyaml && /^\.\.\.$/ { inyaml = 0 }
	inyaml && /^- dependency-name: / {
		n++
		dep = $0; sub(/^- dependency-name: /, "", dep)
		names[n] = dequote(dep); vers[n] = ""
	}
	inyaml && /^  dependency-version: / && n > 0 {
		v = $0; sub(/^  dependency-version: /, "", v)
		vers[n] = dequote(v)
	}
	END {
		if (n == 0) exit 0
		out = ""
		for (i = 1; i <= n; i++) {
			name = names[i]; nv = vers[i]; old = ""
			if (name in from) old = from[name]
			if (nv == "" && (name in tonew)) nv = tonew[name]
			key = name "\t" nv
			if (key in seen) continue
			seen[key] = 1
			# Fail-safe sanitization: any entry outside the safe
			# charset abandons the whole render.
			if (name !~ /^[A-Za-z0-9@._\/+-]+$/) exit 0
			if (nv != "" && nv !~ /^[A-Za-z0-9._+-]+$/) exit 0
			if (old != "" && old !~ /^[A-Za-z0-9._+-]+$/) old = ""
			# A marker substring in any field would corrupt the override
			# framing (release-please and our own strip scan both match
			# markers unanchored), so the render abandons, the same
			# fail-safe as the charset checks above.
			if ((name old nv) ~ /(BEGIN|END)_(COMMIT_OVERRIDE|NESTED_COMMIT)/) exit 0
			out = out name "\t" old "\t" nv "\n"
		}
		printf "%s", out
	}
')
if [ -z "$parsed" ]; then
	echo "skip: no dependency metadata" >&2
	exit 0
fi

# Pass 2: drop any previous override block from the body (replace, not append).
stripped=$(awk '
	index($0, "BEGIN_COMMIT_OVERRIDE") { skip = 1 }
	skip == 0 { print }
	index($0, "END_COMMIT_OVERRIDE") { skip = 0 }
' "$body_file")

# Pass 3: assemble the override block under the body budget as if the PR body
# were empty. That maximizes per-package entries; an oversized Dependabot body
# (which routinely hits GitHub's 65536-char ceiling) is truncated afterward so
# the override still fits. Raising MAX_BODY alone cannot fix that case: the
# rendered override plus a full Dependabot body exceeds GitHub's hard limit.
block=$(printf '%s' "$parsed" | awk -F '\t' -v max="$max_body" '
	{
		if ($2 != "" && $3 != "") l = "deps: bump " $1 " from " $2 " to " $3
		else if ($3 != "") l = "deps: bump " $1 " to " $3
		else l = "deps: bump " $1
		lines[NR] = l
	}
	END {
		if (NR == 0) exit 0
		# bodylen is fixed at 0 here; the "\n\n" separator is charged when the
		# truncated body is non-empty (see keep calc below).
		reserve = 80
		tail = "\nEND_COMMIT_OVERRIDE"
		first = "BEGIN_COMMIT_OVERRIDE\n" lines[1]
		r = (NR > 1) ? reserve : 0
		if (length(first) + length(tail) + r > max) exit 0
		block = first
		used = 1
		for (i = 2; i <= NR; i++) {
			add = "\nBEGIN_NESTED_COMMIT\n" lines[i] "\nEND_NESTED_COMMIT"
			cand = block add
			r2 = (i < NR) ? reserve : 0
			if (length(cand) + length(tail) + r2 > max) break
			block = cand
			used++
		}
		if (used < NR) {
			left = NR - used
			block = block "\nBEGIN_NESTED_COMMIT\ndeps: bump " left " more dependencies\nEND_NESTED_COMMIT"
		}
		printf "%s%s", block, tail
	}
')
if [ -z "$block" ]; then
	echo "skip: override exceeds body budget" >&2
	exit 0
fi

# Truncate the existing body so body + separator + override stay under MAX_BODY.
# Prefer dropping Dependabot prose over dropping package rows: the override is
# what release-please renders into the changelog.
blocklen=$(printf '%s' "$block" | wc -c)
keep=$((max_body - blocklen))
if [ -n "$stripped" ]; then
	# Charge the blank-line separator between body and override.
	keep=$((keep - 2))
fi
if [ "$keep" -lt 0 ]; then
	echo "skip: override exceeds body budget" >&2
	exit 0
fi
if [ -n "$stripped" ]; then
	bodylen=$(printf '%s' "$stripped" | wc -c)
	if [ "$bodylen" -gt "$keep" ]; then
		if [ "$keep" -eq 0 ]; then
			stripped=""
		else
			stripped=$(printf '%s' "$stripped" | awk -v n="$keep" '
				BEGIN { ORS = "" }
				{ buf = buf $0 RT }
				END { print substr(buf, 1, n) }
			')
		fi
	fi
fi

if [ -n "$stripped" ]; then
	printf '%s\n\n%s\n' "$stripped" "$block"
else
	printf '%s\n' "$block"
fi
