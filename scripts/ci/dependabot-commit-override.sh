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
#
# MAX_BODY (default 60000) caps the assembled body under GitHub's 65536-char
# limit; overflow collapses the tail into one "deps: bump N more dependencies"
# entry so the count stays honest.
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
		names[n] = dep; vers[n] = ""
	}
	inyaml && /^  dependency-version: / && n > 0 {
		v = $0; sub(/^  dependency-version: /, "", v)
		vers[n] = v
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
			out = out name "\t" old "\t" nv "\n"
		}
		printf "%s", out
	}
')
[ -n "$parsed" ] || exit 0

# Pass 2: drop any previous override block from the body (replace, not append).
stripped=$(awk '
	index($0, "BEGIN_COMMIT_OVERRIDE") { skip = 1 }
	skip == 0 { print }
	index($0, "END_COMMIT_OVERRIDE") { skip = 0 }
' "$body_file")
bodylen=$(printf '%s' "$stripped" | wc -c)

# Pass 3: assemble the override block within the body budget. The first entry
# sits directly after the marker; every further entry is a nested commit, which
# is what release-please splits on (blank-line splitting does not recognize the
# deps type).
block=$(printf '%s' "$parsed" | awk -F '\t' -v bodylen="$bodylen" -v max="$max_body" '
	{
		if ($2 != "" && $3 != "") l = "deps: bump " $1 " from " $2 " to " $3
		else if ($3 != "") l = "deps: bump " $1 " to " $3
		else l = "deps: bump " $1
		lines[NR] = l
	}
	END {
		if (NR == 0) exit 0
		reserve = 80
		tail = "\nEND_COMMIT_OVERRIDE"
		# The first entry is admitted only if it fits the budget too; when even
		# that does not fit, emit nothing so the caller skips the edit and the
		# group title renders unchanged.
		first = "BEGIN_COMMIT_OVERRIDE\n" lines[1]
		r = (NR > 1) ? reserve : 0
		if (bodylen + 2 + length(first) + length(tail) + r > max) exit 0
		block = first
		used = 1
		for (i = 2; i <= NR; i++) {
			add = "\nBEGIN_NESTED_COMMIT\n" lines[i] "\nEND_NESTED_COMMIT"
			cand = block add
			if (bodylen + 2 + length(cand) + length(tail) + reserve > max) break
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
[ -n "$block" ] || exit 0

if [ -n "$stripped" ]; then
	printf '%s\n\n%s\n' "$stripped" "$block"
else
	printf '%s\n' "$block"
fi
