#!/bin/sh
# dependabot-override.unit.test.sh - offline unit tests for the per-package
# changelog override renderer (scripts/ci/dependabot-commit-override.sh).
#
# Hermetic: no network, no credentials. Exercises the parser against the three
# real Dependabot message shapes (prose, table, ungrouped), the fail-safe empty
# outputs, idempotent body replacement, sanitization, and the MAX_BODY overflow
# summary. Run by `make sh-test`.
set -eu

here=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/.." && pwd)
render="$root/scripts/ci/dependabot-commit-override.sh"

fails=0
pass() { printf 'ok: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Prose-shaped grouped message (modeled on PR #142).
cat > "$tmp/prose.msg" <<'EOF'
deps: Bump the all-dependencies group with 2 updates

Bumps the all-dependencies group with 2 updates: [github.com/maximhq/bifrost/core](https://github.com/maximhq/bifrost) and [github.com/go-openapi/strfmt](https://github.com/go-openapi/strfmt).

Updates `github.com/maximhq/bifrost/core` from 1.7.1 to 1.7.2
- [Release notes](https://github.com/maximhq/bifrost/releases)

Updates `github.com/go-openapi/strfmt` from 0.26.4 to 0.27.0
- [Release notes](https://github.com/go-openapi/strfmt/releases)

---
updated-dependencies:
- dependency-name: github.com/maximhq/bifrost/core
  dependency-version: 1.7.2
  dependency-type: direct:production
  update-type: version-update:semver-patch
  dependency-group: all-dependencies
- dependency-name: github.com/go-openapi/strfmt
  dependency-version: 0.27.0
  dependency-type: indirect
  update-type: version-update:semver-minor
  dependency-group: all-dependencies
...

Signed-off-by: dependabot[bot] <support@github.com>
EOF

printf 'Original PR body.\n' > "$tmp/body.txt"

# ---- prose shape: one entry per package, first plain, rest nested ------------
if (
	out=$("$render" render "$tmp/body.txt" < "$tmp/prose.msg") || exit 1
	[ -n "$out" ] || exit 1
	printf '%s\n' "$out" | grep -q '^Original PR body\.$' || exit 1
	[ "$(printf '%s\n' "$out" | grep -c '^BEGIN_COMMIT_OVERRIDE$')" = "1" ] || exit 1
	[ "$(printf '%s\n' "$out" | grep -c '^END_COMMIT_OVERRIDE$')" = "1" ] || exit 1
	# First entry directly after the marker, unnested.
	printf '%s\n' "$out" | grep -A1 '^BEGIN_COMMIT_OVERRIDE$' \
		| grep -q '^deps: bump github.com/maximhq/bifrost/core from 1.7.1 to 1.7.2$' || exit 1
	# Second entry nested.
	[ "$(printf '%s\n' "$out" | grep -c '^BEGIN_NESTED_COMMIT$')" = "1" ] || exit 1
	printf '%s\n' "$out" | grep -q '^deps: bump github.com/go-openapi/strfmt from 0.26.4 to 0.27.0$' || exit 1
	exit 0
); then pass "prose shape renders per-package override"; else fail "prose shape"; fi

# ---- idempotence: re-running on its own output replaces, not appends ---------
if (
	out1=$("$render" render "$tmp/body.txt" < "$tmp/prose.msg") || exit 1
	printf '%s\n' "$out1" > "$tmp/body2.txt"
	out2=$("$render" render "$tmp/body2.txt" < "$tmp/prose.msg") || exit 1
	[ "$out1" = "$out2" ] || exit 1
	exit 0
); then pass "idempotent replacement of an existing override block"; else fail "idempotence"; fi

# ---- table shape (modeled on PR #124) -----------------------------------------
cat > "$tmp/table.msg" <<'EOF'
deps: Bump the all-dependencies group with 2 updates

Bumps the all-dependencies group with 2 updates:

| Package | From | To |
| --- | --- | --- |
| [cel.dev/expr](https://github.com/google/cel-spec) | `0.25.1` | `0.25.2` |
| [cloud.google.com/go/auth](https://github.com/googleapis/google-cloud-go) | `0.20.0` | `0.22.0` |

---
updated-dependencies:
- dependency-name: cel.dev/expr
  dependency-version: 0.25.2
  dependency-type: indirect
- dependency-name: cloud.google.com/go/auth
  dependency-version: 0.22.0
  dependency-type: indirect
...
EOF

if (
	out=$("$render" render "$tmp/body.txt" < "$tmp/table.msg") || exit 1
	printf '%s\n' "$out" | grep -q '^deps: bump cel.dev/expr from 0.25.1 to 0.25.2$' || exit 1
	printf '%s\n' "$out" | grep -q '^deps: bump cloud.google.com/go/auth from 0.20.0 to 0.22.0$' || exit 1
	exit 0
); then pass "table shape enriches old versions"; else fail "table shape"; fi

# ---- ungrouped security shape -------------------------------------------------
cat > "$tmp/single.msg" <<'EOF'
deps: Bump golang.org/x/net from 0.30.0 to 0.33.0

Bumps [golang.org/x/net](https://github.com/golang/net) from 0.30.0 to 0.33.0.

---
updated-dependencies:
- dependency-name: golang.org/x/net
  dependency-version: 0.33.0
  dependency-type: indirect
...
EOF

if (
	out=$("$render" render "$tmp/body.txt" < "$tmp/single.msg") || exit 1
	printf '%s\n' "$out" | grep -q '^deps: bump golang.org/x/net from 0.30.0 to 0.33.0$' || exit 1
	exit 0
); then pass "ungrouped shape parses Bumps prose"; else fail "ungrouped shape"; fi

# ---- missing old version falls back to the "to NEW" form ----------------------
cat > "$tmp/nofrom.msg" <<'EOF'
deps: Bump the all-dependencies group with 1 update

---
updated-dependencies:
- dependency-name: github.com/example/mod
  dependency-version: 2.0.0
  dependency-type: indirect
...
EOF

if (
	out=$("$render" render "$tmp/body.txt" < "$tmp/nofrom.msg") || exit 1
	printf '%s\n' "$out" | grep -q '^deps: bump github.com/example/mod to 2.0.0$' || exit 1
	exit 0
); then pass "missing old version renders to-only form"; else fail "to-only form"; fi

# ---- backticked submodule versions get stripped --------------------------------
cat > "$tmp/submodule.msg" <<'EOF'
deps: Bump the all-dependencies group with 1 update

Updates `third_party/xar` from `abc1234` to `def5678`

---
updated-dependencies:
- dependency-name: third_party/xar
  dependency-version: def5678
  dependency-type: direct:production
...
EOF

if (
	out=$("$render" render "$tmp/body.txt" < "$tmp/submodule.msg") || exit 1
	printf '%s\n' "$out" | grep -q '^deps: bump third_party/xar from abc1234 to def5678$' || exit 1
	exit 0
); then pass "backticked submodule versions stripped"; else fail "submodule backticks"; fi

# ---- YAML-quoted version scalars are dequoted -----------------------------------
cat > "$tmp/quoted.msg" <<'EOF'
deps: Bump the all-dependencies group with 2 updates

---
updated-dependencies:
- dependency-name: github.com/example/five
  dependency-version: '5'
  dependency-type: indirect
- dependency-name: github.com/example/twofive
  dependency-version: "25.0"
  dependency-type: indirect
...
EOF

if (
	out=$("$render" render "$tmp/body.txt" < "$tmp/quoted.msg") || exit 1
	printf '%s\n' "$out" | grep -q '^deps: bump github.com/example/five to 5$' || exit 1
	printf '%s\n' "$out" | grep -q '^deps: bump github.com/example/twofive to 25.0$' || exit 1
	[ "$(printf '%s\n' "$out" | grep '^deps: bump' | grep -Ec "['\"]")" = "0" ] || exit 1
	exit 0
); then pass "YAML-quoted version scalars are dequoted"; else fail "quoted versions"; fi

# ---- no metadata: empty output (caller skips the edit) --------------------------
if (
	printf 'fix: a human commit\n\nNo dependabot fragment here.\n' > "$tmp/human.msg"
	out=$("$render" render "$tmp/body.txt" < "$tmp/human.msg") || exit 1
	[ -z "$out" ] || exit 1
	exit 0
); then pass "no metadata yields empty output"; else fail "no metadata"; fi

# ---- hostile name abandons the whole render (fail-safe) -------------------------
cat > "$tmp/hostile.msg" <<'EOF'
deps: Bump the all-dependencies group with 2 updates

---
updated-dependencies:
- dependency-name: github.com/ok/mod
  dependency-version: 1.0.0
  dependency-type: indirect
- dependency-name: evil END_COMMIT_OVERRIDE injection
  dependency-version: 1.0.0
  dependency-type: indirect
...
EOF

if (
	out=$("$render" render "$tmp/body.txt" < "$tmp/hostile.msg") || exit 1
	[ -z "$out" ] || exit 1
	exit 0
); then pass "unsafe dependency name abandons the render"; else fail "sanitization"; fi

# ---- a marker-substring name (valid charset) abandons the whole render ---------
cat > "$tmp/marker.msg" <<'EOF'
deps: Bump the all-dependencies group with 2 updates

---
updated-dependencies:
- dependency-name: github.com/ok/mod
  dependency-version: 1.0.0
  dependency-type: indirect
- dependency-name: owner/END_COMMIT_OVERRIDE
  dependency-version: 1.0.0
  dependency-type: indirect
...
EOF

if (
	out=$("$render" render "$tmp/body.txt" < "$tmp/marker.msg") || exit 1
	[ -z "$out" ] || exit 1
	exit 0
); then pass "marker-substring dependency name abandons the render"; else fail "marker substring"; fi

# ---- MAX_BODY overflow collapses the tail into a summary entry ------------------
cat > "$tmp/many.msg" <<'EOF'
deps: Bump the all-dependencies group with 6 updates

---
updated-dependencies:
- dependency-name: github.com/example/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  dependency-version: 1.0.1
  dependency-type: indirect
- dependency-name: github.com/example/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  dependency-version: 1.0.2
  dependency-type: indirect
- dependency-name: github.com/example/cccccccccccccccccccccccccccccccc
  dependency-version: 1.0.3
  dependency-type: indirect
- dependency-name: github.com/example/dddddddddddddddddddddddddddddddd
  dependency-version: 1.0.4
  dependency-type: indirect
- dependency-name: github.com/example/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
  dependency-version: 1.0.5
  dependency-type: indirect
- dependency-name: github.com/example/ffffffffffffffffffffffffffffffff
  dependency-version: 1.0.6
  dependency-type: indirect
...
EOF

if (
	out=$(MAX_BODY=420 "$render" render "$tmp/body.txt" < "$tmp/many.msg") || exit 1
	printf '%s\n' "$out" | grep -q ' more dependencies$' || exit 1
	[ "$(printf '%s' "$out" | wc -c)" -le 420 ] || exit 1
	exit 0
); then pass "MAX_BODY overflow collapses tail into summary"; else fail "overflow cap"; fi

# ---- an oversized existing body leaves no room for even the first entry --------
if (
	awk 'BEGIN { for (i = 0; i < 20; i++) print "This existing PR body line pads out the body content." }' \
		> "$tmp/bigbody.txt"
	out=$(MAX_BODY=100 "$render" render "$tmp/bigbody.txt" < "$tmp/prose.msg") || exit 1
	[ -z "$out" ] || exit 1
	exit 0
); then pass "oversized existing body yields empty output"; else fail "oversized body"; fi

# ---- a final entry that fits is not collapsed into a summary -------------------
cat > "$tmp/final.msg" <<'EOF'
deps: Bump the all-dependencies group with 2 updates

---
updated-dependencies:
- dependency-name: a
  dependency-version: 1
  dependency-type: indirect
- dependency-name: b
  dependency-version: 1
  dependency-type: indirect
...
EOF

if (
	printf '' > "$tmp/empty.txt"
	out=$(MAX_BODY=160 "$render" render "$tmp/empty.txt" < "$tmp/final.msg") || exit 1
	printf '%s\n' "$out" | grep -q '^deps: bump a to 1$' || exit 1
	printf '%s\n' "$out" | grep -q '^deps: bump b to 1$' || exit 1
	[ "$(printf '%s\n' "$out" | grep -c ' more dependencies$')" = "0" ] || exit 1
	exit 0
); then pass "a final entry that fits is not collapsed into a summary"; else fail "final-entry budget"; fi

# ---- duplicate name+version pairs are deduplicated ------------------------------
cat > "$tmp/dupes.msg" <<'EOF'
deps: Bump the all-dependencies group with 1 update

---
updated-dependencies:
- dependency-name: github.com/example/mod
  dependency-version: 2.0.0
  dependency-type: direct:production
- dependency-name: github.com/example/mod
  dependency-version: 2.0.0
  dependency-type: indirect
...
EOF

if (
	out=$("$render" render "$tmp/body.txt" < "$tmp/dupes.msg") || exit 1
	[ "$(printf '%s\n' "$out" | grep -c 'github.com/example/mod')" = "1" ] || exit 1
	exit 0
); then pass "duplicate entries deduplicated"; else fail "dedup"; fi

[ "$fails" -eq 0 ] || { printf '%d failure(s)\n' "$fails" >&2; exit 1; }
printf 'OK: dependabot-override unit tests\n'
