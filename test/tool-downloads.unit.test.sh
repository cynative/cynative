#!/bin/sh
# tool-downloads.unit.test.sh - offline contract pins for the two pinned tool downloads
# (cynative#324). Hermetic: reads tracked workflow files only, no network, no downloads.
#
# Two steps fetch a pinned binary over the network before their job can do any work:
# ci.yaml bootstraps shellcheck for the required Lint & Test check, and release.yaml
# bootstraps cosign for signing. Both carry the same hardening against a flaky or
# throttling GitHub Releases, and every part of it is silent when deleted, because its
# whole job is to suppress a symptom rather than to produce a result:
#
#   - an outer `timeout`, the only hard deadline on the download. curl's
#     --retry-max-time does not stop an attempt that already started, and a 429 or 503
#     Retry-After replaces --retry-delay with a server-chosen sleep, so without it the
#     step waits however long the server asks.
#   - --retry-all-errors, which is what makes a reset during TLS setup (curl exit 35)
#     retryable at all; plain --retry does not treat that as retryable.
#   - a positive --retry count, without which --retry-all-errors does nothing.
#   - a positive --max-time no larger than the outer deadline, so one stalled attempt
#     cannot eat the whole budget.
#
# Drop any of them and both workflows stay green. CI goes back to dying on the occasional
# reset, which reads as flake and gets a re-run rather than a diagnosis, and the release
# goes back to a download that can hold its runner. The sha256sum on the next line is an
# integrity check, not a liveness one, so nothing else observes these values.
#
# Values are parsed and compared, never matched as text: `timeout 0` and `--max-time 0`
# disable the very timers they look like they pin, and `--retry 0` disables retrying
# while --retry-all-errors still reads as present. The outer deadline is compared with
# the step's own timeout-minutes rather than a literal, so retuning either is free while
# a deadline that no longer fits inside the step fails here. Run by `make sh-test`.
set -eu

here=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/.." && pwd)

fails=0
pass() { printf 'ok: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }

# First capture of a sed expression over a blob, or empty when nothing matches.
num() { # sed-expression blob
	printf '%s\n' "$2" | sed -n "$1" | head -n 1
}

# The step's own lines. Ends at the next step (`      - `), the next job (two-space key)
# or the next top-level key, so a step that is last in its job cannot adopt the next
# job's timeout-minutes or borrow a later step's curl.
step_block() { # file step-name
	awk -v want="      - name: $2" '
		$0 == want { f = 1; next }
		f && (/^      - / || /^  [A-Za-z0-9_-]+:[[:space:]]*$/ || /^[A-Za-z0-9_-]+:/) { f = 0 }
		f
	' "$1"
}

# Live shell from a run: body. Strips comments to end of line before joining
# continuations, so a commented-out hardened command cannot vouch for a live bare one,
# and a trailing comment cannot hide the rest of a line.
live_cmds() { # block
	printf '%s\n' "$1" |
		sed 's/[[:space:]]#.*$//; s/^[[:space:]]*#.*$//' |
		awk '/\\$/ { sub(/[[:space:]]*\\$/, " "); buf = buf $0; next } { print buf $0; buf = "" }'
}

# workflow:step name. Both rows are checked by the same rule; neither is special.
for row in \
	".github/workflows/ci.yaml:Bootstrap pinned script-check tools" \
	".github/workflows/release.yaml:Bootstrap pinned cosign"; do
	wf=${row%%:*}
	step=${row#*:}
	file="$root/$wf"
	[ -f "$file" ] || { fail "$wf not found"; continue; }

	# Exactly one step of this name: a duplicate carrying a bare curl must not pass on
	# the strength of the hardened original.
	step_count=$(grep -cxF "      - name: $step" "$file" || true)
	if [ "$step_count" -ne 1 ]; then
		fail "$wf: expected exactly one step named '$step', found $step_count"
		continue
	fi

	block=$(step_block "$file" "$step")
	cmd=$(live_cmds "$block" | grep '[[:space:]]curl[[:space:]]' || true)
	cmd_count=$(printf '%s' "$cmd" | grep -c . || true)
	if [ "$cmd_count" -ne 1 ]; then
		fail "$wf: expected exactly one live curl invocation in '$step', found $cmd_count"
		continue
	fi

	budget=$(num 's/^[[:space:]]*timeout-minutes:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$block")
	outer=$(num 's/.*[[:space:]]timeout[[:space:]][[:space:]]*\([0-9][0-9]*\)[[:space:]][[:space:]]*curl[[:space:]].*/\1/p' "$cmd")
	attempt=$(num 's/.*--max-time[[:space:]][[:space:]]*\([0-9][0-9]*\).*/\1/p' "$cmd")
	retries=$(num 's/.*--retry[[:space:]][[:space:]]*\([0-9][0-9]*\).*/\1/p' "$cmd")
	[ -n "$budget" ] || budget=0
	[ -n "$outer" ] || outer=0
	[ -n "$attempt" ] || attempt=0
	[ -n "$retries" ] || retries=0

	if [ "$budget" -le 0 ]; then
		fail "$wf: step '$step' must declare timeout-minutes - it is the budget the download's own deadline is checked against, and without it this pin has nothing to compare"
	elif [ "$outer" -le 0 ]; then
		# A duration suffix or a -k flag lands here rather than reading as no timeout:
		# the comparison needs bare seconds, so say that instead of claiming it is absent.
		case "$cmd" in
		*timeout*curl*) fail "$wf: the '$step' download must run under an outer timeout written as bare seconds (as in 'timeout 300 curl'), so this pin can compare it with the step's ${budget}m budget" ;;
		*) fail "$wf: the '$step' download must run under an outer timeout - curl's --retry-max-time does not stop an attempt that already started and a Retry-After overrides --retry-delay, so nothing else holds the step to its deadline" ;;
		esac
	elif [ "$outer" -ge $((budget * 60)) ]; then
		fail "$wf: the '$step' download's outer timeout (${outer}s) must be shorter than the step's own budget (${budget}m), or the step is killed mid-download instead of failing on it"
	else
		pass "$wf: '$step' download runs under a ${outer}s deadline, inside the step's ${budget}m"
	fi

	case "$cmd" in
	*--retry-all-errors*)
		if [ "$retries" -gt 0 ]; then
			pass "$wf: '$step' download retries a transport error (--retry $retries)"
		else
			fail "$wf: --retry-all-errors does nothing without a positive --retry count (got $retries)"
		fi
		;;
	*) fail "$wf: the '$step' download must pass --retry-all-errors - a reset during TLS setup surfaces as curl exit 35, which plain --retry does not treat as retryable" ;;
	esac

	if [ "$attempt" -le 0 ]; then
		fail "$wf: the '$step' download must pass a positive --max-time, so one stalled attempt cannot consume the whole deadline"
	elif [ "$outer" -gt 0 ] && [ "$attempt" -gt "$outer" ]; then
		fail "$wf: the '$step' download's --max-time (${attempt}s) must not exceed its outer timeout (${outer}s), or the per-attempt bound is dead weight"
	else
		pass "$wf: '$step' download bounds each attempt at ${attempt}s"
	fi
done

if [ "$fails" -ne 0 ]; then
	printf 'FAIL: tool download contract pins (%d)\n' "$fails" >&2
	exit 1
fi
printf 'OK: tool download contract pins\n'
