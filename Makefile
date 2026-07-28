.PHONY: check check-go check-scripts mod-tidy-check lint format test generate shell-complexity \
	windows-build shellcheck pwsh-lint pwsh-test sh-test snapshot install-e2e llm-smoke \
	llm-tools-smoke homebrew-smoke install-script-smoke

# Pinned external (non-Go) tool versions for check-scripts. Unlike the Go tools
# (pinned via go.mod / `go tool`), these are NOT Dependabot-managed — Dependabot has
# no PowerShell Gallery or raw-binary ecosystem — so bump them here by hand: the
# latest shellcheck release + its GitHub API asset digest, and the latest Pester /
# PSScriptAnalyzer on the PowerShell Gallery.
SHELLCHECK_VERSION := 0.11.0
SHELLCHECK_SHA256 := 8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
PESTER_VERSION := 5.7.1
PSSCRIPTANALYZER_VERSION := 1.25.0

# Pinned release tooling. Same story as the check-scripts pins above (no Dependabot
# ecosystem for raw binaries, so bump by hand), but a separate block because these are
# used by the release pipeline rather than by check-scripts. Bump to the latest cosign
# release and take the digest from the cosign-linux-amd64 row of that release's
# checksums file.
COSIGN_VERSION := 3.1.2
COSIGN_SHA256 := f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf

# Every workflow that is callable as a release gate. Each must carry exactly one
# EXPECTED_CALLER pin naming TRUSTED_CALLER; sh-test enforces that.
GATE_WORKFLOWS := .github/workflows/connector-e2e.yaml .github/workflows/llm-smoke.yaml
TRUSTED_CALLER := cynative/cynative/.github/workflows/release.yaml@refs/heads/main

# The single CI gate. Locally, the fast hermetic check-go is the pre-commit hook.
check: check-go check-scripts

# Go-only, 100% go.mod-pinned/hermetic gate; the pre-commit hook runs this.
check-go: mod-tidy-check generate lint shell-complexity format test windows-build

# mod-tidy-check: verify go.mod/go.sum are tidy without mutating them. `-diff`
# (Go 1.23+) prints the changes tidying would make and exits nonzero if any are
# needed, so a release or a gate run never silently rewrites dependency state.
mod-tidy-check:
	go mod tidy -diff

# Non-Go, system-tool checks. Install-free: each target asserts its pinned tool /
# module version is present and fails with an install hint otherwise.
check-scripts: shellcheck pwsh-lint pwsh-test sh-test

generate:
	go generate ./...

lint: generate
	go tool golangci-lint run

format: generate
	go tool golangci-lint fmt --diff

# The one coverage-exempt test-support package: reusable fake auth.Provider
# implementations imported only from _test.go files, never part of the shipped
# binary. Anchored to the full module path so the exemption fails closed: if the
# module path ever changes, authtest rows become gated again (loud failure)
# instead of the exemption silently widening.
AUTHTEST_PKG := github.com/cynative/cynative/internal/auth/authtest

test: generate
	CGO_ENABLED=1 go test -race -shuffle=on ./... -coverprofile=coverage.out -covermode=atomic
	@# Exact, per-package gate: fail on any uncovered statement (count 0) EXCEPT
	@# files in the imperative shell (*_shell.go), which are integration-tested,
	@# and the test-support package $(AUTHTEST_PKG), which never ships (the import
	@# guard below keeps that a mechanical property, not a convention).
	@uncovered=$$(awk 'NR>1 && $$NF==0 { split($$1, loc, ":"); if (loc[1] !~ /_shell\.go$$/ && index(loc[1], "$(AUTHTEST_PKG)/") != 1) { split(loc[2], pos, "."); print loc[1] ":" pos[1] } }' coverage.out); \
	if [ -n "$$uncovered" ]; then \
		echo "FAIL: core coverage below 100%, uncovered statements:"; \
		echo "$$uncovered"; \
		exit 1; \
	fi
	@echo "OK: 100% core coverage"
	@# Import guard for the exemption above: only _test.go files may import the
	@# coverage-exempt package ({{.Imports}} excludes test imports), so real logic
	@# parked there can mechanically never reach a shipped binary. {{.Imports}}
	@# only sees files the active build context selects, so the check runs once
	@# per goreleaser-shipped platform (GOOS x GOARCH at CGO_ENABLED=0, matching
	@# .goreleaser.yaml; a host-only check would miss an importer hidden behind a
	@# windows/arm64/!cgo build tag), and fails closed if go list errors.
	@for goos in linux windows darwin; do \
		for goarch in amd64 arm64; do \
			imports=$$(CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./...) || { echo "FAIL: GOOS=$$goos GOARCH=$$goarch go list errored, import guard could not run"; exit 1; }; \
			offenders=$$(printf '%s\n' "$$imports" | grep -E " $(AUTHTEST_PKG)(/| |$$)"); \
			if [ -n "$$offenders" ]; then \
				echo "FAIL: coverage-exempt $(AUTHTEST_PKG) is imported by non-test code (GOOS=$$goos GOARCH=$$goarch):"; \
				echo "$$offenders"; \
				exit 1; \
			fi; \
		done; \
	done; \
	echo "OK: no non-test importer of $(AUTHTEST_PKG) (all shipped GOOS/GOARCH, CGO_ENABLED=0)"

# windows-build: the release ships a Windows binary + installer; keep the cross-build
# green. Pure hermetic `go build`, so it lives in check-go (pre-commit catches breaks).
windows-build:
	GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/cynative
	GOOS=windows GOARCH=arm64 go build -o /dev/null ./cmd/cynative

# shellcheck: lint every tracked *.sh at the pinned version (install-free assert).
shellcheck:
	@command -v shellcheck >/dev/null 2>&1 || { echo "FAIL: shellcheck not found — install v$(SHELLCHECK_VERSION): https://github.com/koalaman/shellcheck/releases/tag/v$(SHELLCHECK_VERSION)"; exit 1; }
	@have=$$(shellcheck --version | awk '/^version:/{print $$2}'); \
	if [ "$$have" != "$(SHELLCHECK_VERSION)" ]; then \
		echo "FAIL: shellcheck $$have != pinned $(SHELLCHECK_VERSION) — install the pinned release: https://github.com/koalaman/shellcheck/releases/tag/v$(SHELLCHECK_VERSION)"; \
		exit 1; \
	fi
	@git ls-files -z '*.sh' | xargs -0 shellcheck && echo "OK: shellcheck ($(SHELLCHECK_VERSION))"

# pwsh-lint: PSScriptAnalyzer on every tracked *.ps1 at the pinned module version
# (mirrors shellcheck's git ls-files approach, so a new tracked ps1 file is covered
# automatically). Presence-check with a readable install hint first (install-free,
# never installs the module). -Path binds a single string, so analyze per file and
# aggregate; -EnableExit would end the session after the first file, so fail explicitly.
pwsh-lint:
	@command -v pwsh >/dev/null 2>&1 || { echo "FAIL: pwsh not found — install PowerShell 7 + PSScriptAnalyzer $(PSSCRIPTANALYZER_VERSION)."; exit 1; }
	pwsh -NoProfile -Command 'if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object Version -eq "$(PSSCRIPTANALYZER_VERSION)")) { Write-Host "FAIL: PSScriptAnalyzer $(PSSCRIPTANALYZER_VERSION) not installed — run: Install-Module PSScriptAnalyzer -RequiredVersion $(PSSCRIPTANALYZER_VERSION) -Scope CurrentUser"; exit 1 }; Import-Module -Name PSScriptAnalyzer -RequiredVersion $(PSSCRIPTANALYZER_VERSION) -Force -ErrorAction Stop; $$files = & git ls-files "*.ps1"; if ($$LASTEXITCODE -ne 0) { Write-Host "FAIL: git ls-files failed enumerating *.ps1"; exit 1 }; if ($$files.Count -eq 0) { Write-Host "FAIL: no tracked *.ps1 files matched"; exit 1 }; $$findings = @(); foreach ($$f in $$files) { $$findings += Invoke-ScriptAnalyzer -Path $$f -Settings test/PSScriptAnalyzerSettings.psd1 }; if ($$findings.Count -gt 0) { $$findings | Format-Table -AutoSize | Out-String | Write-Host; exit 1 }'

# pwsh-test: Pester unit tests, one run over every tracked test/*.Tests.ps1 suite
# (mirrors shellcheck's git ls-files approach, so a new hermetic suite is picked up
# automatically), at the pinned module version. Presence-check with a readable
# install hint first (install-free, never installs the module).
# Also presence-check python3: the install.smoke.Tests.ps1 suite launches the
# loopback fixture server (test/serve-fixture.py), mirroring sh-test's guard.
pwsh-test:
	@command -v pwsh >/dev/null 2>&1 || { echo "FAIL: pwsh not found — install PowerShell 7 + Pester $(PESTER_VERSION)."; exit 1; }
	@command -v python3 >/dev/null 2>&1 || { echo "FAIL: python3 not found, needed by the install.smoke.Tests.ps1 loopback fixture server (test/serve-fixture.py)."; exit 1; }
	pwsh -NoProfile -Command 'if (-not (Get-Module -ListAvailable -Name Pester | Where-Object Version -eq "$(PESTER_VERSION)")) { Write-Host "FAIL: Pester $(PESTER_VERSION) not installed — run: Install-Module Pester -RequiredVersion $(PESTER_VERSION) -Scope CurrentUser -SkipPublisherCheck"; exit 1 }; Import-Module -Name Pester -RequiredVersion $(PESTER_VERSION) -Force -ErrorAction Stop; $$files = & git ls-files "test/*.Tests.ps1"; if ($$LASTEXITCODE -ne 0) { Write-Host "FAIL: git ls-files failed enumerating test/*.Tests.ps1"; exit 1 }; if ($$files.Count -eq 0) { Write-Host "FAIL: no tracked test/*.Tests.ps1 suites matched"; exit 1 }; $$r = Invoke-Pester -Path $$files -Output Detailed -PassThru -ErrorAction Stop; if (($$null -eq $$r) -or ($$r.Result -ne "Passed") -or ($$r.TotalCount -lt 1)) { Write-Host "FAIL: pester run not clean"; exit 1 }'

# sh-test: POSIX install.sh unit + loopback smoke tests, the live-e2e guardrails
# library unit tests (test/lib/e2e-guardrails.sh), the shared connector e2e shell
# orchestration unit tests (test/lib/connector-e2e.sh: arbitrate + connector_run_phase
# + e2e_pin_audit_size), the per-package changelog override renderer unit tests
# (test/dependabot-override.unit.test.sh), the release asset-set assertion script's unit
# tests (test/assert-assets.unit.test.sh: the fail-closed-on-missing-digest branches plus
# the generate-mode artifact-type allowlist), the release signing contract pins
# (test/release-signing.unit.test.sh: the .goreleaser.yaml signs stanza, the asset gate's
# admitted type set, the snapshot sign skip, and the release workflow's OIDC permission,
# guarded steps and pinned verification identity, none of which any other gate checks and
# all of which would first fail during a live release), an AST
# syntax check of every file in the shared connector audit-parser package
# (test/lib/connector-audit-parser.py,
# test/lib/connector_audit/*.py, and its specs/), all three connector suites' offline
# audit-parser selftests (--selftest), and the shared-machinery selftest (the engine's
# own cases run with no provider, including the #56 credential prepass detection
# fixtures the per-provider selftests only prove inert on). All hermetic: no network, no
# credentials. The parsers are the security boundary of the live connector e2es, so
# they are gated here rather than only exercised on a live run. The syntax check runs
# under PYTHONDONTWRITEBYTECODE=1 with python3 -B so it leaves no __pycache__; it uses
# ast.parse rather than py_compile for the same reason, and it covers every package
# file including specs that a single provider --selftest does not exercise. Presence-check
# python3 (the smoke test's loopback fixture server) with an install hint,
# mirroring the shellcheck/pwsh install-free pattern.
sh-test:
	@command -v python3 >/dev/null 2>&1 || { echo "FAIL: python3 not found — needed by the install.sh loopback smoke test (test/install.smoke.test.sh)."; exit 1; }
	@sh test/install.unit.test.sh
	@sh test/install.smoke.test.sh
	@sh test/e2e-guardrails.unit.test.sh
	@sh test/connector-e2e.unit.test.sh
	@sh test/render-scoop.unit.test.sh
	@sh test/dependabot-override.unit.test.sh
	@sh test/assert-assets.unit.test.sh
	@sh test/release-signing.unit.test.sh
	@sh test/ci-gate-contract.unit.test.sh
	@sh test/ci-gate-assert.unit.test.sh
	@sh test/llm-smoke-roster.unit.test.sh
	@sh test/retrigger.unit.test.sh
	@PYTHONDONTWRITEBYTECODE=1 sh -c 'for f in test/lib/connector-audit-parser.py test/lib/connector_audit/*.py test/lib/connector_audit/specs/*.py; do python3 -B -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$$f" || { echo "FAIL: python syntax error in $$f"; exit 1; }; done'
	@files=$$(git ls-files 'test/connector.*.e2e.test.sh') || { echo "git ls-files failed for connector selftests" >&2; exit 1; }; \
	 [ -n "$$files" ] || { echo "no connector e2e selftests matched test/connector.*.e2e.test.sh" >&2; exit 1; }; \
	 for f in $$files; do echo "  selftest $$f"; sh "$$f" --selftest || exit 1; done
	@PYTHONDONTWRITEBYTECODE=1 python3 -B test/lib/connector-audit-parser.py --selftest
	@# The trusted-caller pin is the only thing that stops an arbitrary workflow from
	@# driving a release gate; without it, anything calling the workflow would pass the
	@# contract check and reach the credentialed jobs. Fail closed if that exact pinned
	@# value is ever missing, edited away, duplicated (a second EXPECTED_CALLER: line),
	@# or merely shadowed by a commented-out decoy - require exactly one live
	@# EXPECTED_CALLER: line per gate, and its value must match the trusted caller
	@# exactly, not as a substring. Every gate workflow must be listed here.
	@if [ -z "$(GATE_WORKFLOWS)" ]; then \
		echo "FAIL: GATE_WORKFLOWS is empty - an empty list means the pin check covers nothing; every gate workflow must be listed."; \
		exit 1; \
	fi
	@for wf in $(GATE_WORKFLOWS); do \
		if [ ! -f "$$wf" ]; then \
			echo "FAIL: $$wf listed in GATE_WORKFLOWS does not exist - fix the path or the workflow file."; \
			exit 1; \
		fi; \
		count=$$(grep -cE '^[[:space:]]*EXPECTED_CALLER:' "$$wf"); \
		if [ "$$count" -ne 1 ]; then \
			echo "FAIL: $$wf must have exactly one EXPECTED_CALLER: line (found $$count) - a missing or duplicated pin is what stops an arbitrary workflow from driving the release gate."; \
			exit 1; \
		fi; \
		value=$$(grep -E '^[[:space:]]*EXPECTED_CALLER:' "$$wf" | sed -E 's/^[[:space:]]*EXPECTED_CALLER:[[:space:]]*//'); \
		if [ "$$value" != "$(TRUSTED_CALLER)" ]; then \
			echo "FAIL: $$wf's EXPECTED_CALLER pin is '$$value', not the exact trusted caller - this pin is what stops an arbitrary workflow from driving the release gate."; \
			exit 1; \
		fi; \
	done
	@# The publish gate's compound if is the sole consumer of the two gate proofs; a
	@# term dropped there (or a gate_sha comparison edited away) would let a red or
	@# absent gate publish anyway, and nothing else would notice before a live
	@# release. Scoped to the publish job's own if: line, never a whole-file grep,
	@# which a comment or a dead job could satisfy. The scan resets at every job
	@# header, so a publish job missing its if: reports the locate failure below
	@# instead of latching onto a later job's if: line.
	@publish_if=$$(awk '/^  [A-Za-z0-9_-]+:$$/{injob=($$0=="  publish:")} injob && /^    if: /{print; exit}' .github/workflows/release.yaml); \
	if [ -z "$$publish_if" ]; then \
		echo "FAIL: could not locate the publish job's if: line in release.yaml - the publish-gate pin has nothing to check."; \
		exit 1; \
	fi; \
	for term in \
		"needs.connector-e2e.result == 'success'" \
		"needs.connector-e2e.outputs.gate_sha == needs.release.outputs.sha" \
		"needs.llm-smoke.result == 'success'" \
		"needs.llm-smoke.outputs.gate_sha == needs.release.outputs.sha" \
		"needs.release.outputs.sha != ''" \
	; do \
		case "$$publish_if" in \
		*"$$term"*) ;; \
		*) echo "FAIL: the publish gate in release.yaml is missing the required term [$$term]."; exit 1 ;; \
		esac; \
	done
	@# The recovery path (cynative#202) is a workflow trigger, which nothing else
	@# exercises: no test can dispatch it, and its absence is invisible until an
	@# operator needs it mid-incident. Pin both triggers, comments stripped
	@# (sed 's/#.*//') so the prose above them never satisfies the check:
	@#   repository_dispatch/release-retry - the recovery entry point itself;
	@#   push/main - so the recovery trigger can never be added in PLACE of the
	@#     normal release path, which would stop releases entirely.
	@release_on=$$(sed 's/#.*//' .github/workflows/release.yaml | \
		awk '/^[a-zA-Z]/ && !/^on:/ {inon=0} /^on:/{inon=1} inon{print}'); \
	for term in "repository_dispatch:" "- release-retry" "push:" "- main"; do \
		case "$$release_on" in \
		*"$$term"*) ;; \
		*) echo "FAIL: release.yaml's on: block is missing [$$term] - the recovery re-trigger (scripts/release/retrigger.sh) or the normal push trigger would not fire."; exit 1 ;; \
		esac; \
	done
	@# The api-key legs read exactly two secrets across the workflow_call boundary.
	@# release.yaml forwards ONLY these two names, never secrets: inherit. Pin the
	@# boundary from both sides, comments stripped (sed 's/#.*//') so prose never counts:
	@#   llm-smoke.yaml - the sorted-unique set of secrets.<NAME> refs must be exactly
	@#     the two keys, and bracket-form secrets[...] is rejected outright since it
	@#     would evade the dot-form scan;
	@#   release.yaml - `secrets: inherit` must never appear, or a future edit could
	@#     hand every release secret (App key, signing, PAT) to the gate.
	@smoke=$$(sed 's/#.*//' .github/workflows/llm-smoke.yaml); \
	if printf '%s\n' "$$smoke" | grep -q 'secrets\['; then \
		echo "FAIL: llm-smoke.yaml uses bracket-form secrets[...]; only dot-form secrets.NAME is allowed so this pin can enforce the exact set."; \
		exit 1; \
	fi; \
	got=$$(printf '%s\n' "$$smoke" | grep -oE 'secrets\.[A-Za-z0-9_]+' | sed 's/^secrets\.//' | sort -u | xargs); \
	want="ANTHROPIC_API_KEY OPENAI_API_KEY"; \
	if [ "$$got" != "$$want" ]; then \
		echo "FAIL: llm-smoke.yaml secrets.* references are [$$got], expected exactly [$$want] - a new reference would widen the gate's secret access across workflow_call."; \
		exit 1; \
	fi; \
	if sed 's/#.*//' .github/workflows/release.yaml | grep -qE 'secrets:[[:space:]]*inherit'; then \
		echo "FAIL: release.yaml uses 'secrets: inherit' - reusable gates must be granted only the exact named secrets they need, never the full set."; \
		exit 1; \
	fi
	@echo "OK: sh-test (install.sh unit + loopback smoke + e2e guardrails unit + connector-e2e unit + render-scoop unit + dependabot-override unit + assert-assets unit + release-signing contract pins + ci-gate-contract unit + ci-gate-assert unit + llm-smoke roster unit + retrigger unit + python syntax gate + connector audit parsers + shared-machinery selftest + gate trusted-caller pin check + release publish-gate pin check + release trigger pin + llm-smoke secret-reference pin)"

SHELL_COMPLEXITY_MAX := 6

# Shell files (*_shell.go) are exempt from the 100% coverage gate, so guard their
# thinness mechanically: a function over the cyclomatic/cognitive budget means
# "extract this logic into gated (covered) core," not "raise the budget." The
# standalone tools are AST-only (no generate needed); the gate fails closed on any
# non-zero exit (a violation OR a tool error), and the leading grep closes the only
# backdoor — the tools' native //gocyclo:ignore///gocognit:ignore skip directives,
# which they honor but //nolint they do not.
shell-complexity:
	@files=$$(find . -path ./vendor -prune -o -name '*_shell.go' -not -name '*_test.go' -print); \
	if grep -nE '//(gocyclo|gocognit):ignore' $$files; then \
		echo "FAIL: a *_shell.go file uses //gocyclo:ignore or //gocognit:ignore — the thin-shell gate has no escape hatch by design; extract into gated (covered) core instead."; \
		exit 1; \
	fi; \
	cyc=$$(go tool gocyclo -over $(SHELL_COMPLEXITY_MAX) $$files); cyc_rc=$$?; \
	cog=$$(go tool gocognit -over $(SHELL_COMPLEXITY_MAX) $$files); cog_rc=$$?; \
	if [ $$cyc_rc -ne 0 ] || [ $$cog_rc -ne 0 ]; then \
		echo "FAIL: a *_shell.go function exceeds the thin-shell budget (cyclomatic/cognitive <= $(SHELL_COMPLEXITY_MAX)), or a complexity tool errored."; \
		echo "Shells are coverage-gate-exempt glue: EXTRACT the logic into a gated (covered) core file; do not raise the budget."; \
		[ -n "$$cyc" ] && { echo "cyclomatic:"; echo "$$cyc"; }; \
		[ -n "$$cog" ] && { echo "cognitive:"; echo "$$cog"; }; \
		exit 1; \
	fi; \
	echo "OK: *_shell.go within complexity budget (<= $(SHELL_COMPLEXITY_MAX))"

# print-<VAR> echoes a single Makefile variable (CI reads the pinned versions from
# here instead of duplicating them). Example: `make -s print-SHELLCHECK_VERSION`.
print-%:
	@echo '$($*)'

# snapshot: build the release archives once via a goreleaser snapshot (no publish),
# so the local install-e2e target and the CI install-e2e jobs share one definition of
# the goreleaser flags (no drift between the Makefile and the workflow). goreleaser
# no longer runs a before-hook, so snapshot and release share one prep path.
#
# --skip=sign: the signs block in .goreleaser.yaml signs checksums.txt with cosign
# keyless, which needs a GitHub Actions OIDC token no local run has. --snapshot only
# implies skips for publish, announce and validate, and the sign pipe skips only on an
# explicit --skip=sign, so without this a snapshot (and the install-e2e that shells out
# to it) would try to sign and fail. goreleaser v2.17.1's signs schema has no `if` field
# and rejects unknown ones, so this flag is the only route.
snapshot:
	go tool goreleaser release --snapshot --clean --skip=sign

# install-e2e: real-artifact install e2e for release confidence (issue #41). Standalone
# (NOT part of `make check`): builds the release archives via `snapshot`, serves the Linux
# archive from a loopback fixture server, runs the real install.sh, verifies
# `cynative --version`, uninstalls, and proves a checksum failure fails closed. The python3
# presence check (fixture server) runs first so a missing tool fails before the build,
# mirroring the sh-test/shellcheck install-free pattern.
install-e2e:
	@command -v python3 >/dev/null 2>&1 || { echo "FAIL: python3 not found, needed by the install e2e loopback fixture server (test/install.e2e.test.sh)."; exit 1; }
	$(MAKE) snapshot
	sh test/install.e2e.test.sh ./dist
	@echo "OK: install-e2e (real archive install + version + uninstall + checksum-failure)"

# llm-smoke: live, no-tool LLM smoke test (cynative#38). Standalone (NOT part of
# `make check`): runs the real `cynative -p` against a real provider selected via
# CYNATIVE_LLM_* env and needs real credentials; skips cleanly when none are set.
llm-smoke:
	sh test/llm.smoke.test.sh

# llm-tools-smoke: live LLM tool-use smoke test (cynative#49). Standalone (NOT part
# of `make check`): runs the real `cynative -p` against a real provider selected via
# CYNATIVE_LLM_* env and proves the model drives the tool loop through
# code_execution (sums a random integer list in the sandbox); needs real
# credentials and skips cleanly when none are set.
llm-tools-smoke:
	sh test/llm-tools.smoke.test.sh

# connector-%-e2e: live connector end-to-end tests (cynative#39, cynative#52,
# cynative#53). Standalone (NOT part of `make check`): runs the real `cynative -p`
# against a real fixture account/repo through the named connector and needs real
# credentials; skips cleanly when the connector's *_E2E_* env is unset. Each
# script header documents its env and knobs. FORCE keeps the recipe live even if
# a file named connector-<name>-e2e exists in the repo root; a bare pattern rule
# has no such guarantee since it cannot be a .PHONY prerequisite.
.PHONY: FORCE
FORCE:

connector-%-e2e: FORCE ## run one live connector e2e (gcp|aws|github); naming is load-bearing
	sh test/connector.$*.e2e.test.sh

# homebrew-smoke: post-release Homebrew install smoke (cynative#45). Standalone
# (NOT part of `make check`): installs cynative from the public tap via the
# documented `brew install cynative/tap/cynative`, asserts `cynative --version`
# reports the expected release (SMOKE_VERSION, default: latest published),
# uninstalls, and asserts it is gone. Needs brew and network; no skip path.
# The script header documents its env and knobs.
homebrew-smoke:
	sh test/homebrew.smoke.test.sh

# install-script-smoke: post-release public install-script smoke (cynative#47).
# Standalone (NOT part of `make check`): runs the documented
# `curl .../install.sh | sh` path against the public release assets - installs the
# expected release (SMOKE_VERSION, default: latest published), asserts
# `cynative --version`, uninstalls via the documented paired path, and asserts it
# is gone. Needs curl and network; no skip path. The Windows sibling
# (test/install-script.smoke.test.ps1) runs in CI on windows-latest. The script
# header documents its env and knobs.
install-script-smoke:
	sh test/install-script.smoke.test.sh
