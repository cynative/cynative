.PHONY: check check-go check-scripts lint format test generate shell-complexity \
	windows-build shellcheck pwsh-lint pwsh-test sh-test snapshot install-e2e llm-smoke \
	llm-tools-smoke connector-gcp-e2e connector-aws-e2e connector-github-e2e homebrew-smoke install-script-smoke

# Pinned external (non-Go) tool versions for check-scripts. Unlike the Go tools
# (pinned via go.mod / `go tool`), these are NOT Dependabot-managed — Dependabot has
# no PowerShell Gallery or raw-binary ecosystem — so bump them here by hand: the
# latest shellcheck release + its GitHub API asset digest, and the latest Pester /
# PSScriptAnalyzer on the PowerShell Gallery.
SHELLCHECK_VERSION := 0.11.0
SHELLCHECK_SHA256 := 8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
PESTER_VERSION := 5.7.1
PSSCRIPTANALYZER_VERSION := 1.25.0

# The single CI gate. Locally, the fast hermetic check-go is the pre-commit hook.
check: check-go check-scripts

# Go-only, 100% go.mod-pinned/hermetic gate; the pre-commit hook runs this.
check-go: generate lint shell-complexity format test windows-build

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

# pwsh-lint: PSScriptAnalyzer on install.ps1 and the smoke ps1 scripts at the pinned
# module version. Presence-check with a readable install hint first (install-free —
# never installs the module). -Path binds a single string, so analyze per file and
# aggregate; -EnableExit would end the session after the first file, so fail explicitly.
pwsh-lint:
	@command -v pwsh >/dev/null 2>&1 || { echo "FAIL: pwsh not found — install PowerShell 7 + PSScriptAnalyzer $(PSSCRIPTANALYZER_VERSION)."; exit 1; }
	pwsh -NoProfile -Command 'if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object Version -eq "$(PSSCRIPTANALYZER_VERSION)")) { Write-Host "FAIL: PSScriptAnalyzer $(PSSCRIPTANALYZER_VERSION) not installed — run: Install-Module PSScriptAnalyzer -RequiredVersion $(PSSCRIPTANALYZER_VERSION) -Scope CurrentUser"; exit 1 }; Import-Module -Name PSScriptAnalyzer -RequiredVersion $(PSSCRIPTANALYZER_VERSION) -Force -ErrorAction Stop; $$findings = @(); foreach ($$f in "install.ps1", "test/install-script.smoke.test.ps1", "test/scoop.smoke.test.ps1", "test/archive.smoke.test.ps1") { $$findings += Invoke-ScriptAnalyzer -Path $$f -Settings test/PSScriptAnalyzerSettings.psd1 }; if ($$findings.Count -gt 0) { $$findings | Format-Table -AutoSize | Out-String | Write-Host; exit 1 }'

# pwsh-test: Pester unit tests at the pinned module version. Presence-check with a
# readable install hint first (install-free — never installs the module).
pwsh-test:
	@command -v pwsh >/dev/null 2>&1 || { echo "FAIL: pwsh not found — install PowerShell 7 + Pester $(PESTER_VERSION)."; exit 1; }
	pwsh -NoProfile -Command 'if (-not (Get-Module -ListAvailable -Name Pester | Where-Object Version -eq "$(PESTER_VERSION)")) { Write-Host "FAIL: Pester $(PESTER_VERSION) not installed — run: Install-Module Pester -RequiredVersion $(PESTER_VERSION) -Scope CurrentUser -SkipPublisherCheck"; exit 1 }; Import-Module -Name Pester -RequiredVersion $(PESTER_VERSION) -Force -ErrorAction Stop; $$r = Invoke-Pester -Path test/install.unit.Tests.ps1 -Output Detailed -PassThru; if ($$r.FailedCount -gt 0) { exit 1 }'

# sh-test: POSIX install.sh unit + loopback smoke tests, the live-e2e guardrails
# library unit tests (test/lib/e2e-guardrails.sh), the shared connector e2e shell
# orchestration unit tests (test/lib/connector-e2e.sh: arbitrate + connector_run_phase
# + e2e_pin_audit_size), the per-package changelog override renderer unit tests
# (test/dependabot-override.unit.test.sh), an AST syntax check of every file in the
# shared connector audit-parser package (test/lib/connector-audit-parser.py,
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
	@sh test/connector-e2e-contract.unit.test.sh
	@PYTHONDONTWRITEBYTECODE=1 sh -c 'for f in test/lib/connector-audit-parser.py test/lib/connector_audit/*.py test/lib/connector_audit/specs/*.py; do python3 -B -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$$f" || { echo "FAIL: python syntax error in $$f"; exit 1; }; done'
	@sh test/connector.gcp.e2e.test.sh --selftest
	@sh test/connector.aws.e2e.test.sh --selftest
	@sh test/connector.github.e2e.test.sh --selftest
	@PYTHONDONTWRITEBYTECODE=1 python3 -B test/lib/connector-audit-parser.py --selftest
	@echo "OK: sh-test (install.sh unit + loopback smoke + e2e guardrails unit + connector-e2e unit + render-scoop unit + dependabot-override unit + connector-e2e-contract unit + python syntax gate + connector audit parsers + shared-machinery selftest)"

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
# the goreleaser flags (no drift between the Makefile and the workflow). --skip=before
# skips `go mod tidy` to keep the build hermetic/offline.
snapshot:
	go tool goreleaser release --snapshot --clean --skip=before

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

# connector-gcp-e2e: live GCP connector end-to-end test (cynative#39). Standalone
# (NOT part of `make check`): runs the real `cynative -p` against a real GCP fixture
# project through the gcp connector and needs real credentials; skips cleanly when
# GCP_E2E_* env is unset. The script header documents its env and knobs.
connector-gcp-e2e:
	sh test/connector.gcp.e2e.test.sh

# connector-aws-e2e: live AWS connector end-to-end test (cynative#52). Standalone
# (NOT part of `make check`): runs the real `cynative -p` against a real AWS fixture
# account through the aws connector and needs real credentials; skips cleanly when
# AWS_E2E_* env is unset. The script header documents its env and knobs.
connector-aws-e2e:
	sh test/connector.aws.e2e.test.sh

# connector-github-e2e: live GitHub connector end-to-end test (cynative#53). Standalone
# (NOT part of `make check`): runs the real `cynative -p` against a private fixture repo
# through the github connector and needs a token; skips cleanly when GH_E2E_* is unset.
# The script header documents its env and knobs.
connector-github-e2e:
	sh test/connector.github.e2e.test.sh

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
