.PHONY: check check-go check-scripts lint format test generate shell-complexity \
	windows-build shellcheck pwsh-lint pwsh-test sh-test

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

test: generate
	CGO_ENABLED=1 go test -race -shuffle=on ./... -coverprofile=coverage.out -covermode=atomic
	@# Exact, per-package gate: fail on any uncovered statement (count 0) EXCEPT
	@# files in the imperative shell (*_shell.go), which are integration-tested.
	@uncovered=$$(awk 'NR>1 && $$NF==0 { split($$1, loc, ":"); if (loc[1] !~ /_shell\.go$$/) { split(loc[2], pos, "."); print loc[1] ":" pos[1] } }' coverage.out); \
	if [ -n "$$uncovered" ]; then \
		echo "FAIL: core coverage below 100%, uncovered statements:"; \
		echo "$$uncovered"; \
		exit 1; \
	fi
	@echo "OK: 100% core coverage"

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

# pwsh-lint: PSScriptAnalyzer on install.ps1 at the pinned module version. Presence-
# check with a readable install hint first (install-free — never installs the module).
pwsh-lint:
	@command -v pwsh >/dev/null 2>&1 || { echo "FAIL: pwsh not found — install PowerShell 7 + PSScriptAnalyzer $(PSSCRIPTANALYZER_VERSION)."; exit 1; }
	pwsh -NoProfile -Command 'if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object Version -eq "$(PSSCRIPTANALYZER_VERSION)")) { Write-Host "FAIL: PSScriptAnalyzer $(PSSCRIPTANALYZER_VERSION) not installed — run: Install-Module PSScriptAnalyzer -RequiredVersion $(PSSCRIPTANALYZER_VERSION) -Scope CurrentUser"; exit 1 }; Import-Module -Name PSScriptAnalyzer -RequiredVersion $(PSSCRIPTANALYZER_VERSION) -Force -ErrorAction Stop; Invoke-ScriptAnalyzer -Path install.ps1 -Settings test/PSScriptAnalyzerSettings.psd1 -EnableExit'

# pwsh-test: Pester unit tests at the pinned module version. Presence-check with a
# readable install hint first (install-free — never installs the module).
pwsh-test:
	@command -v pwsh >/dev/null 2>&1 || { echo "FAIL: pwsh not found — install PowerShell 7 + Pester $(PESTER_VERSION)."; exit 1; }
	pwsh -NoProfile -Command 'if (-not (Get-Module -ListAvailable -Name Pester | Where-Object Version -eq "$(PESTER_VERSION)")) { Write-Host "FAIL: Pester $(PESTER_VERSION) not installed — run: Install-Module Pester -RequiredVersion $(PESTER_VERSION) -Scope CurrentUser -SkipPublisherCheck"; exit 1 }; Import-Module -Name Pester -RequiredVersion $(PESTER_VERSION) -Force -ErrorAction Stop; $$r = Invoke-Pester -Path test/install.unit.Tests.ps1 -Output Detailed -PassThru; if ($$r.FailedCount -gt 0) { exit 1 }'

# sh-test: POSIX install.sh unit + loopback smoke tests. Presence-check python3
# (the smoke test's loopback fixture server) with an install hint, mirroring the
# shellcheck/pwsh install-free pattern.
sh-test:
	@command -v python3 >/dev/null 2>&1 || { echo "FAIL: python3 not found — needed by the install.sh loopback smoke test (test/install.smoke.test.sh)."; exit 1; }
	@sh test/install.unit.test.sh
	@sh test/install.smoke.test.sh
	@echo "OK: sh-test (install.sh unit + loopback smoke)"

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
