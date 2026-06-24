.PHONY: lint check format test generate shell-complexity

check: generate lint shell-complexity format test

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

SHELL_COMPLEXITY_MAX := 6

# Shell files (*_shell.go) are exempt from the 100% coverage gate, so guard their
# thinness mechanically: a function over the cyclomatic/cognitive budget means
# "extract this logic into gated (covered) core," not "raise the budget." The
# standalone tools are AST-only (no generate needed); the gate fails closed on any
# non-zero exit (a violation OR a tool error), and the leading grep closes the only
# backdoor — the tools' native //gocyclo:ignore///gocognit:ignore skip directives,
# which they honor but //nolint they do not. See issue #126.
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
