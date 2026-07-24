#!/usr/bin/env bash
# Ensure the runner's gh supports `gh release verify`, for the post-publish
# attestation workflow's verify loop. Installs current gh from the official
# apt repo unconditionally, then asserts the subcommand is present:
# `gh release verify --help` exits 0 even when the subcommand is missing
# (cobra handles --help before argument validation), so a plain --help probe
# can't stand in for the assert.
set -euo pipefail

echo "installing current gh from the official apt repo"
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg |
  sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" |
  sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null
sudo apt-get update -qq
sudo apt-get install -y -qq gh
gh release --help 2>/dev/null | grep -qE '^[[:space:]]+verify:'
