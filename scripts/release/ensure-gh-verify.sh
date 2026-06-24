#!/usr/bin/env bash
# Ensure the runner's gh supports `gh release verify` BEFORE the publish
# step: installing tooling after the point of no return would let a network
# flake strand a published release with its detection layer unexecuted.
# `gh release verify --help` exits 0 even when the subcommand is missing
# (cobra handles --help before argument validation), so probe the
# subcommand listing instead.
set -euo pipefail

if gh release --help 2>/dev/null | grep -qE '^[[:space:]]+verify:'; then
  echo "gh supports release verify"
  exit 0
fi

echo "runner gh lacks 'release verify'; installing current gh from the official apt repo"
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg |
  sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" |
  sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null
sudo apt-get update -qq
sudo apt-get install -y -qq gh
gh release --help 2>/dev/null | grep -qE '^[[:space:]]+verify:'
