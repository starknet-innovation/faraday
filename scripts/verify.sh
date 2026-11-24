#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "==> [1/2] Scarb format & compilation check"
if command -v scarb >/dev/null 2>&1; then
  scarb fmt --check
  scarb build
else
  echo "    (scarb not found in PATH; skipping scarb step)"
fi

UC_BIN="${UC_BIN:-$(command -v uc || true)}"
echo "==> [2/2] Ultra Cairo (uc) lint, unit tests, audit, & formal verification"
if [[ -n "$UC_BIN" && -x "$UC_BIN" ]]; then
  "$UC_BIN" lint
  "$UC_BIN" test
  "$UC_BIN" audit
  "$UC_BIN" prove --wide-domain --fail-on findings
else
  echo "    (uc not found in PATH; install https://github.com/omarespejel/uc or set UC_BIN=/path/to/uc)"
fi
