#!/usr/bin/env bash
# M9 logic freeze: while M9 changes screens, the crates that compute, verify,
# sign and parse must stay exactly as they were at the end of M8. Tests in
# those crates may still be added. Lift the freeze only with an approved,
# documented reason (docs/FEATURE_INVENTORY.md, "Intended changes").
set -euo pipefail
BASE=c027ae47b16c0dd49fb86553bc632a2e129eb835 # last commit of M8 (docs after M8-10)
FROZEN=(
  crates/bp-crypto/src
  crates/bp-bitcoin/src
  crates/bp-qr/src
  crates/bp-fat/src
  crates/bp-hal/src
)
if ! git cat-file -e "$BASE^{commit}" 2>/dev/null; then
  git fetch --quiet origin "$BASE" || { echo "freeze base $BASE not available (fetch-depth: 0?)"; exit 1; }
fi
if git diff --quiet "$BASE" -- "${FROZEN[@]}"; then
  echo "logic freeze: core crates unchanged since M8 ($BASE)"
else
  echo "logic freeze broken: these core sources changed since M8:"
  git diff --stat "$BASE" -- "${FROZEN[@]}"
  exit 1
fi
