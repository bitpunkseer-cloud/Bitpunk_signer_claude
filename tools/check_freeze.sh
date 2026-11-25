#!/usr/bin/env bash
# Logic freeze. The code that computes, verifies, signs and parses stays as
# it was at the end of M8 (frozen for M9's screen work, file-level since M10,
# decision 11):
#   - bp-bitcoin, bp-qr, bp-fat: no change at all;
#   - bp-crypto, bp-hal: every file that existed at the end of M8 is
#     unchanged, except that lib.rs may gain `mod` / `use` lines for new
#     files. New crypto primitives and HAL traits come only as new files.
# Tests may still be added in new files. Lift the freeze only with an
# approved, documented reason (docs/FEATURE_INVENTORY.md, intended changes).
set -euo pipefail
BASE=c027ae47b16c0dd49fb86553bc632a2e129eb835 # last commit of M8 (docs after M8-10)
WHOLE=(crates/bp-bitcoin/src crates/bp-qr/src crates/bp-fat/src)
OPEN=(crates/bp-crypto/src crates/bp-hal/src)
if ! git cat-file -e "$BASE^{commit}" 2>/dev/null; then
  git fetch --quiet origin "$BASE" || { echo "freeze base $BASE not available (fetch-depth: 0?)"; exit 1; }
fi
fail=0
if ! git diff --quiet "$BASE" -- "${WHOLE[@]}"; then
  echo "logic freeze broken: these sources changed since M8:"
  git diff --stat "$BASE" -- "${WHOLE[@]}"
  fail=1
fi
while IFS= read -r f; do
  case "$f" in
    */lib.rs)
      bad=$(git diff "$BASE" -- "$f" | grep -E '^[+-]' | grep -vE '^(\+\+\+|---) ' \
        | grep -vE '^\+(pub )?(mod|use) [A-Za-z0-9_:{}, ]+;$' || true)
      if [ -n "$bad" ]; then
        echo "logic freeze broken: $f may only gain mod/use lines:"
        echo "$bad"
        fail=1
      fi
      ;;
    *)
      if ! git diff --quiet "$BASE" -- "$f"; then
        echo "logic freeze broken: $f changed since M8"
        fail=1
      fi
      ;;
  esac
done < <(git ls-tree -r --name-only "$BASE" -- "${OPEN[@]}")
if [ "$fail" = 0 ]; then
  added=$(git diff --name-only --diff-filter=A "$BASE" -- "${OPEN[@]}" | wc -l)
  echo "logic freeze: M8 logic unchanged since $BASE (new files: $added)"
else
  exit 1
fi
