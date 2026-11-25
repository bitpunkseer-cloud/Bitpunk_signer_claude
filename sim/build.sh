#!/usr/bin/env bash
# Build the single-file web simulator.
#   dist/simulator.html   page body (published as a Claude artifact)
#   dist/site/index.html  full HTML document (GitHub Pages)
set -euo pipefail
cd "$(dirname "$0")/.."

HASH="${BP_GIT_HASH:-$(git rev-parse --short=10 HEAD 2>/dev/null || echo dev)}"
if [ -n "$(git status --porcelain -- crates sim 2>/dev/null)" ]; then HASH="$HASH+dirty"; fi
export BP_GIT_HASH="$HASH"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"

cargo build --release --target wasm32-unknown-unknown -p bp-sim-web
WASM=target/wasm32-unknown-unknown/release/bp_sim_web.wasm

mkdir -p dist/site
python3 -I - "$WASM" "v$VERSION / $HASH" sim/web/index.template.html dist/simulator.html dist/site/index.html sim/web/checklist.json <<'PY'
import base64, json, sys
wasm, build, tpl, out_body, out_site, checklist = sys.argv[1:]
b64 = base64.b64encode(open(wasm, "rb").read()).decode()
items = json.dumps(json.load(open(checklist)), ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
page = (open(tpl).read().replace("__WASM_BASE64__", b64).replace("__BUILD__", build)
        .replace("__CHECKLIST_JSON__", items))
open(out_body, "w").write(page)
open(out_site, "w").write(
    '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
    + page.replace("<div class=\"wrap\">", "</head>\n<body>\n<div class=\"wrap\">", 1)
    + "\n</body>\n</html>\n")
print(f"simulator: {len(page)//1024} KiB, build {build}")
PY
