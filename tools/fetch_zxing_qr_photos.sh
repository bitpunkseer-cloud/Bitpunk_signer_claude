#!/bin/sh
# Fetch ZXing's "blackbox" QR photo sets (Apache-2.0, test-only data) for
# the photo test of the QR scanner:
#   tools/fetch_zxing_qr_photos.sh /tmp/zxing
#   ZXING_QR_PHOTOS=/tmp/zxing/core/src/test/resources/blackbox \
#     cargo test -p bp-qr --release --test photos -- --ignored --nocapture
set -eu
dest="${1:?usage: $0 <directory>}"
git clone -q --depth 1 --filter=blob:none --sparse https://github.com/zxing/zxing.git "$dest"
cd "$dest"
git sparse-checkout set $(for i in 1 2 3 4 5 6; do printf 'core/src/test/resources/blackbox/qrcode-%s ' "$i"; done)
echo "photos in $dest/core/src/test/resources/blackbox"
