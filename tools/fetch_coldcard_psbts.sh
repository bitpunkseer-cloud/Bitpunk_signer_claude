#!/bin/sh
# Fetch Coldcard's test PSBTs (Coldcard/firmware testing/data, MIT +
# Commons Clause: test-only data, not stored in this repository) at a
# pinned commit into target/coldcard-psbts, for
#   cargo test -p bp-bitcoin --test coldcard_corpus
set -eu
commit=fab5f64a8346e9a1d71d0792e49bb0f1ca9422a8
dest="$(dirname "$0")/../target/coldcard-psbts"
mkdir -p "$dest"
for f in 2-of-2 b143a_funding b143a_mod1 b143a_mod2 dup_keys example-change failed-ex \
    filled_scriptsig missing_ins missing_txn multisig-single-unsigned multisig-single \
    myself-72sig one-p2pkh-in p2pkh+p2sh+outs p2pkh-in-scriptsig p2pkh-p2sh-p2wpkh \
    p2sh_p2wpkh payjoin sim_conso sim_conso1 sim_conso2 sim_conso3 sim_conso4 sim_conso5 \
    snight-example truncated unknowns-ins wit-utxo-not-match-redeem-scr worked-1 worked-2 \
    worked-4 worked-5 worked-7 worked-combined worked-unsigned xpub-vector; do
  curl -sSfL -o "$dest/$f.psbt" "https://raw.githubusercontent.com/Coldcard/firmware/$commit/testing/data/$f.psbt"
done
echo "$(ls "$dest" | wc -l) PSBTs in $dest"
