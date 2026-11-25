#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "$(uname -s)" = Darwin ] && command -v brew >/dev/null 2>&1; then
    llvm=$(brew --prefix llvm)
    export CC_wasm32_unknown_unknown="${CC_wasm32_unknown_unknown:-$llvm/bin/clang}"
    export AR_wasm32_unknown_unknown="${AR_wasm32_unknown_unknown:-$llvm/bin/llvm-ar}"
fi
cargo build --release --locked --no-default-features --features browser-signer --target wasm32-unknown-unknown --target-dir target --lib
mkdir -p pkg/browser-signer
install -m 644 target/wasm32-unknown-unknown/release/chronos_vault.wasm browser/chronos_signer.wasm
cp browser/chronos_signer.wasm browser/signer.js browser/signer-worker.js browser/signer.d.ts browser/README.md pkg/browser-signer/
