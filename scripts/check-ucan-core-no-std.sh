#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
core_dir="$repo_root/crates/ucan-core"

run_cargo_check() {
  if [[ -n "${IN_NIX_SHELL:-}" ]]; then
    cargo check -p ucan-core --lib --no-default-features
  else
    nix develop "$repo_root" -c cargo check -p ucan-core --lib --no-default-features
  fi
}

check_source_purity() {
  local forbidden_pattern='(^|[^[:alnum:]_])(std::|serde|serde_json|base64|blake3|SystemTime|Instant|Tcp|Udp|File::|PathBuf|std::fs|std::net|std::time|Signer|SigningKey|Ed25519|signature|signing|rand|random|zeroize)'
  if grep -RInE "$forbidden_pattern" "$core_dir/src"; then
    echo "ucan-core contains shell-only std/codec/fs/network/clock/signer concerns" >&2
    return 1
  fi
}

check_no_std_smoke() {
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/src"
  cat >"$tmp/Cargo.toml" <<EOF
[package]
name = "ucan-core-no-std-smoke"
version = "0.0.0"
edition = "2024"

[dependencies]
ucan-core = { path = "$core_dir" }
EOF
  cat >"$tmp/src/lib.rs" <<'EOF'
#![no_std]

use ucan_core::token::CapabilityInput;
use ucan_core::token::Claims;
use ucan_core::token::ClaimsInput;
use ucan_core::token::ProofReferenceInput;

const ISSUER_DID: &str = "did:key:z6Mkissuer";
const AUDIENCE_DID: &str = "did:key:z6Mkaudience";
const RESOURCE_DID: &str = "did:key:z6Mkresource";
const ABILITY: &str = "store/add";
const NOT_BEFORE_SECONDS: u64 = 1;
const EXPIRES_AT_SECONDS: u64 = 2;

pub fn validate_claim_surface() -> bool {
    let capabilities = [CapabilityInput::new(RESOURCE_DID, ABILITY)];
    let proofs: [ProofReferenceInput<'_>; 0] = [];
    Claims::from_input(ClaimsInput {
        issuer_did: Some(ISSUER_DID),
        audience_did: Some(AUDIENCE_DID),
        capabilities: Some(capabilities.as_slice()),
        proofs: Some(proofs.as_slice()),
        not_before_seconds: Some(NOT_BEFORE_SECONDS),
        expires_at_seconds: Some(EXPIRES_AT_SECONDS),
    })
    .is_ok()
}
EOF
  cargo check --manifest-path "$tmp/Cargo.toml" --lib --no-default-features
}

cd "$repo_root"
run_cargo_check
check_source_purity
check_no_std_smoke
