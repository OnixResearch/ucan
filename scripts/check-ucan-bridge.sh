#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

require_pattern() {
  local pattern=$1
  local path=$2
  if ! grep -RInE "$pattern" "$path" >/dev/null; then
    echo "missing required bridge pattern '$pattern' in $path" >&2
    return 1
  fi
}

reject_pattern() {
  local pattern=$1
  local path=$2
  if grep -RInE "$pattern" "$path"; then
    echo "forbidden local semantic implementation matched '$pattern' in $path" >&2
    return 1
  fi
}

require_pattern 'use verified_logic::ucan_ability|VerifiedCapability::from_document|\.contains\(' src
require_pattern 'use verified_logic::ucan_temporal|compose_time_window_chain' src
require_pattern 'use verified_logic::ucan_signature|verify_ed25519_signature|sign_ed25519' src
require_pattern 'use verified_logic::ucan_token|validate_token_envelope' src
require_pattern 'use verified_logic::ucan_chain|proof_link_is_valid|structural_chain_is_valid|check_chain_structural_valid' src
require_pattern 'use verified_logic::ucan_delegation_depth|proof_depth_within_budget' src
require_pattern 'use verified_logic::ucan_revocation|revocation_reference_is_listed|structural_chain_not_revoked_is_valid|check_chain_structural_valid_not_revoked' src
require_pattern 'use verified_logic::ucan_invocation|invocation_request_is_authorized|invocation_chain_is_authorized|receipt_execution_is_valid|check_invocation_chain_authorized|check_receipt_valid' src
require_pattern 'use verified_logic::ucan_did|encode_ed25519_did_key' src
require_pattern '\.is_concrete\(\)' src/token.rs
require_pattern '\.has_wildcard_segment\(\)' src/verified.rs

reject_pattern 'fn .*attenuat.*\{|fn .*temporal.*\{|fn .*signature.*\{' crates/ucan-core/src
reject_pattern 'fn ability_has_wildcard_segment|ABILITY_SEGMENT_SEPARATOR|WILDCARD_ABILITY_SEGMENT' src/token.rs
reject_pattern 'parent\.audience\(\)\.as_str\(\) *!= *child_issuer\.as_str\(\)|child_issuer\.as_str\(\) *!= *parent\.audience\(\)\.as_str\(\)' src/token.rs
reject_pattern 'self\.as_slice\(\)\.iter\(\)\.any\(\|candidate\| candidate == reference\)|candidate == reference\)\)|iter\(\)\.any\(\|existing\| existing == &reference\)' src/token.rs
reject_pattern 'invoker: verified\.issuer\(\)\.clone\(\)' src/token.rs
reject_pattern 'if depth > limits\.max_proof_depth\(\)|depth > limits\.max_proof_depth\(\)|chain_len - 1 <= max_depth' src/token.rs
reject_pattern 'OnceLock|lazy_static|thread_local!|std::env|reqwest|ureq|hyper|process-global|global resolver|global proof|default resolver|default proof store|filesystem fallback|network fallback' src
"$repo_root/scripts/check-ucan-core-no-std.sh"
