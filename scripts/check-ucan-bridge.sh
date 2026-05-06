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
require_pattern 'use verified_logic::ucan_capability_merge|capability_set_authorizes|check_authorized_by' src
require_pattern 'use verified_logic::ucan_temporal|compose_time_window_chain' src
require_pattern 'use verified_logic::ucan_signature|verify_ed25519_signature|sign_ed25519' src
require_pattern 'use verified_logic::ucan_token|validate_token_envelope' src
require_pattern 'use verified_logic::ucan_compact|compact_token_split_is_valid|compact_token_envelope_is_valid|compact_split_matches_parts|compact_envelope_matches_parts|VerifiedCompactTokenEnvelope' src
require_pattern 'use verified_logic::ucan_base64url|base64url_segment_is_valid|base64url_no_pad_segment_is_valid|VerifiedBase64UrlSegment' src
require_pattern 'decode_part|base64url_segment_is_valid|failed verified base64url-no-pad structural admission' src/token.rs
require_pattern 'use verified_logic::ucan_json|json_object_bytes_are_valid|json_object_bytes_have_object_envelope|VerifiedJsonObjectBytes' src
require_pattern 'decode_json_part|validate_decoded_json_object_bytes|json_object_bytes_are_valid|failed verified decoded JSON object structural admission' src/token.rs
require_pattern 'use verified_logic::ucan_header|parsed_header_is_valid|parsed_header_admission_is_valid|VerifiedParsedHeader' src
require_pattern 'use verified_logic::ucan_claims_presence|parsed_claims_presence_is_valid|VerifiedParsedClaimsPresence|ParsedClaimsPresence' src
require_pattern 'validate_header|parsed_header_is_valid|VerifiedParsedHeader|UnsupportedHeader' src/token.rs
require_pattern 'validate_parsed_claims_presence|parsed_claims_presence_is_valid|VerifiedParsedClaimsPresence|MissingProofs|proofs_present|MissingExpiration|MissingNotBefore' src/token.rs
require_pattern 'use verified_logic::ucan_proof_reference|proof_reference_digest_is_valid|proof_reference_admits_digest|proof_reference_digest_from_bytes|VerifiedProofReferenceDigest' src
require_pattern 'proof_reference_digest_is_valid|proof_reference_for_token|blake3::hash|VerifiedProofReferenceDigest' src/token.rs
require_pattern 'use verified_logic::ucan_verification_stage|verification_stage_transcript_outcome|stage_transcript_accepts|first_failed_stage|VerifiedVerificationStageTranscript' src
require_pattern 'use verified_logic::ucan_backend_transcript|backend_transcript_accepts|backend_transcript_first_failed_operation|VerifiedBackendTranscript' src
require_pattern 'record_backend_operation|verify_backend_transcript_accepts|VerifiedBackendOperation::(KeyResolution|ProofLoad|Revocation)' src/token.rs
require_pattern 'use verified_logic::ucan_chain|proof_link_is_valid|structural_chain_is_valid|check_chain_structural_valid' src
require_pattern 'use verified_logic::ucan_delegation_depth|proof_depth_within_budget' src
require_pattern 'use verified_logic::ucan_revocation|revocation_reference_is_listed|structural_chain_not_revoked_is_valid|check_chain_structural_valid_not_revoked' src
require_pattern 'use verified_logic::ucan_invocation|invocation_request_is_authorized|invocation_chain_is_authorized|receipt_execution_is_valid|check_invocation_chain_authorized|check_receipt_valid' src
require_pattern 'use verified_logic::ucan_proof_traversal|proof_traversal_transcript_is_valid|traversal_transcript_valid' src
require_pattern 'proof_traversal_dag_transcript_is_valid|VerifiedProofTraversalDagTranscript|dag_traversal_transcript_valid' src/verified.rs
require_pattern 'verify_live_dag_proof_transcript|LiveProofTraversalTranscript|proof_traversal_dag_transcript_is_valid|parent_indices' src/token.rs
require_pattern 'use verified_logic::web_of_trust_principal|web_of_trust_principal_digest|web_of_trust_principal_digest_is_valid|principal_id_from_bytes|principal_id_from_digest_bytes' src
require_pattern 'use verified_logic::ucan_caveat|typed_caveat_is_satisfied|typed_caveat_set_is_satisfied|caveat_satisfied|caveat_set_satisfied' src
require_pattern 'use verified_logic::ucan_caveat_preservation|caveat_preservation_is_valid|parent_caveat_ids_preserved|VerifiedCaveatPreservation' src
require_pattern 'use verified_logic::ucan_caveat_evaluation|caveat_evaluation_transcript_accepts|first_failed_caveat_index|VerifiedCaveatEvaluationTranscript' src
require_pattern 'parent_caveats_are_preserved|caveat_identifier_set|caveat_preservation_is_valid|VerifiedCaveatPreservation' src/token.rs
require_pattern 'evaluate_capability_caveats|caveat_evaluation_transcript_accepts|caveat_evaluation_first_failed_index|VerifiedCaveatEvaluationFact' src/token.rs
require_pattern 'VerifiedTypedCaveatPolicySet|TypedCaveatContext|parse_time_bound_caveat|parse_rate_limit_caveat|typed_caveat_is_satisfied' src/token.rs
require_pattern 'use verified_logic::web_of_trust_attestation|web_of_trust_attestation_payload_bytes|web_of_trust_attestation_signature_is_valid|web_of_trust_attestation_is_active_at|attestation_payload_bytes|attestation_signature_valid|attestation_active_at' src
require_pattern 'use verified_logic::web_of_trust_revocation|web_of_trust_revocation_payload_bytes|web_of_trust_revocation_signature_is_valid|web_of_trust_revocation_matches_attestation|web_of_trust_revocation_is_effective_at|revocation_payload_bytes|revocation_signature_valid|revocation_matches|revocation_effective_at' src
require_pattern 'use verified_logic::web_of_trust_policy|web_of_trust_threshold_accepts|threshold_accepts' src
require_pattern 'use verified_logic::web_of_trust_ucan_authorizer|web_of_trust_ucan_authorization' src
require_pattern 'use verified_logic::ucan_did|encode_ed25519_did_key|decode_did_key' src
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
