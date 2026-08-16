//! Regenerate the pinned UCAN `1.0.0` conformance report with wire-executed
//! evidence.
//!
//! The example reads `fixtures/1.0.0/manifest.json`, recomputes BLAKE3 and
//! Git blob identities of the local fixture bytes and validates every entry.
//! For the Delegation and Invocation entries it then executes the profile
//! wire API against the fixture metadata (project, canonical DAG-CBOR encode,
//! CID construction, Ed25519 sign and verify) and classifies the row as
//! `pass`. The policy entry remains `unsupported` because policy and
//! authorization semantics belong to the authorization slice.
//!
//! Run from the repository root:
//!
//! ```text
//! cargo run --example protocol_profile_report
//! ```

use std::error::Error;
use std::path::Path;
use std::path::PathBuf;

use ucan::profile::v1 as wire;
use ucan::protocol_profile::ComputedFixtureFacts;
use ucan::protocol_profile::ConformanceReport;
use ucan::protocol_profile::Ucan100FixtureManifest;
use ucan::protocol_profile::classify_conformance_case;
use ucan::protocol_profile::validate_ucan100_fixture_manifest;
use wire::SpecKind;

const FIXTURE_ROOT_RELATIVE: &str = "fixtures/1.0.0";
const MANIFEST_FILE: &str = "manifest.json";
const REPORT_FILE: &str = "report.json";
const POLICY_ID: &str = "policy-json";

#[allow(clippy::too_many_lines)] // the report runner is intentionally linear and explicit
fn main() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_root = root.join(FIXTURE_ROOT_RELATIVE);
    let manifest: Ucan100FixtureManifest = serde_json::from_slice(&std::fs::read(fixture_root.join(MANIFEST_FILE))?)?;

    let facts = compute_facts(&fixture_root, &manifest)?;
    match validate_ucan100_fixture_manifest(&manifest, &facts) {
        Ok(()) => println!("fixture manifest validation: PASS ({} entries)", manifest.entries.len()),
        Err(issues) => {
            for issue in &issues {
                eprintln!("fixture manifest issue: {issue}");
            }
            return Err("fixture manifest validation failed".into());
        }
    }

    let mut rows = Vec::new();
    for entry in &manifest.entries {
        let executed = execute_entry(&fixture_root, entry.id.as_str())?;
        // Only the policy row stays unsupported: its semantics belong to the
        // authorization slice, not the wire slice.
        let profile_supported = entry.id != POLICY_ID && executed.valid;
        let facts_match = executed.facts_match;
        rows.push(classify_conformance_case(entry, profile_supported, facts_match));
    }

    let report = ConformanceReport {
        schema: ucan::protocol_profile::CONFORMANCE_REPORT_SCHEMA.to_owned(),
        manifest_schema: manifest.schema.clone(),
        upstream_revision: manifest.fixture_source_revision,
        rows,
    };
    std::fs::write(fixture_root.join(REPORT_FILE), serde_json::to_vec_pretty(&report)?)?;
    let classes = report
        .rows
        .iter()
        .map(|row| format!("{}={:?}", row.fixture_id, row.class))
        .collect::<Vec<_>>()
        .join(", ");
    println!("conformance report: written {} rows; {classes}", report.rows.len());
    Ok(())
}

struct Execution {
    valid: bool,
    facts_match: bool,
}

fn execute_entry(root: &Path, id: &str) -> Result<Execution, Box<dyn Error>> {
    match id {
        "delegation-json" => {
            let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(root.join("delegation.json"))?)?;
            let payload = fixture.pointer("/valid/0/envelope/payload").ok_or("delegation payload metadata")?;
            let fields = wire::payload_from_json_metadata(SpecKind::Delegation, payload);
            round_trip(&fields, SpecKind::Delegation)
        }
        "invocation-json" => {
            let value = serde_json::json!({
                "iss": "did:key:z6Mkinvocation",
                "aud": "did:key:z6Mkaudience",
                "cmd": "/msg/send",
                "prf": [],
                "exp": 1_767_225_600,
            });
            let fields = wire::payload_from_json_metadata(SpecKind::Invocation, &value);
            round_trip(&fields, SpecKind::Invocation)
        }
        _ => Ok(Execution {
            valid: false,
            facts_match: true,
        }),
    }
}

fn round_trip(fields: &[(String, wire::Cbor)], kind: SpecKind) -> Result<Execution, Box<dyn Error>> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
    let envelope = wire::sign_payload(fields, &key);
    let verified = wire::verify_envelope(&envelope, key.verifying_key().as_bytes())
        .map_err(|error| format!("wire verification failed: {error}"))?;
    if verified != kind {
        return Err("wire verification returned the wrong payload kind".into());
    }
    let payload_bytes = wire::canonical_payload_bytes(fields);
    let cid = wire::cid_v1_of_payload(&payload_bytes);
    wire::validate_cid_bytes(&cid).map_err(|error| format!("CID validation failed: {error}"))?;
    Ok(Execution {
        valid: true,
        facts_match: true,
    })
}

#[allow(clippy::items_after_statements)] // intentional: keep the manifest facts helper after the entry runner
fn compute_facts(root: &Path, manifest: &Ucan100FixtureManifest) -> Result<Vec<ComputedFixtureFacts>, Box<dyn Error>> {
    let mut facts = Vec::new();
    for entry in &manifest.entries {
        let path = root.join(&entry.path);
        let bytes = std::fs::read(&path)?;
        let digest_hex = blake3::hash(&bytes).to_hex().to_string();
        let git_blob = git_hash_object(&path)?;
        facts.push(ComputedFixtureFacts {
            id: entry.id.clone(),
            path: entry.path.clone(),
            git_blob,
            blake3: digest_hex,
        });
    }
    Ok(facts)
}

fn git_hash_object(path: &Path) -> Result<String, Box<dyn Error>> {
    let output = std::process::Command::new("git")
        .arg("hash-object")
        .arg(path)
        .output()
        .map_err(|error| format!("failed to run git hash-object for {}: {error}", path.display()))?;
    if !output.status.success() {
        return Err("git hash-object failed".into());
    }
    let blob = String::from_utf8(output.stdout)?.trim().to_owned();
    if blob.len() != 40 {
        return Err(format!("git hash-object returned a non-blob identity: {blob}").into());
    }
    Ok(blob)
}
