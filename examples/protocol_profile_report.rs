//! Regenerate the pinned UCAN `1.0.0` conformance report.
//!
//! The example reads `fixtures/1.0.0/manifest.json`, computes the exact
//! BLAKE3 and Git blob identities of the local fixture bytes, validates every
//! entry against the pure-core manifest validator, and writes the
//! deterministic conformance report to `fixtures/1.0.0/report.json`.
//!
//! Run from the repository root:
//!
//! ```text
//! cargo run --example protocol_profile_report
//! cargo run --locked --example protocol_profile_report
//! ```

use std::error::Error;
use std::path::Path;
use std::path::PathBuf;

use ucan::protocol_profile::ComputedFixtureFacts;
use ucan::protocol_profile::UCAN_WG_1_0_0;
use ucan::protocol_profile::Ucan100FixtureManifest;
use ucan::protocol_profile::build_conformance_report;
use ucan::protocol_profile::validate_ucan100_fixture_manifest;

const FIXTURE_ROOT_RELATIVE: &str = "fixtures/1.0.0";
const MANIFEST_FILE: &str = "manifest.json";
const REPORT_FILE: &str = "report.json";

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

    // The final UCAN 1.0.0 profile is declared but not implemented in this
    // crate revision, so every pinned case is classified as unsupported.
    let report = build_conformance_report(&manifest, false, true);
    let output = serde_json::to_vec_pretty(&report)?;
    std::fs::write(fixture_root.join(REPORT_FILE), output)?;
    let classes = report
        .rows
        .iter()
        .map(|row| format!("{}={:?}", row.profile_id, row.class))
        .collect::<Vec<_>>()
        .join(", ");
    println!("conformance report: written {} rows; {}", report.rows.len(), classes);
    println!("bound profile: {UCAN_WG_1_0_0}");
    Ok(())
}

fn compute_facts(root: &Path, manifest: &Ucan100FixtureManifest) -> Result<Vec<ComputedFixtureFacts>, Box<dyn Error>> {
    let mut facts = Vec::new();
    for entry in &manifest.entries {
        let path = root.join(&entry.path);
        let bytes = std::fs::read(&path)?;
        let digest = blake3::hash(&bytes).to_hex().to_string();
        let git_blob = git_hash_object(&path)?;
        facts.push(ComputedFixtureFacts {
            id: entry.id.clone(),
            path: entry.path.clone(),
            git_blob,
            blake3: digest,
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
