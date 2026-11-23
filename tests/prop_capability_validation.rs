use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use hegel::TestCase;
use hegel::generators::sampled_from;
use ucan::core::CapabilityError;
use ucan::core::CapabilityField;
use ucan::core::CapabilityView;

const VALID_RESOURCES: [&str; 4] = [
    "did:key:z6Mkalpha",
    "did:key:z6Mkbravo",
    "did:key:z6Mkcharlie",
    "did:key:z6Mkdelta",
];
const VALID_NAMESPACES: [&str; 4] = ["store", "upload", "queue", "email"];
const VALID_ACTIONS: [&str; 4] = ["add", "read", "write", "*"];
const EMBEDDED_WILDCARD_NAMESPACES: [&str; 3] = ["sto*re", "upl*oad", "que*ue"];
const INVALID_ABILITIES: [&str; 4] = ["store//add", "store/Add", " store/add", "store/add "];
const INVALID_WILDCARD_CHARACTER: char = '*';
const INVALID_UPPERCASE_CHARACTER: char = 'A';

const HEGEL_SERVER_VERSION: &str = "0.2.3";
const HEGEL_SERVER_COMMAND_ENV: &str = "HEGEL_SERVER_COMMAND";
const HEGEL_BOOTSTRAP_TIMEOUT_ENV: &str = "UCAN_HEGEL_BOOTSTRAP_TIMEOUT_SECS";
const HEGEL_TEST_TIMEOUT_ENV: &str = "UCAN_HEGEL_TEST_TIMEOUT_SECS";
const DEFAULT_BOOTSTRAP_TIMEOUT_SECS: u64 = 45;
const DEFAULT_TEST_TIMEOUT_SECS: u64 = 60;
const POLL_INTERVAL: Duration = Duration::from_millis(50);

static HEGEL_READY: OnceLock<Result<(), String>> = OnceLock::new();

fn timeout_from_env(var_name: &str, default_secs: u64) -> Duration {
    std::env::var(var_name)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .map_or_else(|| Duration::from_secs(default_secs), Duration::from_secs)
}

fn run_command_with_timeout(
    program: &str,
    args: &[&str],
    log_path: &Path,
    timeout: Duration,
    label: &str,
) -> Result<(), String> {
    let log_file = fs::File::create(log_path)
        .map_err(|err| format!("failed to create Hegel log {}: {err}", log_path.display()))?;
    let stderr_file = log_file
        .try_clone()
        .map_err(|err| format!("failed to clone Hegel log handle {}: {err}", log_path.display()))?;
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .map_err(|err| {
            format!(
                "Hegel bootstrap failed to start `{label}` ({err}). \
                 Ensure `uv` is on PATH (or enter `nix develop`), set `{HEGEL_SERVER_COMMAND_ENV}` \
                 to an existing `hegel` binary, or run offline tests with `--lib --examples`."
            )
        })?;

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                let log = fs::read_to_string(log_path).unwrap_or_default();
                return Err(format!(
                    "Hegel bootstrap command `{label}` exited with {status}. \
                     Offline/network-restricted runs cannot install `hegel-core=={HEGEL_SERVER_VERSION}` via `uv`; \
                     set `{HEGEL_SERVER_COMMAND_ENV}` to a preinstalled `hegel` binary or run `--lib --examples`.\n\
                     Install log ({}):\n{log}",
                    log_path.display()
                ));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    let log = fs::read_to_string(log_path).unwrap_or_default();
                    return Err(format!(
                        "Hegel bootstrap command `{label}` timed out after {}s (likely offline or stalled network). \
                         Set `{HEGEL_SERVER_COMMAND_ENV}` to a preinstalled `hegel` binary, raise \
                         `{HEGEL_BOOTSTRAP_TIMEOUT_ENV}`, or run offline tests with `--lib --examples`.\n\
                         Install log ({}):\n{log}",
                        timeout.as_secs(),
                        log_path.display()
                    ));
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("failed waiting for Hegel bootstrap command `{label}`: {err}"));
            }
        }
    }
}

fn verify_override_binary(override_path: &str) -> Result<(), String> {
    let path = Path::new(override_path);
    if path.is_file() {
        return Ok(());
    }
    Err(format!(
        "`{HEGEL_SERVER_COMMAND_ENV}` points to `{override_path}`, which does not exist or is not a file"
    ))
}

fn ensure_hegel_server_ready() -> Result<(), String> {
    if let Ok(override_path) = std::env::var(HEGEL_SERVER_COMMAND_ENV) {
        return verify_override_binary(&override_path);
    }

    let hegel_dir = PathBuf::from(".hegel");
    let venv_dir = hegel_dir.join("venv");
    let version_file = venv_dir.join("hegel-version");
    let hegel_bin = venv_dir.join("bin").join("hegel");
    if let Ok(cached) = fs::read_to_string(&version_file)
        && cached.trim() == HEGEL_SERVER_VERSION
        && hegel_bin.is_file()
    {
        return Ok(());
    }

    fs::create_dir_all(&hegel_dir)
        .map_err(|err| format!("failed to create Hegel directory {}: {err}", hegel_dir.display()))?;

    let timeout = timeout_from_env(HEGEL_BOOTSTRAP_TIMEOUT_ENV, DEFAULT_BOOTSTRAP_TIMEOUT_SECS);
    let install_log = hegel_dir.join("install.log");
    let venv_str = venv_dir.to_string_lossy().into_owned();
    run_command_with_timeout("uv", &["venv", "--clear", &venv_str], &install_log, timeout, "uv venv")?;

    let python_path = venv_dir.join("bin").join("python");
    let python_str = python_path.to_string_lossy().into_owned();
    let constraints_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("hegel-constraints.txt");
    let constraints_str = constraints_path.to_string_lossy().into_owned();
    let package_spec = format!("hegel-core=={HEGEL_SERVER_VERSION}");
    run_command_with_timeout(
        "uv",
        &[
            "pip",
            "install",
            "--python",
            &python_str,
            "-c",
            &constraints_str,
            &package_spec,
        ],
        &install_log,
        timeout,
        "uv pip install hegel-core",
    )?;

    if !hegel_bin.is_file() {
        return Err(format!("Hegel binary missing at {} after `uv pip install` succeeded", hegel_bin.display()));
    }
    fs::write(&version_file, HEGEL_SERVER_VERSION)
        .map_err(|err| format!("failed to write Hegel version marker {}: {err}", version_file.display()))?;
    Ok(())
}

fn run_hegel_property<F>(test_name: &'static str, property: F)
where F: Fn(TestCase) + Send + 'static {
    if let Err(message) = HEGEL_READY.get_or_init(ensure_hegel_server_ready) {
        panic!("{test_name}: {message}");
    }

    let timeout = timeout_from_env(HEGEL_TEST_TIMEOUT_ENV, DEFAULT_TEST_TIMEOUT_SECS);
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name(format!("hegel-{test_name}"))
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                hegel::hegel(property);
            }));
            let _ = tx.send(outcome);
        })
        .expect("failed to spawn Hegel property test thread");

    match rx.recv_timeout(timeout) {
        Ok(Ok(())) => {}
        Ok(Err(payload)) => std::panic::resume_unwind(payload),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!(
                "{test_name}: timed out after {}s waiting for Hegel property server. \
                 Verify `.hegel/venv` uses `tests/hegel-constraints.txt` (hypothesis==6.148.5), \
                 or raise `{HEGEL_TEST_TIMEOUT_ENV}`.",
                timeout.as_secs()
            );
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("{test_name}: Hegel property test thread exited unexpectedly");
        }
    }
}

#[test]
fn prop_valid_capability_parts_round_trip() {
    run_hegel_property("prop_valid_capability_parts_round_trip", |tc| {
        let resource = tc.draw(sampled_from(VALID_RESOURCES.to_vec()));
        let namespace = tc.draw(sampled_from(VALID_NAMESPACES.to_vec()));
        let action = tc.draw(sampled_from(VALID_ACTIONS.to_vec()));
        let ability = format!("{namespace}/{action}");

        let capability =
            CapabilityView::new(resource, ability.as_str()).expect("generated capability parts should validate");

        assert_eq!(capability.resource(), resource);
        assert_eq!(capability.ability(), ability.as_str());
    });
}

#[test]
fn prop_embedded_wildcards_are_rejected() {
    run_hegel_property("prop_embedded_wildcards_are_rejected", |tc| {
        let resource = tc.draw(sampled_from(VALID_RESOURCES.to_vec()));
        let namespace = tc.draw(sampled_from(EMBEDDED_WILDCARD_NAMESPACES.to_vec()));
        let ability = format!("{namespace}/add");

        let error = CapabilityView::new(resource, ability.as_str())
            .expect_err("embedded wildcard segments must fail validation");

        assert_eq!(error, CapabilityError::InvalidAbilityCharacter {
            character: INVALID_WILDCARD_CHARACTER,
        });
    });
}

#[test]
fn prop_known_invalid_ability_forms_are_rejected() {
    run_hegel_property("prop_known_invalid_ability_forms_are_rejected", |tc| {
        let resource = tc.draw(sampled_from(VALID_RESOURCES.to_vec()));
        let ability = tc.draw(sampled_from(INVALID_ABILITIES.to_vec()));

        let error =
            CapabilityView::new(resource, ability).expect_err("known-invalid ability forms must fail validation");

        match ability {
            "store//add" => assert_eq!(error, CapabilityError::EmptyAbilitySegment),
            "store/Add" => assert_eq!(error, CapabilityError::InvalidAbilityCharacter {
                character: INVALID_UPPERCASE_CHARACTER,
            }),
            " store/add" | "store/add " => assert_eq!(error, CapabilityError::FieldMustBeTrimmed {
                field: CapabilityField::Ability,
            }),
            _ => panic!("unexpected invalid fixture: {ability}"),
        }
    });
}

#[test]
fn hegel_bootstrap_timeout_and_missing_override_fail_fast() {
    let missing = verify_override_binary("/nonexistent/path/to/hegel")
        .expect_err("missing HEGEL_SERVER_COMMAND override must fail immediately");
    assert!(missing.contains(HEGEL_SERVER_COMMAND_ENV));

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let log_path = temp_dir.path().join("timeout.log");
    let error = run_command_with_timeout("sh", &["-c", "sleep 5"], &log_path, Duration::from_millis(200), "sleep test")
        .expect_err("stalled bootstrap command must time out instead of hanging");
    assert!(error.contains("timed out"));
}
