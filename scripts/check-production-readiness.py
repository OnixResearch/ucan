#!/usr/bin/env python3
"""Fail closed when production-readiness docs overclaim crate support."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs" / "production-readiness.json"
DOCS = [
    ROOT / "README.md",
    ROOT / "docs" / "public-api.md",
    ROOT / "docs" / "verified-boundaries.md",
    ROOT / "docs" / "production-readiness.md",
]
ALLOWED_LEVELS = {"controlled-integration-ready", "preview", "unsupported", "production-supported"}
REQUIRED_UNSUPPORTED = {
    "remote-did-resolution",
    "proof-transport-backends",
    "registry-backed-revocation",
    "replay-persistence-store",
    "non-ed25519-key-algorithms",
}
REQUIRED_CONTROLLED = {
    "ed25519-did-key-compact-token",
    "caller-supplied-key-resolution",
    "caller-supplied-proof-store",
    "caller-supplied-revocation",
    "opaque-caveat-policy-evaluation",
}
GENERIC_PRODUCTION_CLAIM = re.compile(r"\bproduction[- ]supported\b", re.IGNORECASE)


def fail(message: str) -> None:
    print(f"production-readiness: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_report() -> dict:
    try:
        return json.loads(REPORT.read_text())
    except Exception as exc:  # noqa: BLE001 - report parse failure should be explicit
        fail(f"cannot parse {REPORT.relative_to(ROOT)}: {exc}")


def surface_map(report: dict) -> dict[str, dict]:
    surfaces = report.get("surfaces")
    if not isinstance(surfaces, list) or not surfaces:
        fail("report must contain a non-empty surfaces list")
    mapped: dict[str, dict] = {}
    for surface in surfaces:
        if not isinstance(surface, dict):
            fail("each surface must be an object")
        surface_id = surface.get("id")
        level = surface.get("level")
        if not isinstance(surface_id, str) or not surface_id:
            fail("each surface must have a non-empty string id")
        if surface_id in mapped:
            fail(f"duplicate surface id {surface_id}")
        if level not in ALLOWED_LEVELS:
            fail(f"surface {surface_id} has invalid level {level!r}")
        for field in ("evidence", "boundary"):
            if not isinstance(surface.get(field), str) or not surface[field].strip():
                fail(f"surface {surface_id} must include {field}")
        mapped[surface_id] = surface
    return mapped


def check_profile(report: dict) -> None:
    if report.get("crate_level") != "controlled-integration-ready":
        fail("crate_level must remain controlled-integration-ready until every production gate is proven")
    profile = report.get("integration_profile")
    if not isinstance(profile, dict):
        fail("integration_profile must be an object")
    required_inputs = set(profile.get("required_inputs", []))
    fail_closed_inputs = set(profile.get("fail_closed_inputs", []))
    for required in [
        "KeyResolver or KeyResolutionContext",
        "ProofStore or ProofCollection",
        "RevocationChecker or NoRevocations",
        "VerificationTime",
        "VerificationLimits",
        "CaveatPolicySet",
        "TokenSigner and caller-owned key custody",
    ]:
        if required not in required_inputs:
            fail(f"integration profile missing required input {required}")
    if len(fail_closed_inputs) < 6:
        fail("integration profile must enumerate fail-closed backend/policy classes")


def check_surface_levels(surfaces: dict[str, dict]) -> None:
    for surface_id in REQUIRED_UNSUPPORTED:
        if surfaces.get(surface_id, {}).get("level") != "unsupported":
            fail(f"{surface_id} must remain unsupported until its promotion gate lands")
    for surface_id in REQUIRED_CONTROLLED:
        if surfaces.get(surface_id, {}).get("level") != "controlled-integration-ready":
            fail(f"{surface_id} must be labeled controlled-integration-ready")
    promoted = [surface_id for surface_id, surface in surfaces.items() if surface["level"] == "production-supported"]
    if promoted:
        fail(f"no surfaces may be production-supported in this gate without promotion evidence: {promoted}")


def check_docs(surfaces: dict[str, dict]) -> None:
    missing = [path for path in DOCS if not path.exists()]
    if missing:
        fail("missing docs: " + ", ".join(str(path.relative_to(ROOT)) for path in missing))
    text_by_doc = {path: path.read_text() for path in DOCS}
    readiness_doc = text_by_doc[ROOT / "docs" / "production-readiness.md"]
    for surface_id, surface in surfaces.items():
        if surface_id not in readiness_doc:
            fail(f"production-readiness.md missing surface {surface_id}")
        if surface["level"] not in readiness_doc:
            fail(f"production-readiness.md missing level {surface['level']} for {surface_id}")
    for path, text in text_by_doc.items():
        if path.name == "production-readiness.md":
            continue
        if GENERIC_PRODUCTION_CLAIM.search(text) and "docs/production-readiness" not in text:
            fail(f"{path.relative_to(ROOT)} mentions production-supported without linking readiness report")
    readme = text_by_doc[ROOT / "README.md"]
    for phrase in [
        "controlled-integration ready",
        "not a turnkey production UCAN platform",
        "docs/production-readiness.md",
    ]:
        if phrase not in readme:
            fail(f"README.md missing readiness phrase {phrase!r}")


def main() -> None:
    report = load_report()
    surfaces = surface_map(report)
    check_profile(report)
    check_surface_levels(surfaces)
    check_docs(surfaces)
    print(
        "production-readiness: PASS "
        f"crate_level={report['crate_level']} surfaces={len(surfaces)}"
    )


if __name__ == "__main__":
    main()
