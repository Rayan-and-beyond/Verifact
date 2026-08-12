#!/usr/bin/env python3
"""Verifact deterministic assessment toolkit.

The agent owns investigation and judgment. This program owns frozen-run selection,
integrity checks, finding/review validation, coverage calculation, and report build.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import os
import re
import secrets
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ASSESSMENT_VERSION = "2.0"
VERIFACT_VERSION = "2.0.0"
SKILL_ROOT = Path(__file__).resolve().parent.parent
FINDING_ID_RE = re.compile(r"^VF-\d{4}-\d{3,}$")
ASSESSMENT_ID_RE = re.compile(r"^VA-\d{8}T\d{6}Z-[A-F0-9]{6}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
ALLOWED_STATES = {"candidate", "validated", "rejected", "inconclusive"}
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
ALLOWED_CONFIDENCES = {"high", "medium", "low"}
ALLOWED_DOMAINS = {
    "event-activity",
    "identity",
    "audit-logging",
    "persistence",
    "network-exposure",
    "sharing-permissions",
    "hardening",
    "updates-software",
}
EVENT_DOMAINS = {"event-activity"}
POSTURE_DOMAINS = ALLOWED_DOMAINS - EVENT_DOMAINS
POSTURE_CATEGORY_DOMAIN = {
    "identity": "identity",
    "audit-logging": "audit-logging",
    "persistence": "persistence",
    "exposure": "network-exposure",
    "sharing-permissions": "sharing-permissions",
    "hardening": "hardening",
    "updates-software": "updates-software",
}
ALLOWED_ASSESSMENT_STATUSES = {"initialized", "collected", "analyzing", "reviewed", "published"}
FINAL_REVIEW = {"validated": "validate", "rejected": "reject", "inconclusive": "inconclusive"}
REVIEW_TYPES = {"independent-agent", "human-reviewer", "same-agent-separated-pass"}
FINDING_FIELDS = {
    "schemaVersion", "id", "title", "state", "category", "severity", "confidence",
    "claim", "impact", "conditions", "evidence", "research", "limitations", "remediation",
    "analyst", "createdUtc", "updatedUtc",
}
REVIEW_FIELDS = {
    "schemaVersion", "findingId", "decision", "reviewedUtc", "reviewer",
    "independence", "identityAssurance", "findingSha256", "summary", "objections",
}


class VerifactError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def assessment_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"VA-{stamp}-{secrets.token_hex(3).upper()}"


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8-sig") as fh:
            return json.load(fh)
    except FileNotFoundError as exc:
        raise VerifactError(f"Missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise VerifactError(f"Invalid JSON in {path}: {exc}") from exc


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(value, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    tmp.replace(path)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(value, encoding="utf-8", newline="\n")
    tmp.replace(path)


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def valid_datetime(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def parse_datetime(value: Any) -> datetime | None:
    if not valid_datetime(value):
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def skill_json(relative: str) -> Any:
    return load_json(SKILL_ROOT / relative)


def required_run_kinds(doc: dict[str, Any]) -> set[str]:
    scope = doc.get("scope") if isinstance(doc.get("scope"), dict) else {}
    raw_domains = scope.get("domains") or []
    domains = {value for value in raw_domains if isinstance(value, str)}
    required: set[str] = set()
    if domains & EVENT_DOMAINS:
        required.add("events")
    if domains & POSTURE_DOMAINS:
        required.add("posture")
    return required


def scope_config_record(root: Path, relative: str) -> dict[str, str]:
    path = root / relative
    return {"path": relative, "sha256": sha256_file(path)}


def assessment_scope_config(root: Path, doc: dict[str, Any], kind: str) -> dict[str, Any]:
    configs = (doc.get("scope") or {}).get("configs") or {}
    record = configs.get(kind) if isinstance(configs, dict) else None
    if not isinstance(record, dict):
        raise VerifactError(f"Assessment scope has no frozen {kind} config")
    path = bounded_path(root, str(record.get("path") or ""))
    if not path.is_file():
        raise VerifactError(f"Frozen {kind} config is missing: {record.get('path')}")
    actual = sha256_file(path)
    expected = str(record.get("sha256") or "").lower()
    if actual != expected:
        raise VerifactError(f"Frozen {kind} config hash mismatch")
    data = load_json(path)
    if not isinstance(data, dict):
        raise VerifactError(f"Frozen {kind} config must be a JSON object")
    return data


def bounded_path(root: Path, relative: str) -> Path:
    if not relative or os.path.isabs(relative):
        raise VerifactError(f"Path must be relative to assessment/run root: {relative!r}")
    candidate = (root / relative).resolve()
    root_resolved = root.resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise VerifactError(f"Path escapes bounded root: {relative}") from exc
    return candidate


def relative_inside(root: Path, child: Path) -> str:
    try:
        return child.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise VerifactError(f"Path must be inside assessment directory: {child}") from exc


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.assessment).resolve()
    if root.exists() and any(root.iterdir()):
        raise VerifactError(f"Assessment directory is not empty: {root}. Choose a new or empty directory.")
    domains = args.domains or sorted(ALLOWED_DOMAINS)
    unknown_domains = sorted(set(domains) - ALLOWED_DOMAINS)
    if unknown_domains:
        raise VerifactError(f"Unknown assessment domain(s): {', '.join(unknown_domains)}")
    root.mkdir(parents=True, exist_ok=True)
    for rel in [
        "evidence/events/runs",
        "evidence/posture/runs",
        "findings",
        "reviews",
        "notes",
        "report",
        "config",
    ]:
        (root / rel).mkdir(parents=True, exist_ok=True)
    domain_set = set(domains)
    new_assessment_id = assessment_id()
    configs: dict[str, dict[str, str]] = {}
    if domain_set & EVENT_DOMAINS:
        event_scope = skill_json("config/event-scope.json")
        event_scope["assessmentId"] = new_assessment_id
        event_scope["defaultWindowDays"] = args.event_days
        write_json(root / "config/event-scope.json", event_scope)
        write_json(root / "config/analysis-scope.json", skill_json("config/analysis-scope.json"))
        configs["events"] = scope_config_record(root, "config/event-scope.json")
        configs["analysis"] = scope_config_record(root, "config/analysis-scope.json")
        configs["eventNormalizer"] = {
            "path": "skill:scripts/windows/Export-VerifactTriageData.ps1",
            "sha256": sha256_file(SKILL_ROOT / "scripts/windows/Export-VerifactTriageData.ps1"),
        }
    if domain_set & POSTURE_DOMAINS:
        posture = skill_json("config/posture-scope.json")
        posture["assessmentId"] = new_assessment_id
        posture["sources"] = [
            source for source in posture.get("sources") or []
            if POSTURE_CATEGORY_DOMAIN.get(str(source.get("category"))) in domain_set
        ]
        if "sharing-permissions" in domain_set:
            dependency_ids = {
                "persistence-services", "persistence-scheduled-tasks", "persistence-startup-commands",
                "persistence-startup-folders", "persistence-run-keys",
            }
            full_posture = skill_json("config/posture-scope.json")
            existing_ids = {source.get("id") for source in posture["sources"]}
            posture["sources"].extend(
                source for source in full_posture.get("sources") or []
                if source.get("id") in dependency_ids and source.get("id") not in existing_ids
            )
        if not posture["sources"]:
            raise VerifactError("The selected posture domains produced an empty collection scope")
        write_json(root / "config/posture-scope.json", posture)
        configs["posture"] = scope_config_record(root, "config/posture-scope.json")
        configs["postureNormalizer"] = {
            "path": "skill:scripts/windows/Export-VerifactPostureInventory.ps1",
            "sha256": sha256_file(SKILL_ROOT / "scripts/windows/Export-VerifactPostureInventory.ps1"),
        }
        configs["postureCollector"] = {
            "path": "skill:scripts/windows/Collect-VerifactPosture.ps1",
            "sha256": sha256_file(SKILL_ROOT / "scripts/windows/Collect-VerifactPosture.ps1"),
        }
    if domain_set & EVENT_DOMAINS:
        configs["eventCollector"] = {
            "path": "skill:scripts/windows/Collect-VerifactEvidence.ps1",
            "sha256": sha256_file(SKILL_ROOT / "scripts/windows/Collect-VerifactEvidence.ps1"),
        }

    now = utc_now()
    doc = {
        "schemaVersion": ASSESSMENT_VERSION,
        "assessmentId": new_assessment_id,
        "createdUtc": now,
        "updatedUtc": now,
        "status": "initialized",
        "target": {"kind": "windows-endpoint", "label": args.target, "hostIdentitySha256": None},
        "scope": {
            "mode": "read-only",
            "domains": domains,
            "excludedFamilies": ["Microsoft Defender-specific collection"],
            "configs": configs,
        },
        "selectedRuns": {},
        "coverage": {"status": "unknown", "limitations": []},
    }
    write_json(root / "assessment.json", doc)
    print(f"Initialized {doc['assessmentId']} at {root}")
    return 0


def selected_run_record(assessment_root: Path, run_dir: Path, kind: str) -> dict[str, str]:
    run_dir = run_dir.resolve()
    expected_root = assessment_root / "evidence" / kind / "runs"
    try:
        run_dir.relative_to(expected_root.resolve())
    except ValueError as exc:
        raise VerifactError(f"{kind} run must be inside {expected_root}: {run_dir}") from exc
    manifest = run_dir / "manifest.json"
    if not manifest.is_file():
        raise VerifactError(f"Run manifest not found: {manifest}")
    data = load_json(manifest)
    if not isinstance(data, dict):
        raise VerifactError(f"Run manifest must be a JSON object: {manifest}")
    run_id = str(data.get("runId") or run_dir.name)
    host_identity = str(data.get("hostIdentitySha256") or "").lower()
    if not SHA256_RE.fullmatch(host_identity):
        raise VerifactError(f"{kind} manifest has no valid hostIdentitySha256")
    return {
        "runId": run_id,
        "manifest": relative_inside(assessment_root, manifest),
        "manifestSha256": sha256_file(manifest),
        "hostIdentitySha256": host_identity,
    }


def cmd_select(args: argparse.Namespace) -> int:
    root = Path(args.assessment).resolve()
    assessment_path = root / "assessment.json"
    doc = load_json(assessment_path)
    if not isinstance(doc, dict):
        raise VerifactError("assessment.json must contain a JSON object")
    selected = dict(doc.get("selectedRuns") or {})
    if args.events_run:
        record = selected_run_record(root, Path(args.events_run), "events")
        run_errors, _, _ = verify_run("events", root, record, doc)
        if run_errors:
            raise VerifactError("Event run cannot be selected:\n - " + "\n - ".join(run_errors))
        selected["events"] = record
    if args.posture_run:
        record = selected_run_record(root, Path(args.posture_run), "posture")
        run_errors, _, _ = verify_run("posture", root, record, doc)
        if run_errors:
            raise VerifactError("Posture run cannot be selected:\n - " + "\n - ".join(run_errors))
        selected["posture"] = record
    if not args.events_run and not args.posture_run:
        raise VerifactError("Select at least one run with --events-run or --posture-run.")
    identities = {str(record.get("hostIdentitySha256") or "") for record in selected.values() if isinstance(record, dict)}
    if len(identities) != 1:
        raise VerifactError("Selected event and posture runs do not come from the same Windows host")
    selected_identity = next(iter(identities))
    target = doc.get("target") if isinstance(doc.get("target"), dict) else {}
    frozen_identity = str(target.get("hostIdentitySha256") or "")
    if frozen_identity and frozen_identity != selected_identity:
        raise VerifactError("Selected run does not match the host identity already frozen for this assessment")
    target["hostIdentitySha256"] = selected_identity
    doc["target"] = target
    doc["selectedRuns"] = selected
    doc["status"] = "collected"
    doc["updatedUtc"] = utc_now()
    write_json(assessment_path, doc)
    for kind, record in selected.items():
        print(f"Selected {kind}: {record['runId']}  sha256={record['manifestSha256']}")
    return 0


def verify_reference(run_dir: Path, rel: str, expected_size: Any, expected_hash: Any, label: str, errors: list[str]) -> None:
    try:
        path = bounded_path(run_dir, rel)
    except VerifactError as exc:
        errors.append(f"{label}: {exc}")
        return
    if not path.is_file():
        errors.append(f"{label}: referenced file is missing: {rel}")
        return
    actual_size = path.stat().st_size
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
        errors.append(f"{label}: sizeBytes is missing or malformed for {rel}")
    elif expected_size != actual_size:
        errors.append(f"{label}: byte length mismatch for {rel} (manifest {expected_size}, actual {actual_size})")
    if not expected_hash or not SHA256_RE.fullmatch(str(expected_hash).lower()):
        errors.append(f"{label}: SHA-256 missing or malformed for {rel}")
        return
    actual_hash = sha256_file(path)
    if actual_hash != str(expected_hash).lower():
        errors.append(f"{label}: SHA-256 mismatch for {rel}")


def event_coverage(manifest: dict[str, Any], scope: dict[str, Any] | None = None) -> tuple[str, list[str]]:
    limitations: list[str] = []
    core_limitations: list[str] = []
    policy = skill_json("config/assessment-policy.json")
    scope = scope or skill_json("config/event-scope.json")
    discovery_failures = set(policy.get("coreEventFailureStates") or [])
    export_failures = set(policy.get("coreEventExportFailureStates") or [])
    configured = {str(c.get("name")): c for c in scope.get("channels") or [] if isinstance(c, dict)}
    expected_core = {name for name, item in configured.items() if item.get("tier") == "core"}
    raw_channels = manifest.get("channels") or []
    channels = {str(c.get("name")): c for c in raw_channels if isinstance(c, dict)}
    for missing in sorted(expected_core - set(channels)):
        message = f"Configured core event channel {missing} is absent from the run manifest"
        limitations.append(message)
        core_limitations.append(message)
    for name in sorted(set(configured) & set(channels)):
        channel = channels[name]
        discovery = str(channel.get("discoveryStatus") or "")
        export = str(channel.get("exportStatus") or "")
        # An empty retained channel is valid evidence, not a collection failure.
        # It has nothing to export, so collectors legitimately record not-exported.
        export_failed = discovery != "empty" and export in export_failures
        if discovery in discovery_failures or export_failed:
            tier = str(configured[name].get("tier") or "optional")
            message = f"{tier.capitalize()} event channel {channel.get('name')} is incomplete: discovery={discovery or 'unknown'}, export={export or 'unknown'}"
            limitations.append(message)
            if tier == "core":
                core_limitations.append(message)
    return ("degraded" if core_limitations else "complete", limitations)


def posture_coverage(manifest: dict[str, Any], scope: dict[str, Any] | None = None) -> tuple[str, list[str]]:
    limitations: list[str] = []
    if manifest.get("currentUserProfileCoverage") == "degraded-elevated-identity":
        limitations.append("Current-user HKCU and APPDATA coverage reflects an alternate elevated identity, not necessarily the invoking user")
    bad = {"partial", "unavailable", "unsupported", "inaccessible", "failed"}
    scope = scope or skill_json("config/posture-scope.json")
    expected = {str(s.get("id")) for s in scope.get("sources") or []}
    raw_artifacts = manifest.get("artifacts") or []
    artifacts = raw_artifacts if isinstance(raw_artifacts, list) else []
    actual = {str(a.get("id")) for a in artifacts if isinstance(a, dict)}
    for missing in sorted(expected - actual):
        limitations.append(f"Configured posture source {missing} is absent from the run manifest")
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        if str(artifact.get("status")) in bad:
            limitations.append(
                f"Posture source {artifact.get('id', artifact.get('path', 'unknown'))} is {artifact.get('status')}"
            )
    transcript = manifest.get("transcript") or {}
    if transcript and transcript.get("status") not in {None, "collected", "created"}:
        limitations.append("Posture collection transcript was not captured cleanly")
    if manifest.get("status") == "completed-with-limitations" and not limitations:
        limitations.append("Posture collector reported limitations")
    return ("degraded" if limitations else "complete", limitations)


def verify_run(
    kind: str,
    assessment_root: Path,
    record: dict[str, Any],
    assessment: dict[str, Any] | None = None,
) -> tuple[list[str], list[str], dict[str, Any]]:
    errors: list[str] = []
    if not isinstance(record, dict):
        return [f"{kind}: selected run record must be a JSON object"], [], {}
    manifest_path = bounded_path(assessment_root, str(record.get("manifest", "")))
    if not manifest_path.is_file():
        return [f"{kind}: selected manifest is missing: {record.get('manifest')}"], [], {}
    actual_manifest_hash = sha256_file(manifest_path)
    expected_manifest_hash = str(record.get("manifestSha256") or "").lower()
    if actual_manifest_hash != expected_manifest_hash:
        errors.append(
            f"{kind}: selected manifest hash mismatch (expected {expected_manifest_hash}, actual {actual_manifest_hash})"
        )
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        return errors + [f"{kind}: run manifest must be a JSON object"], [], {}
    run_dir = manifest_path.parent
    if str(record.get("runId")) != str(manifest.get("runId")):
        errors.append(f"{kind}: selected run ID does not match manifest run ID")
    manifest_identity = str(manifest.get("hostIdentitySha256") or "").lower()
    record_identity = str(record.get("hostIdentitySha256") or "").lower()
    if not SHA256_RE.fullmatch(manifest_identity):
        errors.append(f"{kind}: manifest hostIdentitySha256 is missing or malformed")
    if manifest_identity != record_identity:
        errors.append(f"{kind}: selected host identity does not match the manifest")
    identity_strength = str(manifest.get("hostIdentityStrength") or "unknown")
    started = parse_datetime(manifest.get("collectionStartedUtc"))
    completed = parse_datetime(manifest.get("collectionCompletedUtc"))
    if started is None or completed is None:
        errors.append(f"{kind}: collection timestamps are missing or malformed")
    elif completed < started:
        errors.append(f"{kind}: collectionCompletedUtc precedes collectionStartedUtc")
    elif completed > datetime.now(timezone.utc) + timedelta(minutes=5):
        errors.append(f"{kind}: collectionCompletedUtc is in the future")
    if assessment is not None and started is not None:
        assessment_created = parse_datetime(assessment.get("createdUtc"))
        if assessment_created is not None and started < assessment_created:
            errors.append(f"{kind}: collectionStartedUtc predates the assessment")
    if manifest.get("readOnlyCollection") is not True:
        errors.append(f"{kind}: manifest does not assert read-only collection")
    if manifest.get("defenderSpecificCollectionExcluded") is not True:
        errors.append(f"{kind}: manifest does not assert the Defender-specific collection exclusion")
    if assessment is not None and manifest.get("assessmentId") != assessment.get("assessmentId"):
        errors.append(f"{kind}: manifest assessmentId does not match the assessment")
    if manifest.get("currentHostOnly") is not True:
        errors.append(f"{kind}: manifest does not assert current-host-only collection")
    if kind == "events":
        if manifest.get("schemaVersion") != "2.0":
            errors.append("events: only Verifact v2 event manifests may be selected")
        if manifest.get("assessmentDomain") != "event-evidence":
            errors.append("events: manifest assessmentDomain must be event-evidence")
        if manifest.get("mode") != "full-export":
            errors.append("events: inventory-only runs cannot be used as assessment evidence")
        if assessment is not None:
            try:
                event_scope = assessment_scope_config(assessment_root, assessment, "events")
                if manifest.get("requestedDays") != event_scope.get("defaultWindowDays"):
                    errors.append("events: collection window does not match the frozen assessment scope")
            except VerifactError as exc:
                errors.append(f"events: {exc}")
        if manifest.get("status") not in {"completed", "completed-degraded"}:
            errors.append(f"events: unsupported run status {manifest.get('status')!r}")
    else:
        if manifest.get("assessmentDomain") != "host-posture":
            errors.append("posture: manifest assessmentDomain must be host-posture")
        if manifest.get("mode") != "full-snapshot":
            errors.append("posture: manifest mode must be full-snapshot")
        if manifest.get("status") not in {"completed", "completed-with-limitations"}:
            errors.append(f"posture: unsupported run status {manifest.get('status')!r}")

    raw_artifacts = manifest.get("artifacts") or []
    if not isinstance(raw_artifacts, list):
        errors.append(f"{kind}: artifacts must be an array")
        artifacts: list[Any] = []
    else:
        artifacts = raw_artifacts
    seen_artifact_paths: set[str] = set()
    if artifacts:
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                errors.append(f"{kind}: artifact {index} must be an object")
                continue
            rel = artifact.get("path")
            if not rel:
                status = str(artifact.get("status") or "")
                if status in {"collected", "partial", "empty"}:
                    errors.append(f"{kind}: artifact {artifact.get('id', index)} has status {status} but no path")
                continue
            if str(rel) in seen_artifact_paths:
                errors.append(f"{kind}: duplicate artifact path in manifest: {rel}")
                continue
            seen_artifact_paths.add(str(rel))
            verify_reference(
                run_dir,
                str(rel),
                artifact.get("sizeBytes"),
                artifact.get("sha256"),
                f"{kind} artifact {artifact.get('id', artifact.get('channel', index))}",
                errors,
            )
    else:
        errors.append(f"{kind}: v2 run manifest contains no artifact inventory")

    if kind == "events":
        channels = manifest.get("channels") if isinstance(manifest.get("channels"), list) else []
        allowed_discovery = {"present", "empty", "disabled", "missing-or-inaccessible", "present-boundary-read-failed"}
        allowed_export = {"exported", "not-exported", "outside-requested-window", "export-failed"}
        artifact_by_path = {str(item.get("path")): item for item in artifacts if isinstance(item, dict) and item.get("path")}
        seen_channels: set[str] = set()
        for index, channel in enumerate(channels):
            if not isinstance(channel, dict):
                errors.append(f"events: channel {index} must be an object")
                continue
            name = str(channel.get("name") or "")
            if not name or name in seen_channels:
                errors.append(f"events: channel name is missing or duplicated: {name!r}")
            seen_channels.add(name)
            discovery = str(channel.get("discoveryStatus") or "")
            export = str(channel.get("exportStatus") or "")
            if discovery not in allowed_discovery:
                errors.append(f"events: channel {name} has unsupported discoveryStatus {discovery!r}")
            if export not in allowed_export:
                errors.append(f"events: channel {name} has unsupported exportStatus {export!r}")
            if discovery in {"empty", "disabled", "missing-or-inaccessible", "present-boundary-read-failed"}:
                if export != "not-exported":
                    errors.append(f"events: channel {name} has an impossible discovery/export state combination")
            elif discovery == "present" and export not in {"exported", "outside-requested-window", "export-failed"}:
                errors.append(f"events: channel {name} has an impossible discovery/export state combination")
            if export == "exported":
                path = str(channel.get("exportPath") or "")
                artifact = artifact_by_path.get(path)
                if not artifact:
                    errors.append(f"events: exported channel {name} is absent from the artifact inventory")
                elif (
                    artifact.get("sha256") != channel.get("sha256")
                    or artifact.get("sizeBytes") != channel.get("exportSizeBytes")
                ):
                    errors.append(f"events: exported channel {name} disagrees with the artifact inventory")
    else:
        allowed_statuses = {"collected", "empty", "partial", "unavailable", "unsupported", "inaccessible", "failed"}
        for index, artifact in enumerate(artifacts):
            if isinstance(artifact, dict) and str(artifact.get("status") or "") not in allowed_statuses:
                errors.append(f"posture: artifact {artifact.get('id', index)} has unsupported status {artifact.get('status')!r}")

    transcript = manifest.get("transcript") or {}
    if not isinstance(transcript, dict):
        errors.append(f"{kind}: transcript must be an object")
        transcript = {}
    if transcript.get("status") in {"collected", "created"} and transcript.get("sha256"):
        verify_reference(
            run_dir,
            str(transcript.get("path") or ""),
            transcript.get("sizeBytes"),
            transcript.get("sha256"),
            f"{kind} transcript",
            errors,
        )

    collector_path = manifest.get("collectorSnapshot")
    collector_hash = manifest.get("collectorSha256")
    if not collector_path or not collector_hash:
        errors.append(f"{kind}: collector snapshot provenance is required")
    else:
        try:
            cp = bounded_path(run_dir, str(collector_path))
            if not cp.is_file():
                errors.append(f"{kind}: collector snapshot is missing: {collector_path}")
            elif sha256_file(cp) != str(collector_hash).lower():
                errors.append(f"{kind}: collector snapshot hash mismatch")
        except VerifactError as exc:
            errors.append(f"{kind}: {exc}")

    configured_scope: dict[str, Any] | None = None
    if assessment is not None:
        try:
            configured_scope = assessment_scope_config(assessment_root, assessment, kind)
            configs = (assessment.get("scope") or {}).get("configs") or {}
            expected_scope_hash = str((configs.get(kind) or {}).get("sha256") or "").lower()
            collector_config_name = "eventCollector" if kind == "events" else "postureCollector"
            expected_collector_hash = str((configs.get(collector_config_name) or {}).get("sha256") or "").lower()
            if str(collector_hash or "").lower() != expected_collector_hash:
                errors.append(f"{kind}: collector snapshot is not the pinned Verifact collector")
            if str(manifest.get("collectionPlanSha256") or "").lower() != expected_scope_hash:
                errors.append(f"{kind}: manifest is not bound to the frozen collection plan")
            snapshot_rel = str(manifest.get("scopeConfigSnapshot") or "")
            snapshot_path = bounded_path(run_dir, snapshot_rel)
            if not snapshot_path.is_file():
                errors.append(f"{kind}: frozen collection-scope snapshot is missing")
            elif sha256_file(snapshot_path) != expected_scope_hash:
                errors.append(f"{kind}: collection scope does not match the assessment's frozen scope")
            if kind == "events":
                configured_channels = {
                    str(item.get("name")): item
                    for item in configured_scope.get("channels") or [] if isinstance(item, dict)
                }
                actual_channels = {
                    str(item.get("name")): item
                    for item in manifest.get("channels") or [] if isinstance(item, dict)
                }
                expected_names = set(configured_channels)
                actual_names = set(actual_channels)
                if actual_names != expected_names:
                    errors.append("events: manifest channels do not exactly match the frozen assessment scope")
                for name in sorted(expected_names & actual_names):
                    if actual_channels[name].get("tier") != configured_channels[name].get("tier"):
                        errors.append(f"events: channel {name} tier does not match the frozen assessment scope")
            else:
                expected_ids = {str(item.get("id")) for item in configured_scope.get("sources") or [] if isinstance(item, dict)}
                actual_ids = {
                    str(item.get("id")) for item in manifest.get("artifacts") or []
                    if isinstance(item, dict) and not str(item.get("id") or "").startswith("metadata-")
                }
                if actual_ids != expected_ids:
                    errors.append("posture: manifest sources do not exactly match the frozen assessment scope")
        except VerifactError as exc:
            errors.append(f"{kind}: {exc}")

    if kind == "events":
        coverage, limitations = event_coverage(manifest, configured_scope)
    else:
        coverage, limitations = posture_coverage(manifest, configured_scope)
    if identity_strength != "strong":
        limitations.append(f"{kind}: host identity strength is {identity_strength}")
        coverage = "degraded"
    return errors, limitations, {"status": coverage, "manifest": manifest}


def verify_selected(root: Path, doc: dict[str, Any]) -> tuple[list[str], list[str], dict[str, str]]:
    selected = doc.get("selectedRuns") or {}
    errors: list[str] = []
    limitations: list[str] = []
    per_kind: dict[str, str] = {}
    required = required_run_kinds(doc)
    completion_times: list[datetime] = []
    if not isinstance(selected, dict):
        return ["assessment.json: selectedRuns must be an object"], [], {}
    for kind in ("events", "posture"):
        if kind not in selected:
            if kind in required:
                limitations.append(f"No required {kind} run is selected")
                per_kind[kind] = "missing"
            continue
        run_errors, run_limits, result = verify_run(kind, root, selected[kind], doc)
        errors.extend(run_errors)
        limitations.extend(run_limits)
        per_kind[kind] = result.get("status", "unknown") if result else "unknown"
        completed = parse_datetime((result.get("manifest") or {}).get("collectionCompletedUtc")) if result else None
        if completed is not None:
            completion_times.append(completed)
    identities = {
        str(record.get("hostIdentitySha256") or "")
        for record in selected.values() if isinstance(record, dict)
    }
    if len(identities) > 1:
        errors.append("Selected runs come from different Windows hosts")
    target_identity = str((doc.get("target") or {}).get("hostIdentitySha256") or "")
    if identities and target_identity not in identities:
        errors.append("Selected runs do not match the assessment's frozen host identity")
    if len(completion_times) > 1 and max(completion_times) - min(completion_times) > timedelta(hours=24):
        limitations.append("Selected event and posture collections are more than 24 hours apart")
    return errors, limitations, per_kind


def cmd_verify(args: argparse.Namespace) -> int:
    root = Path(args.assessment).resolve()
    assessment_path = root / "assessment.json"
    doc = load_json(assessment_path)
    if not isinstance(doc, dict):
        raise VerifactError("assessment.json must contain a JSON object")
    selected = doc.get("selectedRuns") or {}
    if not isinstance(selected, dict):
        raise VerifactError("assessment.json selectedRuns must contain a JSON object")
    if not selected:
        raise VerifactError("No selected runs are frozen in assessment.json.")
    errors, limitations, per_kind = verify_selected(root, doc)

    if errors:
        print("INTEGRITY VERIFICATION FAILED")
        for item in errors:
            print(f" - {item}")
        return 2

    overall = "degraded" if limitations or any(v != "complete" for v in per_kind.values()) else "complete"
    print("Evidence integrity: PASS")
    print(f"Coverage: {overall.upper()}")
    if limitations:
        for item in sorted(set(limitations)):
            print(f" - {item}")
    return 0


def validate_assessment_shape(root: Path, doc: dict[str, Any], errors: list[str]) -> None:
    if not isinstance(doc, dict):
        errors.append("assessment.json: root must be a JSON object")
        return
    allowed_root = {"schemaVersion", "assessmentId", "createdUtc", "updatedUtc", "status", "target", "scope", "selectedRuns", "coverage"}
    for key in sorted(set(doc) - allowed_root):
        errors.append(f"assessment.json: unknown field {key}")
    require(doc.get("schemaVersion") == "2.0", "assessment.json: schemaVersion must be 2.0", errors)
    require(bool(ASSESSMENT_ID_RE.fullmatch(str(doc.get("assessmentId") or ""))), "assessment.json: invalid assessmentId", errors)
    require(valid_datetime(doc.get("createdUtc")), "assessment.json: createdUtc must be a timezone-aware date-time", errors)
    require(valid_datetime(doc.get("updatedUtc")), "assessment.json: updatedUtc must be a timezone-aware date-time", errors)
    created = parse_datetime(doc.get("createdUtc"))
    updated = parse_datetime(doc.get("updatedUtc"))
    require(created is None or updated is None or updated >= created, "assessment.json: updatedUtc precedes createdUtc", errors)
    require(updated is None or updated <= datetime.now(timezone.utc) + timedelta(minutes=5), "assessment.json: updatedUtc is in the future", errors)
    require(doc.get("status") in ALLOWED_ASSESSMENT_STATUSES, "assessment.json: invalid status", errors)
    raw_target = doc.get("target") or {}
    require(isinstance(raw_target, dict), "assessment.json: target must be an object", errors)
    target = raw_target if isinstance(raw_target, dict) else {}
    for key in sorted(set(target) - {"kind", "label", "hostIdentitySha256"}):
        errors.append(f"assessment.json: target has unknown field {key}")
    require(target.get("kind") == "windows-endpoint", "assessment.json: target.kind must be windows-endpoint", errors)
    require(bool(str(target.get("label") or "").strip()), "assessment.json: target.label is required", errors)
    host_identity = target.get("hostIdentitySha256")
    require(host_identity is None or bool(SHA256_RE.fullmatch(str(host_identity))), "assessment.json: target.hostIdentitySha256 invalid", errors)
    raw_scope = doc.get("scope") or {}
    require(isinstance(raw_scope, dict), "assessment.json: scope must be an object", errors)
    scope = raw_scope if isinstance(raw_scope, dict) else {}
    for key in sorted(set(scope) - {"mode", "domains", "excludedFamilies", "configs"}):
        errors.append(f"assessment.json: scope has unknown field {key}")
    require(scope.get("mode") == "read-only", "assessment.json: scope.mode must be read-only", errors)
    domains = scope.get("domains") or []
    require(isinstance(domains, list) and bool(domains), "assessment.json: scope.domains must be a non-empty array", errors)
    if isinstance(domains, list):
        string_domains = all(isinstance(x, str) for x in domains)
        require(string_domains, "assessment.json: every scope domain must be a string", errors)
        if string_domains:
            require(len(domains) == len(set(domains)), "assessment.json: scope.domains must be unique", errors)
            for domain in sorted(set(domains) - ALLOWED_DOMAINS):
                errors.append(f"assessment.json: unknown scope domain {domain}")
    excluded = scope.get("excludedFamilies") or []
    require(isinstance(excluded, list), "assessment.json: scope.excludedFamilies must be an array", errors)
    require(isinstance(excluded, list) and "Microsoft Defender-specific collection" in excluded, "assessment.json: configured Defender-specific exclusion is missing", errors)
    configs = scope.get("configs") or {}
    require(isinstance(configs, dict), "assessment.json: scope.configs must be an object", errors)
    required_configs = required_run_kinds(doc)
    if "events" in required_configs:
        required_configs |= {"analysis", "eventNormalizer", "eventCollector"}
    if "posture" in required_configs:
        required_configs |= {"postureNormalizer", "postureCollector"}
    if isinstance(configs, dict):
        allowed_configs = {"events", "posture", "analysis", "eventCollector", "postureCollector", "eventNormalizer", "postureNormalizer"}
        for kind in sorted(set(configs) - allowed_configs):
            errors.append(f"assessment.json: unknown frozen config {kind}")
        for kind, record in configs.items():
            require(isinstance(record, dict), f"assessment.json: {kind} config must be an object", errors)
            if not isinstance(record, dict):
                continue
            for key in sorted(set(record) - {"path", "sha256"}):
                errors.append(f"assessment.json: {kind} config has unknown field {key}")
            require(bool(str(record.get("path") or "")), f"assessment.json: {kind} config path is required", errors)
            require(bool(SHA256_RE.fullmatch(str(record.get("sha256") or "").lower())), f"assessment.json: {kind} config SHA-256 invalid", errors)
        for kind in sorted(required_configs):
            record = configs.get(kind)
            require(isinstance(record, dict), f"assessment.json: missing frozen {kind} config", errors)
            if not isinstance(record, dict):
                continue
            relative = str(record.get("path") or "")
            expected_hash = str(record.get("sha256") or "").lower()
            require(bool(SHA256_RE.fullmatch(expected_hash)), f"assessment.json: {kind} config SHA-256 invalid", errors)
            if relative.startswith("skill:"):
                skill_path = SKILL_ROOT / relative[len("skill:"):]
                require(skill_path.is_file(), f"assessment.json: pinned {kind} tool is missing", errors)
                if skill_path.is_file() and SHA256_RE.fullmatch(expected_hash):
                    require(sha256_file(skill_path) == expected_hash, f"assessment.json: pinned {kind} tool hash mismatch", errors)
                continue
            try:
                config_path = bounded_path(root, relative)
                require(config_path.is_file(), f"assessment.json: frozen {kind} config is missing", errors)
                if config_path.is_file() and SHA256_RE.fullmatch(expected_hash):
                    require(sha256_file(config_path) == expected_hash, f"assessment.json: frozen {kind} config hash mismatch", errors)
            except VerifactError as exc:
                errors.append(f"assessment.json: {kind} config {exc}")
    selected_runs = doc.get("selectedRuns") or {}
    require(isinstance(selected_runs, dict), "assessment.json: selectedRuns must be an object", errors)
    for kind, record in selected_runs.items() if isinstance(selected_runs, dict) else []:
        require(kind in {"events", "posture"}, f"assessment.json: unknown selected run kind {kind}", errors)
        if not isinstance(record, dict):
            errors.append(f"assessment.json: {kind} selected run must be an object")
            continue
        for key in sorted(set(record) - {"runId", "manifest", "manifestSha256", "hostIdentitySha256"}):
            errors.append(f"assessment.json: {kind} selected run has unknown field {key}")
        require(bool(str(record.get("runId") or "")), f"assessment.json: {kind}.runId is required", errors)
        require(bool(str(record.get("manifest") or "")), f"assessment.json: {kind}.manifest is required", errors)
        require(bool(SHA256_RE.fullmatch(str(record.get("manifestSha256") or ""))), f"assessment.json: {kind}.manifestSha256 invalid", errors)
        require(bool(SHA256_RE.fullmatch(str(record.get("hostIdentitySha256") or ""))), f"assessment.json: {kind}.hostIdentitySha256 invalid", errors)
    coverage = doc.get("coverage") or {}
    require(isinstance(coverage, dict), "assessment.json: coverage must be an object", errors)
    if isinstance(coverage, dict):
        for key in sorted(set(coverage) - {"status", "limitations", "sources"}):
            errors.append(f"assessment.json: coverage has unknown field {key}")
        require(coverage.get("status") in {"unknown", "complete", "degraded"}, "assessment.json: invalid coverage status", errors)
        limitations = coverage.get("limitations") or []
        require(isinstance(limitations, list) and all(isinstance(x, str) for x in limitations), "assessment.json: coverage.limitations must be a string array", errors)
        sources = coverage.get("sources")
        require(sources is None or isinstance(sources, dict), "assessment.json: coverage.sources must be an object", errors)
        if isinstance(sources, dict):
            for key in sorted(set(sources) - {"events", "posture"}):
                errors.append(f"assessment.json: coverage.sources has unknown field {key}")
            for key, value in sources.items():
                require(value in {"complete", "degraded", "missing", "unknown"}, f"assessment.json: coverage.sources.{key} invalid", errors)


def load_records(directory: Path) -> list[tuple[Path, dict[str, Any]]]:
    if not directory.exists():
        return []
    out = []
    for path in sorted(directory.glob("*.json")):
        out.append((path, load_json(path)))
    return out


def verify_derived_evidence(
    assessment_root: Path,
    assessment: dict[str, Any],
    run_dir: Path,
    run_kind: str,
    relative: str,
    evidence_hash: str,
    manifest_hash: str,
) -> tuple[bool, str]:
    def verify_generator(summary: dict[str, Any]) -> tuple[bool, str]:
        generator = str(summary.get("generator") or "")
        expected = str(summary.get("generatorSha256") or "").lower()
        if not generator or not SHA256_RE.fullmatch(expected):
            return False, "normalization generator provenance is missing"
        try:
            generator_path = bounded_path(run_dir, generator)
        except VerifactError as exc:
            return False, str(exc)
        if not generator_path.is_file() or sha256_file(generator_path) != expected:
            return False, "normalization generator snapshot hash mismatch"
        return True, ""

    if run_kind == "events" and relative.startswith("derived/triage/"):
        summary_path = run_dir / "derived/triage/summary.json"
        if not summary_path.is_file():
            return False, "event normalization summary is missing"
        summary = load_json(summary_path)
        if not isinstance(summary, dict) or summary.get("rawManifestSha256") != manifest_hash:
            return False, "event normalization is not bound to the selected manifest"
        configs = (assessment.get("scope") or {}).get("configs") or {}
        expected_analysis_hash = str((configs.get("analysis") or {}).get("sha256") or "").lower()
        if summary.get("analysisScopeSha256") != expected_analysis_hash:
            return False, "event normalization did not use the assessment's frozen analysis scope"
        generator_ok, generator_error = verify_generator(summary)
        if not generator_ok:
            return False, generator_error
        if summary.get("generatorSha256") != str((configs.get("eventNormalizer") or {}).get("sha256") or "").lower():
            return False, "event normalization generator is not the pinned Verifact normalizer"
        if summary.get("output") != relative or summary.get("outputSha256") != evidence_hash:
            return False, "event derived file is not hash-listed by its normalization summary"
        if summary.get("outputSizeBytes") != (run_dir / relative).stat().st_size:
            return False, "event derived file size does not match its normalization summary"
        return True, ""
    if run_kind == "posture" and relative.startswith("derived/inventory/"):
        summary_path = run_dir / "derived/inventory/summary.json"
        if not summary_path.is_file():
            return False, "posture normalization summary is missing"
        summary = load_json(summary_path)
        if not isinstance(summary, dict) or summary.get("manifestSha256") != manifest_hash:
            return False, "posture normalization is not bound to the selected manifest"
        if int(summary.get("rowsOmittedByBound") or 0) > 0 or int(summary.get("fieldValuesTruncated") or 0) > 0:
            return False, "posture normalization omitted or truncated evidence; cite the raw artifact instead"
        if summary.get("normalizationLimitations"):
            return False, "posture normalization reports limitations; cite the raw artifact instead"
        generator_ok, generator_error = verify_generator(summary)
        if not generator_ok:
            return False, generator_error
        configs = (assessment.get("scope") or {}).get("configs") or {}
        if summary.get("generatorSha256") != str((configs.get("postureNormalizer") or {}).get("sha256") or "").lower():
            return False, "posture normalization generator is not the pinned Verifact normalizer"
        outputs = summary.get("outputs") if isinstance(summary.get("outputs"), list) else []
        match = next((item for item in outputs if isinstance(item, dict) and item.get("path") == relative), None)
        if not match or match.get("sha256") != evidence_hash or match.get("sizeBytes") != (run_dir / relative).stat().st_size:
            return False, "posture derived file is not hash-listed by its normalization summary"
        return True, ""
    return False, "derived evidence is outside a recognized Verifact normalization output"


def verify_evidence_lineage(
    root: Path,
    assessment: dict[str, Any],
    source_path: Path,
    run_kind: str,
    evidence_hash: str,
) -> tuple[bool, str]:
    selected = assessment.get("selectedRuns") or {}
    record = selected.get(run_kind) if isinstance(selected, dict) else None
    if not isinstance(record, dict):
        return False, f"no selected {run_kind} run exists"
    manifest_path = bounded_path(root, str(record.get("manifest") or ""))
    run_dir = manifest_path.parent
    try:
        relative = source_path.resolve().relative_to(run_dir.resolve()).as_posix()
    except ValueError:
        return False, f"source is not inside the selected {run_kind} run"
    if relative == "manifest.json":
        return (evidence_hash == str(record.get("manifestSha256") or ""), "selected manifest hash does not match evidence")
    manifest = load_json(manifest_path)
    if not isinstance(manifest, dict):
        return False, "selected manifest is not a JSON object"
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    artifact = next((item for item in artifacts if isinstance(item, dict) and item.get("path") == relative), None)
    if artifact:
        if str(artifact.get("sha256") or "").lower() != evidence_hash:
            return False, "source hash does not match the selected manifest artifact inventory"
        return True, ""
    return verify_derived_evidence(
        root,
        assessment,
        run_dir,
        run_kind,
        relative,
        evidence_hash,
        str(record.get("manifestSha256") or "").lower(),
    )


def validate_evidence_locator(source_path: Path, locator: str) -> tuple[bool, str]:
    suffix = source_path.suffix.lower()
    if suffix == ".evtx":
        return False, "direct EVTX locators are not portable; cite derived/triage/events.jsonl"
    if suffix == ".json":
        if not locator.startswith("json-pointer=/"):
            return False, "JSON locator must be json-pointer=/path"
        try:
            value: Any = load_json(source_path)
            for token in locator[len("json-pointer=/"):].split("/"):
                key = token.replace("~1", "/").replace("~0", "~")
                value = value[int(key)] if isinstance(value, list) else value[key]
            return True, ""
        except (VerifactError, KeyError, IndexError, TypeError, ValueError):
            return False, "JSON Pointer does not resolve in the cited file"
    if suffix == ".jsonl" and source_path.name == "events.jsonl":
        match = re.fullmatch(r"line=([1-9]\d*);channel=([^;]+);recordId=([1-9]\d*)", locator)
        if not match:
            return False, "event JSONL locator must be line=<n>;channel=<name>;recordId=<id>"
        number = int(match.group(1))
        try:
            line = next(
                (value for index, value in enumerate(source_path.open("r", encoding="utf-8-sig"), start=1) if index == number),
                None,
            )
            record = json.loads(line) if line is not None else None
        except (OSError, json.JSONDecodeError):
            return False, "event JSONL locator does not resolve to a valid record"
        if not isinstance(record, dict):
            return False, "event JSONL locator is outside the cited file"
        if str(record.get("channel")) != match.group(2) or str(record.get("recordId")) != match.group(3):
            return False, "event JSONL locator keys do not match the cited record"
        return True, ""
    expected_kind = "row" if suffix == ".csv" else "line"
    match = re.fullmatch(rf"{expected_kind}=([1-9]\d*)", locator)
    if not match:
        return False, f"{suffix or 'text'} locator must be {expected_kind}=<positive integer>"
    number = int(match.group(1))
    try:
        if suffix == ".csv":
            with source_path.open("r", encoding="utf-8-sig", newline="") as fh:
                row_count = max(0, sum(1 for _ in csv.reader(fh)) - 1)
            return (number <= row_count, "row locator is outside the cited CSV data")
        line_count = sum(1 for _ in source_path.open("r", encoding="utf-8-sig", errors="replace"))
    except (OSError, csv.Error):
        return False, "cited file cannot be read for locator validation"
    return (number <= line_count, "locator is outside the cited file")


def validate_finding(root: Path, assessment: dict[str, Any], path: Path, f: dict[str, Any], errors: list[str]) -> None:
    prefix = path.name
    if not isinstance(f, dict):
        errors.append(f"{prefix}: finding root must be a JSON object")
        return
    required = [
        "schemaVersion", "id", "title", "state", "category", "confidence", "claim",
        "conditions", "evidence", "limitations", "analyst", "createdUtc", "updatedUtc",
    ]
    for key in required:
        require(key in f, f"{prefix}: missing required field {key}", errors)
    for key in sorted(set(f) - FINDING_FIELDS):
        errors.append(f"{prefix}: unknown field {key}")
    require(f.get("schemaVersion") == "2.0", f"{prefix}: schemaVersion must be 2.0", errors)
    fid = str(f.get("id") or "")
    require(bool(FINDING_ID_RE.fullmatch(fid)), f"{prefix}: invalid finding ID {fid!r}", errors)
    require(path.stem == fid, f"{prefix}: filename must match finding ID", errors)
    state = f.get("state")
    require(state in ALLOWED_STATES, f"{prefix}: invalid state {state!r}", errors)
    require(isinstance(f.get("title"), str) and len(f.get("title", "").strip()) >= 3, f"{prefix}: title is too short", errors)
    require(isinstance(f.get("category"), str) and bool(f.get("category", "").strip()), f"{prefix}: category is required", errors)
    scoped_domains = set((assessment.get("scope") or {}).get("domains") or [])
    require(f.get("category") in scoped_domains, f"{prefix}: category is outside the declared assessment scope", errors)
    require(f.get("confidence") in ALLOWED_CONFIDENCES, f"{prefix}: invalid confidence", errors)
    require(f.get("severity") is None or f.get("severity") in ALLOWED_SEVERITIES, f"{prefix}: invalid severity", errors)
    require(len(str(f.get("claim") or "").strip()) >= 10, f"{prefix}: claim is too short", errors)
    require(f.get("impact") is None or isinstance(f.get("impact"), str), f"{prefix}: impact must be a string or null", errors)
    require(isinstance(f.get("analyst"), str) and bool(f.get("analyst", "").strip()), f"{prefix}: analyst is required", errors)
    require(valid_datetime(f.get("createdUtc")), f"{prefix}: createdUtc must be a timezone-aware date-time", errors)
    require(valid_datetime(f.get("updatedUtc")), f"{prefix}: updatedUtc must be a timezone-aware date-time", errors)
    finding_created = parse_datetime(f.get("createdUtc"))
    finding_updated = parse_datetime(f.get("updatedUtc"))
    require(finding_created is None or finding_updated is None or finding_updated >= finding_created, f"{prefix}: updatedUtc precedes createdUtc", errors)
    require(finding_updated is None or finding_updated <= datetime.now(timezone.utc) + timedelta(minutes=5), f"{prefix}: updatedUtc is in the future", errors)
    for field in ("limitations", "remediation"):
        value = f.get(field, [])
        require(isinstance(value, list) and all(isinstance(x, str) for x in value), f"{prefix}: {field} must be a string array", errors)

    conditions = f.get("conditions") if isinstance(f.get("conditions"), list) else []
    evidence = f.get("evidence") if isinstance(f.get("evidence"), list) else []
    research = f.get("research") if isinstance(f.get("research"), list) else []
    require(isinstance(f.get("conditions"), list) and bool(conditions), f"{prefix}: at least one claim condition is required", errors)
    require(isinstance(f.get("evidence"), list), f"{prefix}: evidence must be an array", errors)
    require(f.get("research") is None or isinstance(f.get("research"), list), f"{prefix}: research must be an array", errors)
    evidence_ids: set[str] = set()
    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            errors.append(f"{prefix}: evidence[{index}] must be an object")
            continue
        for key in sorted(set(item) - {"id", "source", "runKind", "locator", "supports", "sha256"}):
            errors.append(f"{prefix}: evidence[{index}] has unknown field {key}")
        eid = str(item.get("id") or "")
        require(bool(eid), f"{prefix}: evidence[{index}].id is required", errors)
        require(eid not in evidence_ids, f"{prefix}: duplicate evidence id {eid}", errors)
        evidence_ids.add(eid)
        for key in ["source", "runKind", "locator", "supports"]:
            require(bool(str(item.get(key) or "").strip()), f"{prefix}: evidence[{index}].{key} is required", errors)
        run_kind = str(item.get("runKind") or "")
        require(run_kind in {"events", "posture"}, f"{prefix}: evidence[{index}].runKind invalid", errors)
        evidence_hash = item.get("sha256")
        require(bool(SHA256_RE.fullmatch(str(evidence_hash or "").lower())), f"{prefix}: evidence[{index}].sha256 is required and must be valid", errors)
        source = str(item.get("source") or "")
        if source:
            try:
                source_path = bounded_path(root, source)
                require(source_path.is_file(), f"{prefix}: evidence[{index}] source file is missing: {source}", errors)
                try:
                    source_path.relative_to((root / "evidence").resolve())
                    inside_evidence = True
                except ValueError:
                    inside_evidence = False
                require(inside_evidence, f"{prefix}: evidence[{index}] source must be inside the assessment evidence directory", errors)
                if source_path.is_file() and SHA256_RE.fullmatch(str(evidence_hash or "").lower()):
                    require(sha256_file(source_path) == str(evidence_hash).lower(), f"{prefix}: evidence[{index}] source SHA-256 mismatch: {source}", errors)
                    locator_ok, locator_error = validate_evidence_locator(source_path, str(item.get("locator") or ""))
                    require(locator_ok, f"{prefix}: evidence[{index}] locator invalid: {locator_error}", errors)
                    lineage_ok, lineage_error = verify_evidence_lineage(
                        root, assessment, source_path, run_kind, str(evidence_hash).lower()
                    )
                    require(lineage_ok, f"{prefix}: evidence[{index}] lineage failure: {lineage_error}", errors)
            except VerifactError as exc:
                errors.append(f"{prefix}: evidence[{index}] {exc}")

    research_ids: set[str] = set()
    for index, item in enumerate(research):
        if not isinstance(item, dict):
            errors.append(f"{prefix}: research[{index}] must be an object")
            continue
        for key in sorted(set(item) - {"id", "title", "url", "accessedUtc", "supports"}):
            errors.append(f"{prefix}: research[{index}] has unknown field {key}")
        rid = str(item.get("id") or "")
        require(bool(rid), f"{prefix}: research[{index}].id is required", errors)
        require(rid not in research_ids, f"{prefix}: duplicate research id {rid}", errors)
        research_ids.add(rid)
        require(isinstance(item.get("title"), str) and bool(item.get("title", "").strip()), f"{prefix}: research[{index}].title is required", errors)
        url = item.get("url")
        require(isinstance(url, str) and url.startswith("https://"), f"{prefix}: research[{index}].url must use HTTPS", errors)
        require(valid_datetime(item.get("accessedUtc")), f"{prefix}: research[{index}].accessedUtc must be a timezone-aware date-time", errors)
        require(isinstance(item.get("supports"), str) and len(item.get("supports", "").strip()) >= 3, f"{prefix}: research[{index}].supports is required", errors)

    referenced_evidence: set[str] = set()
    referenced_research: set[str] = set()
    for index, cond in enumerate(conditions):
        if not isinstance(cond, dict):
            errors.append(f"{prefix}: conditions[{index}] must be an object")
            continue
        for key in sorted(set(cond) - {"kind", "statement", "status", "evidenceRefs", "researchRefs"}):
            errors.append(f"{prefix}: conditions[{index}] has unknown field {key}")
        kind = cond.get("kind")
        require(kind in {"host-fact", "external-prerequisite"}, f"{prefix}: conditions[{index}].kind invalid", errors)
        require(isinstance(cond.get("statement"), str) and len(cond.get("statement", "").strip()) >= 3, f"{prefix}: conditions[{index}].statement is required", errors)
        status = cond.get("status")
        require(status in {"established", "missing", "unknown"}, f"{prefix}: conditions[{index}].status invalid", errors)
        evidence_refs = cond.get("evidenceRefs") or []
        research_refs = cond.get("researchRefs") or []
        require(isinstance(evidence_refs, list) and all(isinstance(x, str) for x in evidence_refs), f"{prefix}: conditions[{index}].evidenceRefs must be a string array", errors)
        require(isinstance(research_refs, list) and all(isinstance(x, str) for x in research_refs), f"{prefix}: conditions[{index}].researchRefs must be a string array", errors)
        if status == "established":
            require(bool(evidence_refs or research_refs), f"{prefix}: established condition {index} requires an evidence or research reference", errors)
            if kind == "host-fact":
                require(bool(evidence_refs), f"{prefix}: established host-fact condition {index} requires local evidence", errors)
        for ref in evidence_refs:
            require(ref in evidence_ids, f"{prefix}: condition references unknown evidence id {ref}", errors)
            referenced_evidence.add(ref)
        for ref in research_refs:
            require(ref in research_ids, f"{prefix}: condition references unknown research id {ref}", errors)
            referenced_research.add(ref)
    if state == "validated":
        require(f.get("severity") in ALLOWED_SEVERITIES, f"{prefix}: validated finding requires severity", errors)
        require(bool(evidence), f"{prefix}: validated finding requires concrete evidence", errors)
        require(all(isinstance(x, dict) and bool(x.get("sha256")) for x in evidence), f"{prefix}: every validated evidence source must be hash-bound", errors)
        require(all(isinstance(c, dict) and c.get("status") == "established" for c in conditions), f"{prefix}: all required conditions must be established before validation", errors)
        require(any(isinstance(c, dict) and c.get("kind") == "host-fact" for c in conditions), f"{prefix}: validated finding requires at least one host-fact condition", errors)
        require(evidence_ids <= referenced_evidence, f"{prefix}: every validated evidence item must support a claim condition", errors)
        require(research_ids <= referenced_research, f"{prefix}: every research item must support a claim condition", errors)
    if state in {"rejected", "inconclusive"}:
        require(f.get("severity") is None or f.get("severity") in ALLOWED_SEVERITIES, f"{prefix}: invalid severity", errors)


def validate_review(path: Path, r: dict[str, Any], errors: list[str]) -> None:
    prefix = path.name
    if not isinstance(r, dict):
        errors.append(f"{prefix}: review root must be a JSON object")
        return
    required = ["schemaVersion", "findingId", "decision", "reviewedUtc", "reviewer", "independence", "identityAssurance", "findingSha256", "summary", "objections"]
    for key in required:
        require(key in r, f"{prefix}: missing required field {key}", errors)
    for key in sorted(set(r) - REVIEW_FIELDS):
        errors.append(f"{prefix}: unknown field {key}")
    require(r.get("schemaVersion") == "2.0", f"{prefix}: schemaVersion must be 2.0", errors)
    finding_id = str(r.get("findingId") or "")
    require(bool(FINDING_ID_RE.fullmatch(finding_id)), f"{prefix}: invalid findingId", errors)
    require(path.stem == finding_id, f"{prefix}: filename must match findingId", errors)
    require(r.get("decision") in {"validate", "reject", "inconclusive", "challenge"}, f"{prefix}: invalid decision", errors)
    require(valid_datetime(r.get("reviewedUtc")), f"{prefix}: reviewedUtc must be a timezone-aware date-time", errors)
    reviewed = parse_datetime(r.get("reviewedUtc"))
    require(reviewed is None or reviewed <= datetime.now(timezone.utc) + timedelta(minutes=5), f"{prefix}: reviewedUtc is in the future", errors)
    require(isinstance(r.get("reviewer"), str) and bool(r.get("reviewer", "").strip()), f"{prefix}: reviewer is required", errors)
    require(r.get("independence") in REVIEW_TYPES, f"{prefix}: invalid independence value", errors)
    require(r.get("identityAssurance") == "unverified-self-attestation", f"{prefix}: identityAssurance must disclose unverified-self-attestation", errors)
    require(bool(SHA256_RE.fullmatch(str(r.get("findingSha256") or ""))), f"{prefix}: findingSha256 invalid", errors)
    require(isinstance(r.get("summary"), str) and len(r.get("summary", "").strip()) >= 5, f"{prefix}: summary is too short", errors)
    objections = r.get("objections") if isinstance(r.get("objections"), list) else []
    require(isinstance(r.get("objections"), list), f"{prefix}: objections must be an array", errors)
    for index, obj in enumerate(objections):
        if not isinstance(obj, dict):
            errors.append(f"{prefix}: objections[{index}] must be an object")
            continue
        for key in sorted(set(obj) - {"type", "statement", "material", "resolution"}):
            errors.append(f"{prefix}: objections[{index}] has unknown field {key}")
        require(obj.get("type") in {"missing-prerequisite", "contradiction", "benign-alternative", "severity", "confidence", "remediation", "other"}, f"{prefix}: objections[{index}].type invalid", errors)
        require(isinstance(obj.get("statement"), str) and len(obj.get("statement", "").strip()) >= 3, f"{prefix}: objections[{index}].statement is required", errors)
        require(isinstance(obj.get("material"), bool), f"{prefix}: objections[{index}].material must be boolean", errors)
        require(obj.get("resolution") is None or isinstance(obj.get("resolution"), str), f"{prefix}: objections[{index}].resolution must be a string or null", errors)


def validate_bundle(root: Path) -> tuple[list[str], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    errors: list[str] = []
    assessment = load_json(root / "assessment.json")
    validate_assessment_shape(root, assessment, errors)
    if not isinstance(assessment, dict):
        assessment = {}
    findings_records = load_records(root / "findings")
    reviews_records = load_records(root / "reviews")
    findings: list[dict[str, Any]] = []
    reviews: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    collection_completed: list[datetime] = []
    selected_runs = assessment.get("selectedRuns") or {}
    if isinstance(selected_runs, dict):
        for record in selected_runs.values():
            if not isinstance(record, dict):
                continue
            try:
                selected_manifest = load_json(bounded_path(root, str(record.get("manifest") or "")))
                completed = parse_datetime(selected_manifest.get("collectionCompletedUtc")) if isinstance(selected_manifest, dict) else None
                if completed is not None:
                    collection_completed.append(completed)
            except VerifactError as exc:
                errors.append(f"Selected run: {exc}")
    latest_collection = max(collection_completed) if collection_completed else None
    for path, f in findings_records:
        validate_finding(root, assessment, path, f, errors)
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id") or "")
        require(fid not in seen, f"Duplicate finding ID: {fid}", errors)
        seen.add(fid)
        findings.append(f)
    for path, r in reviews_records:
        validate_review(path, r, errors)
        if not isinstance(r, dict):
            continue
        fid = str(r.get("findingId") or "")
        require(fid not in reviews, f"Multiple canonical reviews for {fid}; keep one review record per finding", errors)
        reviews[fid] = r
    for f in findings:
        fid = f.get("id")
        state = f.get("state")
        review = reviews.get(fid)
        if review:
            finding_path = root / "findings" / f"{fid}.json"
            require(review.get("findingSha256") == sha256_file(finding_path), f"{fid}: review is not bound to the current finding revision", errors)
            reviewed_utc = parse_datetime(review.get("reviewedUtc"))
            finding_updated = parse_datetime(f.get("updatedUtc"))
            require(
                reviewed_utc is not None and finding_updated is not None and reviewed_utc >= finding_updated,
                f"{fid}: review must occur after the reviewed finding revision",
                errors,
            )
        if state in FINAL_REVIEW:
            require(review is not None, f"{fid}: final state {state} requires an independent review record", errors)
            if review:
                finding_updated = parse_datetime(f.get("updatedUtc"))
                require(
                    latest_collection is None or (finding_updated is not None and finding_updated >= latest_collection),
                    f"{fid}: final finding revision predates selected evidence collection",
                    errors,
                )
                expected = FINAL_REVIEW[state]
                require(review.get("decision") == expected, f"{fid}: state {state} requires review decision {expected}", errors)
                require(review.get("independence") in REVIEW_TYPES, f"{fid}: final disposition requires a declared review pass", errors)
                if review.get("independence") in {"independent-agent", "human-reviewer"}:
                    require(str(review.get("reviewer") or "").strip() != str(f.get("analyst") or "").strip(), f"{fid}: declared separate reviewer must differ from the finding analyst", errors)
                if state == "validated":
                    unresolved = [
                        o for o in review.get("objections") or []
                        if isinstance(o, dict) and o.get("material") and not str(o.get("resolution") or "").strip()
                    ]
                    require(not unresolved, f"{fid}: validated finding has unresolved material review objections", errors)
        elif state == "candidate" and fid in reviews:
            require(reviews[fid].get("decision") == "challenge", f"{fid}: candidate review may only remain at decision=challenge", errors)
    for fid in reviews:
        require(fid in seen, f"Review references missing finding: {fid}", errors)
    return errors, findings, reviews


def cmd_validate(args: argparse.Namespace) -> int:
    root = Path(args.assessment).resolve()
    errors, findings, reviews = validate_bundle(root)
    assessment_path = root / "assessment.json"
    assessment = load_json(assessment_path)
    selected = assessment.get("selectedRuns") or {} if isinstance(assessment, dict) else {}
    limitations: list[str] = []
    per_kind: dict[str, str] = {}
    missing_required = sorted(required_run_kinds(assessment) - set(selected)) if isinstance(selected, dict) else []
    if missing_required and not args.draft:
        for kind in missing_required:
            errors.append(f"A required {kind} run must be selected before final validation")
    if not errors and selected:
        verify_errors, limitations, per_kind = verify_selected(root, assessment)
        errors.extend(verify_errors)
    elif not errors and args.draft:
        print("Draft validation only: evidence readiness was not asserted.")
    if errors:
        print("ASSESSMENT VALIDATION FAILED")
        for item in errors:
            print(f" - {item}")
        return 2
    if selected and assessment.get("status") != "published":
        overall = "degraded" if limitations or any(v != "complete" for v in per_kind.values()) else "complete"
        assessment["coverage"] = {"status": overall, "limitations": sorted(set(limitations)), "sources": per_kind}
        if not args.draft:
            assessment["status"] = "reviewed"
        assessment["updatedUtc"] = utc_now()
        write_json(assessment_path, assessment)
        print("Evidence integrity: PASS")
    elif selected:
        print("Evidence integrity: PASS")
    counts = {state: sum(1 for f in findings if f.get("state") == state) for state in ALLOWED_STATES}
    print("Assessment model: PASS")
    print(
        f"Findings: {counts['validated']} validated, {counts['rejected']} rejected, "
        f"{counts['inconclusive']} inconclusive, {counts['candidate']} candidate"
    )
    print(f"Canonical reviews: {len(reviews)}")
    return 0


def severity_rank(value: Any) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, None: 5}.get(value, 6)


def json_for_script(data: Any) -> str:
    # JSON itself is valid JS. Escape closing script tags defensively.
    return (
        json.dumps(data, ensure_ascii=False)
        .replace("</", "<\\/")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def dashboard_script(data: dict[str, Any]) -> str:
    payload = json_for_script(data)
    return f'''const DATA={payload};
const q=s=>document.querySelector(s); const esc=s=>String(s??'').replace(/[&<>\"]/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c]));
const findings=DATA.findings||[]; const validated=findings.filter(f=>f.state==='validated'); const other=findings.filter(f=>f.state==='rejected'||f.state==='inconclusive'); const candidates=findings.filter(f=>f.state==='candidate');
q('#summary').textContent=`${{DATA.assessment.target.label}} · ${{DATA.assessment.scope.mode}} assessment · coverage ${{(DATA.assessment.coverage?.status||'unknown').toUpperCase()}}`;
const metrics=[['Validated',validated.length],['Open candidates',candidates.length],['Inconclusive',findings.filter(f=>f.state==='inconclusive').length],['Coverage',(DATA.assessment.coverage?.status||'unknown').toUpperCase()]];
q('#metrics').innerHTML=metrics.map(([k,v])=>`<div class="card"><div class="k">${{esc(k)}}</div><div class="v">${{esc(v)}}</div></div>`).join('');
const collections=DATA.collections||[]; q('#collections').innerHTML=collections.length?collections.map(c=>`<div class="finding"><div class="id">${{esc(c.kind).toUpperCase()}} · ${{esc(c.runId)}}</div><div class="claim">${{esc(c.startedUtc)}} to ${{esc(c.completedUtc)}}</div><div class="chips"><span class="chip">${{esc(c.status)}}</span><span class="chip">host identity ${{esc(c.hostIdentityStrength)}}</span>${{c.requestedDays?`<span class="chip">${{esc(c.requestedDays)}} day window</span>`:''}}</div></div>`).join(''):'<div class="empty">No collection runs are selected.</div>';
function card(f){{const ev=(f.evidence||[]).map(e=>`<div class="ev"><b>${{esc(e.id)}}</b> · ${{esc(e.source)}}<br>${{esc(e.locator)}}<br>${{esc(e.supports)}}</div>`).join('');const refs=(f.research||[]).map(r=>`<div class="ev"><a href="${{esc(r.url)}}" rel="noreferrer">${{esc(r.title)}}</a><br>${{esc(r.supports)}}</div>`).join('');return `<article class="finding"><div class="finding-head"><div><div class="id">${{esc(f.id)}} · ${{esc(f.state).toUpperCase()}}</div><div class="title">${{esc(f.title)}}</div></div><div class="chips"><span class="chip sev-${{esc(f.severity||'none')}}">${{esc(f.severity||'no severity')}}</span><span class="chip">confidence ${{esc(f.confidence)}}</span><span class="chip">${{esc(f.category)}}</span></div></div><div class="claim">${{esc(f.claim)}}</div>${{ev?`<div class="evidence">${{ev}}</div>`:''}}${{refs?`<div class="evidence">${{refs}}</div>`:''}}</article>`}}
q('#validated').innerHTML=validated.length?validated.sort((a,b)=>(a.severityRank-b.severityRank)||a.id.localeCompare(b.id)).map(card).join(''):'<div class="empty">No validated findings are present in this assessment package.</div>';
q('#other').innerHTML=other.length?other.map(card).join(''):'<div class="empty">No rejected or inconclusive items are present.</div>';
const lim=DATA.assessment.coverage?.limitations||[]; q('#limitations').innerHTML=lim.length?lim.map(x=>`<div class="finding lim">${{esc(x)}}</div>`).join(''):'<div class="empty">No collection limitation is currently recorded.</div>';
q('#footer').textContent=`Assessment ${{DATA.assessment.assessmentId}} · generated ${{DATA.generatedUtc}} · Verifact report output is scoped to the collected evidence.`;
'''


def explorer_html(data: dict[str, Any]) -> str:
    def e(x: Any) -> str:
        return html.escape(str(x if x is not None else ""))
    rows = []
    reviews = data.get("reviews") or {}
    for f in sorted(data.get("findings") or [], key=lambda x: x.get("id", "")):
        cond = "".join(
            f"<li><b>{e(c.get('status'))}</b> {e(c.get('statement'))}<br><small>Evidence: {e(', '.join(c.get('evidenceRefs') or []) or 'none')} · Research: {e(', '.join(c.get('researchRefs') or []) or 'none')}</small></li>"
            for c in f.get("conditions") or []
        )
        ev = "".join(
            f"<li><code>{e(x.get('id'))}</code> {e(x.get('source'))} · {e(x.get('locator'))}<br>{e(x.get('supports'))}</li>"
            for x in f.get("evidence") or []
        )
        research = "".join(
            f"<li><code>{e(x.get('id'))}</code> <a href='{e(x.get('url'))}' rel='noreferrer'>{e(x.get('title'))}</a><br>{e(x.get('supports'))} · accessed {e(x.get('accessedUtc'))}</li>"
            for x in f.get("research") or []
        )
        review = reviews.get(f.get("id")) or {}
        objections = "".join(
            f"<li><b>{e(o.get('type'))}</b> · {'material' if o.get('material') else 'non-material'} · {e(o.get('statement'))}<br><small>Resolution: {e(o.get('resolution') or 'unresolved')}</small></li>"
            for o in review.get("objections") or []
        )
        rows.append(f"""<article><header><code>{e(f.get('id'))}</code><h2>{e(f.get('title'))}</h2><p>{e(f.get('state'))} · {e(f.get('severity') or 'no severity')} · confidence {e(f.get('confidence'))}</p></header><h3>Claim</h3><p>{e(f.get('claim'))}</p><h3>Required conditions</h3><ul>{cond}</ul><h3>Evidence</h3><ul>{ev or '<li>No evidence attached</li>'}</ul><h3>Research</h3><ul>{research or '<li>No external research attached</li>'}</ul><h3>Declared review separation</h3><p><b>{e(review.get('decision') or 'none')}</b> · {e(review.get('independence') or 'not recorded')} · identity assurance: {e(review.get('identityAssurance') or 'not recorded')} · {e(review.get('summary') or '')}</p><ul>{objections}</ul></article>""")
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Verifact Explorer</title><style>body{{max-width:1050px;margin:auto;padding:32px 20px;background:#0b0d10;color:#eef1f4;font:15px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}}a{{color:#e8f05a}}.top{{color:#9da7b3}}article{{margin:24px 0;padding:24px;background:#12161b;border:1px solid #2a323c;border-radius:16px}}code{{color:#e8f05a}}h2{{margin:.25rem 0}}h3{{margin-top:1.4rem;font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:#9da7b3}}li{{margin:.6rem 0}}small{{color:#9da7b3}}</style></head><body><h1>Verifact evidence explorer</h1><p class='top'>{e(data['assessment']['assessmentId'])} · Trace each claim through conditions, evidence locators, and review.</p>{''.join(rows) if rows else '<article>No finding records are present.</article>'}</body></html>"""


def manifest_path_label(root: Path, path: Path) -> str:
    return "skill:" + path.relative_to(SKILL_ROOT).as_posix() if path.is_relative_to(SKILL_ROOT) else relative_inside(root, path)


def canonical_build_inputs(root: Path, assessment: dict[str, Any], findings: list[dict[str, Any]]) -> list[Path]:
    inputs = [root / "assessment.json"] + [p for p, _ in load_records(root / "findings")] + [p for p, _ in load_records(root / "reviews")]
    selected = assessment.get("selectedRuns") or {}
    for record in selected.values() if isinstance(selected, dict) else []:
        if isinstance(record, dict):
            inputs.append(bounded_path(root, str(record.get("manifest") or "")))
    configs = (assessment.get("scope") or {}).get("configs") or {}
    for record in configs.values() if isinstance(configs, dict) else []:
        if not isinstance(record, dict):
            continue
        relative = str(record.get("path") or "")
        inputs.append(SKILL_ROOT / relative[len("skill:"):] if relative.startswith("skill:") else bounded_path(root, relative))
    for finding in findings:
        for item in finding.get("evidence") or []:
            if not isinstance(item, dict) or not item.get("source"):
                continue
            source_path = bounded_path(root, str(item["source"]))
            inputs.append(source_path)
            if "/derived/triage/" in source_path.as_posix() or "/derived/inventory/" in source_path.as_posix():
                inputs.append(source_path.parent / "summary.json")
                inputs.append(source_path.parent / "normalizer.ps1")
    unique: dict[str, Path] = {}
    for path in inputs:
        unique[str(path.resolve())] = path
    return sorted(unique.values(), key=lambda path: manifest_path_label(root, path))


def collection_summaries(root: Path, assessment: dict[str, Any]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    selected = assessment.get("selectedRuns") or {}
    for kind in ("events", "posture"):
        record = selected.get(kind) if isinstance(selected, dict) else None
        if not isinstance(record, dict):
            continue
        manifest = load_json(bounded_path(root, str(record.get("manifest") or "")))
        if not isinstance(manifest, dict):
            continue
        summaries.append({
            "kind": kind,
            "runId": manifest.get("runId"),
            "startedUtc": manifest.get("collectionStartedUtc"),
            "completedUtc": manifest.get("collectionCompletedUtc"),
            "status": manifest.get("status"),
            "hostIdentityStrength": manifest.get("hostIdentityStrength", "unknown"),
            "requestedDays": manifest.get("requestedDays") if kind == "events" else None,
        })
    return summaries


def render_report_outputs(
    root: Path,
    assessment: dict[str, Any],
    findings: list[dict[str, Any]],
    reviews: dict[str, dict[str, Any]],
    generated: str,
) -> dict[str, bytes]:
    enriched = []
    for finding in findings:
        item = dict(finding)
        item["severityRank"] = severity_rank(finding.get("severity"))
        enriched.append(item)
    data = {
        "schemaVersion": "2.0",
        "generatedUtc": generated,
        "verifactVersion": VERIFACT_VERSION,
        "assessment": assessment,
        "collections": collection_summaries(root, assessment),
        "findings": enriched,
        "reviews": reviews,
    }
    template = (SKILL_ROOT / "assets" / "report-template.html").read_text(encoding="utf-8")
    return {
        "report/data.json": json_bytes(data),
        "report/index.html": template.replace("/*__VERIFACT_DATA__*/", dashboard_script(data)).encode("utf-8"),
        "report/explorer.html": explorer_html(data).encode("utf-8"),
    }


def cmd_build(args: argparse.Namespace) -> int:
    root = Path(args.assessment).resolve()
    errors, findings, reviews = validate_bundle(root)
    assessment = load_json(root / "assessment.json")
    if not isinstance(assessment, dict):
        assessment = {}
    selected = assessment.get("selectedRuns") or {}
    if not isinstance(selected, dict):
        selected = {}
    missing_required = sorted(required_run_kinds(assessment) - set(selected))
    for kind in missing_required:
        errors.append(f"A required {kind} run must be selected before report publication")
    if any(f.get("state") == "candidate" for f in findings):
        errors.append("Open candidate findings must be challenged and disposed before final report publication")
    if not errors:
        verify_errors, limitations, per_kind = verify_selected(root, assessment)
        errors.extend(verify_errors)
    else:
        limitations, per_kind = [], {}
    if errors:
        print("REPORT BUILD BLOCKED BY VALIDATION ERRORS")
        for item in errors:
            print(f" - {item}")
        return 2
    coverage = "degraded" if limitations or any(v != "complete" for v in per_kind.values()) else "complete"
    assessment["coverage"] = {"status": coverage, "limitations": sorted(set(limitations)), "sources": per_kind}
    assessment["status"] = "published"
    assessment["updatedUtc"] = utc_now()
    report = root / "report"
    report.mkdir(parents=True, exist_ok=True)
    generated = utc_now()
    write_json(root / "assessment.json", assessment)
    rendered_outputs = render_report_outputs(root, assessment, findings, reviews, generated)
    for relative, payload in rendered_outputs.items():
        path = bounded_path(root, relative)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(payload)
        tmp.replace(path)

    inputs = canonical_build_inputs(root, assessment, findings)
    template_path = SKILL_ROOT / "assets" / "report-template.html"
    manifest = {
        "schemaVersion": "2.0",
        "generatedUtc": generated,
        "assessmentId": assessment.get("assessmentId"),
        "builder": {
            "verifactVersion": VERIFACT_VERSION,
            "toolSha256": sha256_file(Path(__file__)),
            "templateSha256": sha256_file(template_path),
        },
        "inputs": [
            {
                "path": manifest_path_label(root, p),
                "sizeBytes": p.stat().st_size,
                "sha256": sha256_file(p),
            }
            for p in inputs
        ],
        "outputs": [
            {"path": relative, "sizeBytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
            for relative, payload in sorted(rendered_outputs.items())
        ],
    }
    write_json(report / "build-manifest.json", manifest)
    print(f"Built report: {report / 'index.html'}")
    print(f"Built explorer: {report / 'explorer.html'}")
    return 0


def cmd_verify_report(args: argparse.Namespace) -> int:
    root = Path(args.assessment).resolve()
    build_manifest = load_json(root / "report/build-manifest.json")
    if not isinstance(build_manifest, dict):
        raise VerifactError("Report build manifest must be a JSON object")
    errors: list[str] = []
    assessment = load_json(root / "assessment.json")
    bundle_errors, findings, reviews = validate_bundle(root)
    errors.extend(bundle_errors)
    if not isinstance(assessment, dict):
        errors.append("assessment.json must be a JSON object")
        assessment = {}
    else:
        selected_errors, _, _ = verify_selected(root, assessment)
        errors.extend(selected_errors)
    require(build_manifest.get("schemaVersion") == "2.0", "build-manifest.json: schemaVersion must be 2.0", errors)
    require(build_manifest.get("assessmentId") == assessment.get("assessmentId"), "build-manifest.json: assessmentId mismatch", errors)
    require(valid_datetime(build_manifest.get("generatedUtc")), "build-manifest.json: generatedUtc must be a timezone-aware date-time", errors)
    builder = build_manifest.get("builder") if isinstance(build_manifest.get("builder"), dict) else {}
    require(builder.get("verifactVersion") == VERIFACT_VERSION, "build-manifest.json: Verifact builder version mismatch", errors)
    require(builder.get("toolSha256") == sha256_file(Path(__file__)), "build-manifest.json: Verifact builder hash mismatch", errors)
    require(builder.get("templateSha256") == sha256_file(SKILL_ROOT / "assets/report-template.html"), "build-manifest.json: report template hash mismatch", errors)
    expected_inputs = {manifest_path_label(root, path) for path in canonical_build_inputs(root, assessment, findings)}
    expected_outputs = {"report/data.json", "report/index.html", "report/explorer.html"}
    actual_inputs = {str(item.get("path")) for item in build_manifest.get("inputs") or [] if isinstance(item, dict)}
    actual_outputs = {str(item.get("path")) for item in build_manifest.get("outputs") or [] if isinstance(item, dict)}
    require(actual_inputs == expected_inputs, "build-manifest.json: canonical input set is incomplete or unexpected", errors)
    require(actual_outputs == expected_outputs, "build-manifest.json: output set is incomplete or unexpected", errors)
    generated = str(build_manifest.get("generatedUtc") or "")
    rendered_outputs = render_report_outputs(root, assessment, findings, reviews, generated) if valid_datetime(generated) else {}
    for group in ("inputs", "outputs"):
        records = build_manifest.get(group)
        if not isinstance(records, list):
            errors.append(f"build-manifest.json: {group} must be an array")
            continue
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                errors.append(f"build-manifest.json: {group}[{index}] must be an object")
                continue
            try:
                relative = str(record.get("path") or "")
                path = SKILL_ROOT / relative[len("skill:"):] if relative.startswith("skill:") else bounded_path(root, relative)
            except VerifactError as exc:
                errors.append(str(exc))
                continue
            if not path.is_file():
                errors.append(f"{group}: missing {record.get('path')}")
                continue
            if group == "outputs" and relative in rendered_outputs:
                expected_payload = rendered_outputs[relative]
                expected_size = len(expected_payload)
                expected_hash = hashlib.sha256(expected_payload).hexdigest()
                if record.get("sizeBytes") != expected_size or record.get("sha256") != expected_hash:
                    errors.append(f"outputs: build manifest does not describe canonical bytes for {relative}")
                if path.read_bytes() != expected_payload:
                    errors.append(f"outputs: content does not match canonical build for {relative}")
            if path.stat().st_size != record.get("sizeBytes"):
                errors.append(f"{group}: byte length mismatch for {record.get('path')}")
            if sha256_file(path) != record.get("sha256"):
                errors.append(f"{group}: SHA-256 mismatch for {record.get('path')}")
    if errors:
        if not getattr(args, "quiet", False):
            print("REPORT VERIFICATION FAILED")
            for item in errors:
                print(f" - {item}")
        return 2
    if not getattr(args, "quiet", False):
        print("Report provenance: PASS")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    root = Path(args.assessment).resolve()
    doc = load_json(root / "assessment.json")
    if not isinstance(doc, dict):
        raise VerifactError("assessment.json must contain a JSON object")
    findings = [d for _, d in load_records(root / "findings")]
    counts = {state: sum(1 for f in findings if isinstance(f, dict) and f.get("state") == state) for state in ALLOWED_STATES}
    print(f"Assessment: {doc.get('assessmentId')}")
    print(f"Target: {doc.get('target', {}).get('label')}")
    state = str(doc.get("status"))
    if state == "published":
        check_args = argparse.Namespace(assessment=str(root), quiet=True)
        if cmd_verify_report(check_args) != 0:
            state = "published-stale"
    print(f"State: {state}")
    print(f"Coverage: {doc.get('coverage', {}).get('status', 'unknown')}")
    print(f"Selected runs: {', '.join((doc.get('selectedRuns') or {}).keys()) or 'none'}")
    print(f"Findings: {counts['validated']} validated / {counts['rejected']} rejected / {counts['inconclusive']} inconclusive / {counts['candidate']} candidate")
    for limitation in doc.get("coverage", {}).get("limitations") or []:
        print(f"Limitation: {limitation}")
    return 0


def cmd_package(args: argparse.Namespace) -> int:
    skill_root = SKILL_ROOT
    output = Path(args.output).resolve()
    try:
        output.relative_to(skill_root)
    except ValueError:
        pass
    else:
        raise VerifactError("Package output must be outside the skill directory")

    allowed_roots = {"agents", "assets", "config", "references", "schemas", "scripts"}
    files = [skill_root / "SKILL.md", skill_root / "LICENSE"]
    for directory in sorted(allowed_roots):
        root = skill_root / directory
        if root.exists():
            files.extend(path for path in root.rglob("*") if path.is_file())

    clean_files: list[Path] = []
    for path in sorted(set(files)):
        relative = path.relative_to(skill_root)
        if path.is_symlink():
            raise VerifactError(f"Refusing to package symlink: {relative}")
        if any(part.startswith(".") or part == "__pycache__" for part in relative.parts):
            continue
        if path.suffix in {".pyc", ".pyo"}:
            continue
        clean_files.append(path)

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in clean_files:
            arc = (Path("verifact") / path.relative_to(skill_root)).as_posix()
            info = zipfile.ZipInfo(arc, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            mode = 0o755 if "scripts" in path.relative_to(skill_root).parts else 0o644
            info.external_attr = (mode & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    print(f"Packaged skill: {output} ({output.stat().st_size} bytes)")
    return 0


def cmd_hash_file(args: argparse.Namespace) -> int:
    path = Path(args.path).resolve()
    if not path.is_file():
        raise VerifactError(f"File not found: {path}")
    print(sha256_file(path))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="verifact", description="Deterministic toolkit for the Verifact agent skill")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="Create a canonical assessment package")
    p.add_argument("assessment")
    p.add_argument("--target", required=True, help="Human-readable Windows endpoint label")
    p.add_argument("--domain", dest="domains", action="append", choices=sorted(ALLOWED_DOMAINS), help="Limit assessment domains; repeatable")
    p.add_argument("--event-days", type=int, choices=range(1, 3651), default=120, metavar="DAYS", help="Frozen event lookback window (default: 120)")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("select", help="Freeze selected evidence runs by manifest hash")
    p.add_argument("assessment")
    p.add_argument("--events-run")
    p.add_argument("--posture-run")
    p.set_defaults(func=cmd_select)

    p = sub.add_parser("verify", help="Verify selected manifests and evidence artifacts")
    p.add_argument("assessment")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("validate", help="Validate assessment, finding, and review contracts")
    p.add_argument("assessment")
    p.add_argument("--draft", action="store_true", help="Check draft structure without requiring all scoped evidence runs")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("status", help="Print compact assessment status")
    p.add_argument("assessment")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("build", help="Build generic static dashboard and explorer")
    p.add_argument("assessment")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("verify-report", help="Verify all report build-manifest inputs and outputs")
    p.add_argument("assessment")
    p.set_defaults(func=cmd_verify_report)

    p = sub.add_parser("package", help="Zip the self-contained Verifact skill")
    p.add_argument("--output", required=True)
    p.set_defaults(func=cmd_package)

    p = sub.add_parser("hash-file", help="Print the SHA-256 of a finding or evidence file")
    p.add_argument("path")
    p.set_defaults(func=cmd_hash_file)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        return int(args.func(args))
    except VerifactError as exc:
        print(f"Verifact error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
