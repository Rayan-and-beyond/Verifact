import hashlib
import importlib.util
import json
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / ".agents" / "skills" / "verifact"
CLI = SKILL / "scripts" / "verifact.py"
HOST_A = "a" * 64
HOST_B = "b" * 64


def run(*args, check=False):
    cp = subprocess.run([sys.executable, str(CLI), *map(str, args)], text=True, capture_output=True)
    if check and cp.returncode != 0:
        raise AssertionError(f"command failed: {cp.args}\nstdout={cp.stdout}\nstderr={cp.stderr}")
    return cp


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def init_assessment(tmp_path, *extra):
    assessment = tmp_path / "assessment"
    cp = run("init", assessment, "--target", "TEST-WIN11", *extra, check=True)
    assert "Initialized" in cp.stdout
    return assessment


def make_event_run(assessment, *, host=HOST_A, core_missing=False):
    run_dir = assessment / "evidence/events/runs/EVENTS_TEST"
    scope_source = assessment / "config/event-scope.json"
    scope = read(scope_source)
    metadata = run_dir / "metadata"
    metadata.mkdir(parents=True, exist_ok=True)
    scope_snapshot = metadata / "event-scope.json"
    scope_snapshot.write_bytes(scope_source.read_bytes())
    collector = metadata / "collector.ps1"
    collector.write_bytes((SKILL / "scripts/windows/Collect-VerifactEvidence.ps1").read_bytes())
    inventory = metadata / "channel-inventory.json"
    inventory.write_text("[]\n", encoding="utf-8")
    artifacts = [
        {"id": "event-scope", "path": "metadata/event-scope.json", "sizeBytes": scope_snapshot.stat().st_size, "sha256": sha(scope_snapshot)},
        {"id": "collector", "path": "metadata/collector.ps1", "sizeBytes": collector.stat().st_size, "sha256": sha(collector)},
        {"id": "channel-inventory", "path": "metadata/channel-inventory.json", "sizeBytes": inventory.stat().st_size, "sha256": sha(inventory)},
    ]
    channels = []
    for item in scope["channels"]:
        channel = {
            "name": item["name"],
            "tier": item["tier"],
            "discoveryStatus": "empty",
            "exportStatus": "not-exported",
        }
        if item["name"] == "Security" and not core_missing:
            raw = run_dir / "raw/event-logs/Security.evtx"
            raw.parent.mkdir(parents=True, exist_ok=True)
            raw.write_bytes(b"EVTX-fixture")
            channel.update({
                "discoveryStatus": "present", "exportStatus": "exported",
                "exportPath": "raw/event-logs/Security.evtx",
                "exportSizeBytes": raw.stat().st_size, "sha256": sha(raw),
            })
            artifacts.append({
                "path": "raw/event-logs/Security.evtx", "sizeBytes": raw.stat().st_size,
                "sha256": sha(raw), "channel": "Security", "tier": "core",
            })
        elif item["name"] == "Security" and core_missing:
            channel.update({"discoveryStatus": "missing-or-inaccessible", "error": "access denied"})
        channels.append(channel)
    now = datetime.now(timezone.utc) + timedelta(seconds=1)
    write(run_dir / "manifest.json", {
        "schemaVersion": "2.0", "runId": "EVENTS_TEST",
        "status": "completed-degraded" if core_missing else "completed",
        "assessmentDomain": "event-evidence", "mode": "full-export",
        "readOnlyCollection": True, "currentHostOnly": True, "defenderSpecificCollectionExcluded": True,
        "assessmentId": read(assessment / "assessment.json")["assessmentId"],
        "hostIdentitySha256": host, "hostIdentityStrength": "strong",
        "requestedDays": scope["defaultWindowDays"],
        "collectionStartedUtc": now.isoformat().replace("+00:00", "Z"),
        "collectionCompletedUtc": (now + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "scopeConfigSnapshot": "metadata/event-scope.json",
        "collectionPlanSha256": sha(scope_snapshot),
        "collectorSnapshot": "metadata/collector.ps1", "collectorSha256": sha(collector),
        "channels": channels, "artifacts": artifacts,
    })
    return run_dir


def make_posture_run(assessment, *, host=HOST_A):
    run_dir = assessment / "evidence/posture/runs/POSTURE_TEST"
    scope_source = assessment / "config/posture-scope.json"
    scope = read(scope_source)
    metadata = run_dir / "metadata"
    metadata.mkdir(parents=True, exist_ok=True)
    scope_snapshot = metadata / "posture-scope.json"
    scope_snapshot.write_bytes(scope_source.read_bytes())
    collector = metadata / "collector.ps1"
    collector.write_bytes((SKILL / "scripts/windows/Collect-VerifactPosture.ps1").read_bytes())
    artifacts = [{
        "id": "metadata-posture-scope", "category": "metadata", "status": "collected",
        "path": "metadata/posture-scope.json", "sizeBytes": scope_snapshot.stat().st_size,
        "sha256": sha(scope_snapshot),
    }, {
        "id": "metadata-collector", "category": "metadata", "status": "collected",
        "path": "metadata/collector.ps1", "sizeBytes": collector.stat().st_size,
        "sha256": sha(collector),
    }]
    for source in scope["sources"]:
        path = run_dir / source["outputPath"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("[]\n", encoding="utf-8")
        artifacts.append({
            "id": source["id"], "category": source["category"], "status": "empty",
            "path": source["outputPath"], "format": source["format"],
            "sizeBytes": path.stat().st_size, "sha256": sha(path),
        })
    now = datetime.now(timezone.utc) + timedelta(seconds=1)
    write(run_dir / "manifest.json", {
        "schemaVersion": "1.0", "runId": "POSTURE_TEST", "status": "completed",
        "assessmentDomain": "host-posture", "mode": "full-snapshot",
        "readOnlyCollection": True, "currentHostOnly": True, "defenderSpecificCollectionExcluded": True,
        "assessmentId": read(assessment / "assessment.json")["assessmentId"],
        "hostIdentitySha256": host, "hostIdentityStrength": "strong",
        "collectionStartedUtc": now.isoformat().replace("+00:00", "Z"),
        "collectionCompletedUtc": (now + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "scopeConfigSnapshot": "metadata/posture-scope.json",
        "collectionPlanSha256": sha(scope_snapshot),
        "collectorSnapshot": "metadata/collector.ps1", "collectorSha256": sha(collector),
        "artifacts": artifacts,
    })
    return run_dir


def valid_finding(source, source_hash, *, fid="VF-2026-101", category="event-activity"):
    now = datetime.now(timezone.utc) + timedelta(minutes=1)
    stamp = now.isoformat().replace("+00:00", "Z")
    return {
        "schemaVersion": "2.0", "id": fid, "title": "Test security condition",
        "state": "validated", "category": category, "severity": "medium", "confidence": "high",
        "claim": "The collected evidence establishes a bounded test security condition.",
        "impact": "Test impact", "analyst": "primary-agent",
        "conditions": [{"kind": "host-fact", "statement": "Required condition exists", "status": "established", "evidenceRefs": ["VA-1"], "researchRefs": []}],
        "evidence": [{"id": "VA-1", "source": source, "runKind": "events", "locator": "json-pointer=/channels/0/discoveryStatus", "supports": "Establishes the required condition.", "sha256": source_hash}],
        "limitations": [], "remediation": ["Correct the test condition."],
        "createdUtc": stamp, "updatedUtc": stamp,
    }


def write_review(assessment, finding, *, decision="validate", reviewer="independent-agent-pass", independence="independent-agent"):
    finding_path = assessment / "findings" / f"{finding['id']}.json"
    reviewed = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    review = {
        "schemaVersion": "2.0", "findingId": finding["id"], "decision": decision,
        "reviewedUtc": reviewed, "reviewer": reviewer, "independence": independence,
        "identityAssurance": "unverified-self-attestation",
        "findingSha256": sha(finding_path),
        "summary": "The claim survives challenge and remains bounded by the evidence.",
        "objections": [{"type": "benign-alternative", "statement": "A benign explanation was considered.", "material": False, "resolution": "It does not change the bounded claim."}],
    }
    write(assessment / "reviews" / f"{finding['id']}.json", review)
    return review


def prepare_event_assessment(tmp_path, *, finding=True):
    assessment = init_assessment(tmp_path, "--domain", "event-activity")
    run_dir = make_event_run(assessment)
    run("select", assessment, "--events-run", run_dir, check=True)
    if finding:
        source = run_dir / "manifest.json"
        item = valid_finding(source.relative_to(assessment).as_posix(), sha(source))
        write(assessment / "findings" / f"{item['id']}.json", item)
        write_review(assessment, item)
        return assessment, run_dir, item
    return assessment, run_dir, None


def test_skill_shape_and_metadata():
    text = (SKILL / "SKILL.md").read_text()
    assert text.startswith("---\n")
    assert "name: verifact" in text
    assert "Run every Verifact command yourself" in text
    metadata = yaml.safe_load((SKILL / "agents/openai.yaml").read_text())
    assert metadata["interface"]["display_name"] == "Verifact"
    assert "$verifact" in metadata["interface"]["default_prompt"]


def test_all_shipped_json_parses():
    for path in SKILL.rglob("*.json"):
        read(path)


def test_init_freezes_domain_filtered_configs(tmp_path):
    assessment = init_assessment(tmp_path, "--domain", "identity")
    doc = read(assessment / "assessment.json")
    assert set(doc["scope"]["configs"]) == {"posture", "postureCollector", "postureNormalizer"}
    scope = read(assessment / "config/posture-scope.json")
    assert {item["category"] for item in scope["sources"]} == {"identity"}
    assert run("validate", assessment, "--draft").returncode == 0
    assert run("validate", assessment).returncode == 2


def test_malformed_assessment_returns_validation_error(tmp_path):
    assessment = tmp_path / "assessment"
    (assessment / "findings").mkdir(parents=True)
    (assessment / "reviews").mkdir()
    write(assessment / "assessment.json", {"schemaVersion": "2.0", "target": ["bad"], "scope": ["bad"]})
    cp = run("validate", assessment)
    assert cp.returncode == 2
    assert "ASSESSMENT VALIDATION FAILED" in cp.stdout


def test_assessment_rejects_fields_forbidden_by_schema(tmp_path):
    assessment = init_assessment(tmp_path, "--domain", "identity")
    doc = read(assessment / "assessment.json")
    doc["unexpectedRootField"] = {"accepted": True}
    write(assessment / "assessment.json", doc)
    cp = run("validate", assessment, "--draft")
    assert cp.returncode == 2
    assert "unknown field unexpectedRootField" in cp.stdout


def test_selected_artifact_and_manifest_tamper_are_detected(tmp_path):
    assessment, run_dir, _ = prepare_event_assessment(tmp_path, finding=False)
    assert run("verify", assessment).returncode == 0
    artifact = run_dir / "raw/event-logs/Security.evtx"
    artifact.write_bytes(b"tampered")
    assert "SHA-256 mismatch" in run("verify", assessment).stdout
    artifact.write_bytes(b"EVTX-fixture")
    manifest = read(run_dir / "manifest.json")
    manifest["status"] = "changed-after-selection"
    write(run_dir / "manifest.json", manifest)
    assert "selected manifest hash mismatch" in run("verify", assessment).stdout


def test_manifest_artifact_size_is_mandatory(tmp_path):
    assessment = init_assessment(tmp_path, "--domain", "event-activity")
    run_dir = make_event_run(assessment)
    manifest = read(run_dir / "manifest.json")
    manifest["artifacts"][0].pop("sizeBytes")
    write(run_dir / "manifest.json", manifest)
    cp = run("select", assessment, "--events-run", run_dir)
    assert cp.returncode == 2
    assert "sizeBytes is missing or malformed" in cp.stderr


def test_different_hosts_cannot_be_selected(tmp_path):
    assessment = init_assessment(tmp_path)
    events = make_event_run(assessment, host=HOST_A)
    posture = make_posture_run(assessment, host=HOST_B)
    cp = run("select", assessment, "--events-run", events, "--posture-run", posture)
    assert cp.returncode == 2
    assert "same Windows host" in cp.stderr


def test_frozen_scope_tamper_and_manifest_scope_mismatch_are_detected(tmp_path):
    assessment, run_dir, _ = prepare_event_assessment(tmp_path, finding=False)
    scope = assessment / "config/event-scope.json"
    scope.write_text("{}\n", encoding="utf-8")
    assert "config hash mismatch" in run("verify", assessment).stdout
    scope.write_bytes((run_dir / "metadata/event-scope.json").read_bytes())
    doc = read(assessment / "assessment.json")
    doc["scope"]["configs"]["events"]["sha256"] = sha(scope)
    write(assessment / "assessment.json", doc)
    snapshot = run_dir / "metadata/event-scope.json"
    snapshot.write_text("{}\n", encoding="utf-8")
    cp = run("verify", assessment)
    assert cp.returncode == 2
    assert "collection scope" in cp.stdout or "SHA-256 mismatch" in cp.stdout


def test_missing_core_event_telemetry_degrades_coverage(tmp_path):
    assessment = init_assessment(tmp_path, "--domain", "event-activity")
    run_dir = make_event_run(assessment, core_missing=True)
    run("select", assessment, "--events-run", run_dir, check=True)
    cp = run("verify", assessment, check=True)
    assert "Coverage: DEGRADED" in cp.stdout
    run("validate", assessment, check=True)
    doc = read(assessment / "assessment.json")
    assert doc["coverage"]["status"] == "degraded"
    assert any("Security" in item for item in doc["coverage"]["limitations"])


def test_finding_must_be_scoped_and_trace_to_selected_run(tmp_path):
    assessment, _, finding = prepare_event_assessment(tmp_path)
    finding["category"] = "hardening"
    write(assessment / "findings" / f"{finding['id']}.json", finding)
    write_review(assessment, finding)
    assert "outside the declared" in run("validate", assessment).stdout
    finding["category"] = "event-activity"
    loose = assessment / "evidence/loose.txt"
    loose.write_text("not selected\n", encoding="utf-8")
    finding["evidence"][0].update({"source": "evidence/loose.txt", "sha256": sha(loose)})
    write(assessment / "findings" / f"{finding['id']}.json", finding)
    write_review(assessment, finding)
    assert "lineage failure" in run("validate", assessment).stdout


def test_review_is_bound_to_exact_finding_revision(tmp_path):
    assessment, _, finding = prepare_event_assessment(tmp_path)
    assert run("validate", assessment).returncode == 0
    finding["severity"] = "high"
    write(assessment / "findings" / f"{finding['id']}.json", finding)
    cp = run("validate", assessment)
    assert cp.returncode == 2
    assert "not bound to the current finding revision" in cp.stdout


def test_declared_separate_reviewer_must_differ_from_analyst(tmp_path):
    assessment, _, finding = prepare_event_assessment(tmp_path)
    write_review(assessment, finding, reviewer=finding["analyst"])
    cp = run("validate", assessment)
    assert cp.returncode == 2
    assert "declared separate reviewer must differ" in cp.stdout


def test_same_agent_review_fallback_is_disclosed_and_allowed(tmp_path):
    assessment, _, finding = prepare_event_assessment(tmp_path)
    write_review(assessment, finding, reviewer=finding["analyst"], independence="same-agent-separated-pass")
    cp = run("validate", assessment)
    assert cp.returncode == 0


def test_report_build_and_provenance_verification(tmp_path):
    assessment, _, finding = prepare_event_assessment(tmp_path)
    cp = run("build", assessment)
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert finding["id"] in (assessment / "report/index.html").read_text()
    assert run("verify-report", assessment).returncode == 0
    (assessment / "report/index.html").write_text("tampered", encoding="utf-8")
    cp = run("verify-report", assessment)
    assert cp.returncode == 2
    assert "SHA-256 mismatch" in cp.stdout


def test_report_verification_reconstructs_canonical_output(tmp_path):
    assessment, _, _ = prepare_event_assessment(tmp_path)
    assert run("build", assessment).returncode == 0
    report = assessment / "report/index.html"
    report.write_text(report.read_text(encoding="utf-8") + "TAMPERED", encoding="utf-8")
    manifest_path = assessment / "report/build-manifest.json"
    manifest = read(manifest_path)
    output = next(item for item in manifest["outputs"] if item["path"] == "report/index.html")
    output["sizeBytes"] = report.stat().st_size
    output["sha256"] = sha(report)
    write(manifest_path, manifest)
    cp = run("verify-report", assessment)
    assert cp.returncode == 2
    assert "content does not match canonical build" in cp.stdout


def test_final_nonvalidated_evidence_still_requires_integrity(tmp_path):
    assessment, _, finding = prepare_event_assessment(tmp_path)
    finding["state"] = "rejected"
    finding["severity"] = None
    finding["evidence"][0]["locator"] = "line=999999999"
    finding["evidence"][0].pop("sha256")
    write(assessment / "findings" / f"{finding['id']}.json", finding)
    write_review(assessment, finding, decision="reject")
    cp = run("validate", assessment)
    assert cp.returncode == 2
    assert "sha256 is required" in cp.stdout


def test_build_reverifies_selected_artifact(tmp_path):
    assessment, run_dir, _ = prepare_event_assessment(tmp_path)
    (run_dir / "raw/event-logs/Security.evtx").write_bytes(b"tampered")
    cp = run("build", assessment)
    assert cp.returncode == 2
    assert "SHA-256 mismatch" in cp.stdout


def test_empty_core_channels_are_not_collection_failures():
    spec = importlib.util.spec_from_file_location("verifact_cli", CLI)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    scope = read(SKILL / "config/event-scope.json")
    channels = [{"name": item["name"], "tier": item["tier"], "discoveryStatus": "empty", "exportStatus": "not-exported"} for item in scope["channels"]]
    status, limitations = module.event_coverage({"channels": channels}, scope)
    assert status == "complete"
    assert limitations == []


def test_event_jsonl_locator_resolves_exact_record_and_evtx_is_rejected(tmp_path):
    spec = importlib.util.spec_from_file_location("verifact_locator_cli", CLI)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    events = tmp_path / "events.jsonl"
    events.write_text('{"channel":"Security","recordId":42}\n', encoding="utf-8")
    assert module.validate_evidence_locator(events, "line=1;channel=Security;recordId=42") == (True, "")
    ok, error = module.validate_evidence_locator(events, "line=1;channel=Security;recordId=999")
    assert not ok and "do not match" in error
    evtx = tmp_path / "Security.evtx"
    evtx.write_bytes(b"fixture")
    ok, error = module.validate_evidence_locator(evtx, "channel=Security;recordId=42")
    assert not ok and "not portable" in error


def test_powershell_contracts_are_present():
    event = (SKILL / "scripts/windows/Collect-VerifactEvidence.ps1").read_text()
    posture = (SKILL / "scripts/windows/Collect-VerifactPosture.ps1").read_text()
    triage = (SKILL / "scripts/windows/Export-VerifactTriageData.ps1").read_text()
    inventory = (SKILL / "scripts/windows/Export-VerifactPostureInventory.ps1").read_text()
    orchestrator = (SKILL / "scripts/windows/Invoke-VerifactCollection.ps1").read_text()
    assert "hostIdentitySha256" in event and "hostIdentitySha256" in posture
    assert "Event run directory already exists" in event
    assert "-PolicyStore ActiveStore" in posture
    assert "generatorSha256" in triage and "generatorSha256" in inventory
    assert "status -notin @('collected', 'partial', 'empty')" in inventory
    assert "ConvertFrom-Csv" in posture and "machineName      = $values[0]" in posture
    assert "Start-Process" in orchestrator and "-Verb RunAs" in orchestrator
    assert "ready-for-analysis" in orchestrator
    assert "foreach ($candidate in $candidates)" in orchestrator
    assert "currentUserProfileCoverage" in posture and "InvokingUser" in posture


def test_schemas_validate_generated_contracts(tmp_path):
    schema_dir = SKILL / "schemas"
    schemas = {name: read(schema_dir / f"{name}.schema.json") for name in ("assessment", "finding", "review")}
    generated = init_assessment(tmp_path, "--domain", "identity")
    errors = list(Draft202012Validator(schemas["assessment"], format_checker=FormatChecker()).iter_errors(read(generated / "assessment.json")))
    assert errors == []
    assert run("validate", generated, "--draft").returncode == 0

    assessment, _, finding = prepare_event_assessment(tmp_path / "contracts")
    review = read(assessment / "reviews" / f"{finding['id']}.json")
    finding_errors = list(Draft202012Validator(schemas["finding"], format_checker=FormatChecker()).iter_errors(finding))
    review_errors = list(Draft202012Validator(schemas["review"], format_checker=FormatChecker()).iter_errors(review))
    assert finding_errors == []
    assert review_errors == []


def test_impossible_event_state_and_wrong_window_are_rejected(tmp_path):
    assessment = init_assessment(tmp_path, "--domain", "event-activity", "--event-days", "7")
    run_dir = make_event_run(assessment)
    manifest_path = run_dir / "manifest.json"
    manifest = read(manifest_path)
    manifest["requestedDays"] = 8
    write(manifest_path, manifest)
    cp = run("select", assessment, "--events-run", run_dir)
    assert cp.returncode == 2 and "collection window" in cp.stderr
    manifest["requestedDays"] = 7
    manifest["channels"][0]["discoveryStatus"] = "empty"
    manifest["channels"][0]["exportStatus"] = "exported"
    write(manifest_path, manifest)
    cp = run("select", assessment, "--events-run", run_dir)
    assert cp.returncode == 2 and "impossible" in cp.stderr


def test_invalid_locator_and_open_candidate_block_publication(tmp_path):
    assessment, _, finding = prepare_event_assessment(tmp_path)
    finding["evidence"][0]["locator"] = "x"
    write(assessment / "findings" / f"{finding['id']}.json", finding)
    write_review(assessment, finding)
    cp = run("validate", assessment)
    assert cp.returncode == 2 and "locator invalid" in cp.stdout

    finding["state"] = "candidate"
    finding["severity"] = None
    finding["evidence"][0]["locator"] = "json-pointer=/channels/0/discoveryStatus"
    write(assessment / "findings" / f"{finding['id']}.json", finding)
    (assessment / "reviews" / f"{finding['id']}.json").unlink()
    cp = run("build", assessment)
    assert cp.returncode == 2 and "Open candidate" in cp.stdout


def test_report_manifest_cannot_omit_provenance_and_status_detects_staleness(tmp_path):
    assessment, _, _ = prepare_event_assessment(tmp_path)
    run("build", assessment, check=True)
    manifest_path = assessment / "report/build-manifest.json"
    manifest = read(manifest_path)
    manifest["inputs"] = []
    write(manifest_path, manifest)
    cp = run("verify-report", assessment)
    assert cp.returncode == 2 and "canonical input set" in cp.stdout
    cp = run("status", assessment)
    assert cp.returncode == 0 and "State: published-stale" in cp.stdout


def test_skill_zip_is_reproducible_and_clean(tmp_path):
    first = tmp_path / "one.zip"
    second = tmp_path / "two.zip"
    run("package", "--output", first, check=True)
    run("package", "--output", second, check=True)
    assert sha(first) == sha(second)
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
    assert "verifact/SKILL.md" in names
    assert all(name.startswith("verifact/") for name in names)
    assert not any("__pycache__" in name or name.endswith(".pyc") for name in names)
