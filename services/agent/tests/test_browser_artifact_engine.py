"""Deterministic engine projections for tagged browser artifact rows."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_browser_artifact_audit_summary_counts_tagged_rows_deterministically() -> None:
    output = {
        "schema_version": 2,
        "browser_family": "chrome",
        "artifact_kind": "chromium_history",
        "rows_seen": 5,
        "truncated": True,
        "rows": [
            {"record_type": "visit", "url": "https://one.example"},
            {"record_type": "download", "download_id": 7},
            {"record_type": "visit", "url": "https://two.example"},
            # Compatibility with the original visit-only wire shape.
            {"url": "https://legacy.example"},
            {"record_type": "future_browser_record"},
        ],
    }

    summary = fea.browser_artifact_audit_summary(output, "/case/History")

    assert summary == {
        "artifact_path": "/case/History",
        "schema_version": 2,
        "browser_family": "chrome",
        "artifact_kind": "chromium_history",
        "rows_seen": 5,
        "rows_returned": 5,
        "truncated": True,
        "record_type_counts": {
            "download": 1,
            "future_browser_record": 1,
            "visit": 3,
        },
    }


@pytest.mark.parametrize(
    ("row", "expected_ts", "summary_fragment", "metadata_key"),
    [
        (
            {
                "record_type": "visit",
                "url": "https://visit.example/path",
                "last_visit_time_iso": "2026-01-01T00:00:00Z",
                "visit_count": 3,
            },
            "2026-01-01T00:00:00Z",
            "browser visit: https://visit.example/path",
            "visit_count",
        ),
        (
            {
                "record_type": "download",
                "download_id": 41,
                "source_url": "https://download.example/tool.zip",
                "target_path": "C:\\Users\\analyst\\Downloads\\tool.zip",
                "start_time_iso": "2026-01-02T00:00:00Z",
                "total_bytes": 4096,
                "state": 1,
                "danger_type": 0,
                "interrupt_reason": 0,
                "opened": False,
            },
            "2026-01-02T00:00:00Z",
            "browser download: https://download.example/tool.zip",
            "download_id",
        ),
        (
            {
                "record_type": "cookie_metadata",
                "host": ".cookie.example",
                "name": "session",
                "path": "/",
                "last_access_time_iso": "2026-01-03T00:00:00Z",
                "is_secure": True,
                "is_http_only": True,
            },
            "2026-01-03T00:00:00Z",
            "browser cookie metadata: .cookie.example",
            "is_http_only",
        ),
        (
            {
                "record_type": "autofill_metadata",
                "field_name": "email",
                "stored_value_count": 2,
                "use_count": 6,
                "last_used_time_iso": "2026-01-04T00:00:00Z",
            },
            "2026-01-04T00:00:00Z",
            "browser autofill metadata: email",
            "stored_value_count",
        ),
        (
            {
                "record_type": "login_metadata",
                "origin_url": "https://login.example/",
                "signon_realm": "https://login.example/",
                "last_used_time_iso": "2026-01-05T00:00:00Z",
                "times_used": 9,
                "blacklisted_by_user": False,
            },
            "2026-01-05T00:00:00Z",
            "browser login metadata: https://login.example/",
            "times_used",
        ),
    ],
)
def test_browser_timeline_projection_supports_every_tagged_row(
    row: dict, expected_ts: str, summary_fragment: str, metadata_key: str
) -> None:
    event = fea.browser_timeline_projection(row, "/case/browser.sqlite")

    assert event is not None
    assert event["ts"] == expected_ts
    assert event["summary"] == summary_fragment
    assert event["metadata"]["history_path"] == "/case/browser.sqlite"
    assert metadata_key in event["metadata"]


def test_browser_timeline_projection_never_copies_secret_payload_columns() -> None:
    rows = [
        {
            "record_type": "cookie_metadata",
            "host": ".example.test",
            "name": "sid",
            "path": "/",
            "last_access_time_iso": "2026-01-03T00:00:00Z",
            "value": "COOKIE-PLAINTEXT-SENTINEL",
            "encrypted_value": "COOKIE-CIPHERTEXT-SENTINEL",
        },
        {
            "record_type": "autofill_metadata",
            "field_name": "email",
            "last_used_time_iso": "2026-01-04T00:00:00Z",
            "value": "AUTOFILL-SECRET-SENTINEL",
        },
        {
            "record_type": "login_metadata",
            "origin_url": "https://example.test",
            "signon_realm": "https://example.test",
            "last_used_time_iso": "2026-01-05T00:00:00Z",
            "password_value": "PASSWORD-BLOB-SENTINEL",
            "form_data": "FORM-DATA-SENTINEL",
            "notes": "PASSWORD-NOTE-SENTINEL",
        },
    ]

    rendered = json.dumps(
        [fea.browser_timeline_projection(row, "/case/db") for row in rows],
        sort_keys=True,
    )

    for sentinel in (
        "COOKIE-PLAINTEXT-SENTINEL",
        "COOKIE-CIPHERTEXT-SENTINEL",
        "AUTOFILL-SECRET-SENTINEL",
        "PASSWORD-BLOB-SENTINEL",
        "FORM-DATA-SENTINEL",
        "PASSWORD-NOTE-SENTINEL",
    ):
        assert sentinel not in rendered


def test_cookie_scope_path_is_not_mislabeled_as_an_evidence_path() -> None:
    event = fea.browser_timeline_projection(
        {
            "record_type": "cookie_metadata",
            "host": ".example.test",
            "name": "sid",
            "path": "/account",
            "last_access_time_iso": "2026-01-03T00:00:00Z",
        },
        "/case/Cookies",
    )

    assert event is not None
    assert event["metadata"]["cookie_path"] == "/account"
    assert "path" not in event["metadata"]
    normalized = fea.build_normalized_timeline(
        [
            {
                "ts": event["ts"],
                "source": "browser_history",
                "artifact_class": "browser_history",
                "description": event["summary"],
                "tool_call_id": "tc-cookie",
                "details": event["metadata"],
            }
        ],
        [],
    )
    assert normalized["events"][0]["source_record_ref"].startswith(
        "browser_history:browser_record_id=sha256:"
    )


def test_browser_timeline_projection_ignores_unknown_or_untimed_rows() -> None:
    assert (
        fea.browser_timeline_projection(
            {"record_type": "unknown", "last_used_time_iso": "2026-01-01T00:00:00Z"},
            "/case/db",
        )
        is None
    )
    assert (
        fea.browser_timeline_projection({"record_type": "download", "download_id": 1}, "/case/db")
        is None
    )


def test_browser_record_ref_is_insertion_stable_and_secret_independent() -> None:
    row = {
        "record_type": "cookie_metadata",
        "host": ".stable.example",
        "name": "session",
        "path": "/account",
        "last_access_time_iso": "2026-01-03T00:00:00Z",
        "value": "FIRST-COOKIE-SECRET",
        "encrypted_value": "FIRST-COOKIE-CIPHERTEXT",
    }
    projected = fea.browser_timeline_projection(row, "/case/Cookies")
    changed_secrets = fea.browser_timeline_projection(
        {
            **row,
            "value": "SECOND-COOKIE-SECRET",
            "encrypted_value": "SECOND-COOKIE-CIPHERTEXT",
        },
        "/case/Cookies",
    )

    assert projected is not None
    assert changed_secrets is not None
    record_id = projected["metadata"]["browser_record_id"]
    assert record_id.startswith("sha256:")
    assert len(record_id.removeprefix("sha256:")) == 64
    assert changed_secrets["metadata"]["browser_record_id"] == record_id
    assert "COOKIE-SECRET" not in json.dumps(projected, sort_keys=True)
    assert "COOKIE-CIPHERTEXT" not in json.dumps(projected, sort_keys=True)

    browser_event = {
        "ts": projected["ts"],
        "source": "browser_history",
        "artifact_class": "browser_history",
        "description": projected["summary"],
        "tool_call_id": "tc-browser",
        "details": projected["metadata"],
    }
    unrelated_event = {
        "ts": "2020-01-01T00:00:00Z",
        "source": "prefetch_parse",
        "artifact_class": "prefetch",
        "description": "unrelated earlier event",
        "tool_call_id": "tc-prefetch",
        "details": {},
    }
    original = fea.build_normalized_timeline([browser_event], [])
    with_insertion = fea.build_normalized_timeline([unrelated_event, browser_event], [])

    original_ref = original["events"][0]["source_record_ref"]
    inserted_ref = next(
        event["source_record_ref"]
        for event in with_insertion["events"]
        if event["tool_call_id"] == "tc-browser"
    )
    assert inserted_ref == original_ref


def test_browser_record_ids_distinguish_public_partition_and_account_metadata() -> None:
    cookie_base = {
        "record_type": "cookie_metadata",
        "host": ".example.test",
        "name": "sid",
        "path": "/",
        "last_access_time_iso": "2026-01-03T00:00:00Z",
        "top_frame_site_key": "https://a.example",
        "source_type": 1,
    }
    cookie_partition = {
        **cookie_base,
        "top_frame_site_key": "https://b.example",
        "source_type": 2,
    }
    login_base = {
        "record_type": "login_metadata",
        "origin_url": "https://portal.example/login",
        "action_url": "https://portal.example/session-a",
        "username": "alpha@example.test",
        "signon_realm": "https://portal.example/",
        "created_time_iso": "2026-01-05T00:00:00Z",
    }
    login_account = {
        **login_base,
        "action_url": "https://portal.example/session-b",
        "username": "beta@example.test",
    }
    login_row_41 = {**login_base, "login_id": 41}
    login_row_42 = {**login_base, "login_id": 42}

    identities = {
        fea.browser_timeline_projection(row, "/case/db")["metadata"]["browser_record_id"]
        for row in (
            cookie_base,
            cookie_partition,
            login_base,
            login_account,
            login_row_41,
            login_row_42,
        )
    }

    assert len(identities) == 6


def test_browser_row_sampling_stratifies_record_types_deterministically() -> None:
    visits = [
        {
            "record_type": "visit",
            "url": f"https://visit-{index}.example",
            "last_visit_time_iso": f"2026-01-01T00:00:{index:02d}Z",
        }
        for index in range(12)
    ]
    download = {
        "record_type": "download",
        "download_id": 99,
        "start_time_iso": "2026-01-02T00:00:00Z",
    }
    rows = [*visits, {"record_type": "unknown"}, download]

    sample = fea.sample_browser_timeline_rows(rows, limit=8)

    assert len(sample) == 8
    assert {fea._browser_record_type(row) for row in sample} == {"visit", "download"}
    assert sample == fea.sample_browser_timeline_rows(rows, limit=8)
    assert sample == fea.sample_browser_timeline_rows(
        [{"record_type": "unrelated_future_type"}, *rows], limit=8
    )


def test_browser_lane_prioritizes_canonical_databases_before_generic_sqlite() -> None:
    canonical_paths = [
        "/profiles/z/Cookies",
        "/profiles/a/History",
        "/profiles/b/Archived History.sqlite",
        "/profiles/a/Login Data",
        "/profiles/a/places.sqlite",
        "/profiles/a/Web Data",
    ]
    generic_paths = [f"/noise/{index:02d}.sqlite" for index in range(20)]
    entries = [
        {"path": path, "artifact_class": "browser_db"}
        for path in [*generic_paths, *canonical_paths]
    ]

    selected, skipped_count = fea.prioritize_browser_entries(entries, limit=20)
    selected_reversed, skipped_reversed = fea.prioritize_browser_entries(
        list(reversed(entries)), limit=20
    )
    selected_paths = [entry["path"] for entry in selected]

    assert skipped_count == 6
    assert skipped_reversed == skipped_count
    assert [entry["path"] for entry in selected_reversed] == selected_paths
    assert selected_paths[:6] == sorted(canonical_paths, key=str.casefold)
    assert set(canonical_paths) <= set(selected_paths)
    assert (
        fea.classify_artifact_path("/profiles/a/Archived History")["artifact_class"] == "browser_db"
    )


def test_case_binding_includes_every_custody_registered_artifact_hash() -> None:
    generic = [
        {
            "path": f"/evidence/noise/{index:02d}.sqlite",
            "artifact_class": "browser_db",
            "sha256": f"{index:064x}",
            "custody_status": "custody_registered",
        }
        for index in range(20)
    ]
    canonical = {
        "path": "profile/History",
        "canonical_path": "/evidence/profile/History",
        "artifact_class": "browser_db",
        "sha256": "a" * 64,
        "custody_status": "custody_registered",
    }
    evtx = {
        "path": "/evidence/Windows/System32/winevt/Logs/Security.evtx",
        "artifact_class": "evtx",
        "sha256": "b" * 64,
        "custody_status": "custody_registered",
    }
    inventory = {
        "parent_case_id": "dir-bound-case",
        "entries": [*generic, canonical, evtx],
    }

    binding = json.loads(fea.browser_case_binding(inventory))

    assert binding["case_id"] == "dir-bound-case"
    assert len(binding["artifacts"]) == 22
    assert {(item["path"], item["sha256"]) for item in binding["artifacts"]} >= {
        ("/evidence/profile/History", "a" * 64),
        ("/evidence/Windows/System32/winevt/Logs/Security.evtx", "b" * 64),
    }
    assert all(len(item["sha256"]) == 64 for item in binding["artifacts"])


def test_case_binding_fails_closed_before_environment_size_exhaustion() -> None:
    inventory = {
        "parent_case_id": "dir-oversize-binding",
        "entries": [
            {
                "path": f"/evidence/{index:03d}-{'x' * 1500}.evtx",
                "artifact_class": "evtx",
                "sha256": f"{index:064x}",
                "custody_status": "custody_registered",
            }
            for index in range(500)
        ],
    }

    with pytest.raises(RuntimeError, match="binding exceeds"):
        fea.browser_case_binding(inventory)


def test_browser_only_inventory_is_complete_without_fake_disk_gap() -> None:
    investigation = fea.Investigation("/case/browser-profile", parallel=False)
    investigation.evidence_inventory = {
        "entries": [
            {
                "path": "/case/browser-profile/History",
                "artifact_class": "browser_db",
                "custody_status": "custody_registered",
            }
        ]
    }
    investigation.tool_calls = [
        {
            "tool": "browser_history",
            "tool_call_id": "tc-browser",
            "rows_seen": 1,
            "rows_returned": 1,
        }
    ]

    completeness = investigation._case_completeness()
    checks = {row["artifact_class"]: row for row in completeness.get("checks", [])}

    assert checks["browser_history"]["available"] is True
    assert checks["browser_history"]["touched"] is True
    assert checks["disk/filesystem"]["available"] is False
    assert checks["disk/filesystem"]["touched"] is False
    reverse_checks = fea.build_coverage_reverse_audits(
        "INDETERMINATE", [], investigation.tool_calls, completeness
    )
    browser_audit = next(
        row for row in reverse_checks if row["check_id"] == "coverage_reverse_uninvoked_tools"
    )
    assert browser_audit["status"] == "PASS"
    assert browser_audit["evidence"] == ["browser_history"]
    report_qa = fea.build_report_qa_signoff(
        findings=[],
        tool_calls=investigation.tool_calls,
        verdict="INDETERMINATE",
        case_completeness=completeness,
        attack_coverage={"blind_spot_count": 0},
        normalized_timeline={"events": []},
        analysis_limitations=[],
    )
    status_by_id = {row["check_id"]: row["status"] for row in report_qa.get("checks", [])}
    assert status_by_id["disk_auto_mode_custody_only"] == "PASS"
    assert status_by_id["coverage_reverse_uninvoked_tools"] == "PASS"
    coverage_manifest = fea.build_coverage_manifest(
        case_id="dir-browser-case",
        evidence_path="/case/browser-profile",
        case_completeness=completeness,
        attack_coverage={"summary": "browser-only fixture", "blind_spot_count": 0},
        tool_calls=investigation.tool_calls,
        evidence_inventory=investigation.evidence_inventory,
        analysis_limitations=[],
    )
    coverage_rows = {
        row["artifact_class"]: row for row in coverage_manifest.get("artifact_classes", [])
    }
    assert coverage_rows["browser_history"]["status"] == "parsed"
    assert coverage_rows["browser_history"]["records_seen"] == 1
    assert coverage_rows["browser_history"]["rows_returned"] == 1
    assert coverage_rows["disk/filesystem"]["status"] == "not_supplied"
    assert coverage_manifest["summary"]["coverage_ratio"] == 1.0
    blocker_text = " ".join(report_qa.get("customer_release_blockers", [])).lower()
    assert "disk evidence was registered for custody only" not in blocker_text
    assert "never examined by an applicable typed tool" not in blocker_text

    next_actions = fea.build_next_actions([], {"targets": []}, completeness, timeline=[])
    assert "memory-only" not in json.dumps(next_actions).lower()

    story = fea.build_executive_attack_story(
        findings=[],
        verdict="INDETERMINATE",
        normalized_timeline={"events": []},
        case_completeness=completeness,
        attack_coverage={"blind_spot_count": 1, "targets": []},
        report_qa={"status": "WARN"},
        next_actions=next_actions,
        analysis_limitations=[],
        evidence_path="/case/browser-profile",
    )
    story_text = json.dumps(story, sort_keys=True).lower()
    assert "triage leads only" not in story_text
    assert "hypothesis-level signals" not in story_text
    assert "read each cited tool call in the findings" not in story_text
    assert "no reportable finding" in story_text


def test_browser_download_lane_counts_as_t1105_coverage() -> None:
    coverage = fea.build_attack_coverage(
        tool_calls=[
            {
                "tool": "browser_history",
                "tool_call_id": "tc-browser",
                "record_type_counts": {"download": 1, "visit": 2},
            }
        ],
        findings=[],
        case_completeness={
            "checks": [
                {
                    "artifact_class": "browser_history",
                    "available": True,
                    "touched": True,
                }
            ]
        },
    )
    t1105 = next(row for row in coverage["targets"] if row["technique_id"] == "T1105")

    assert t1105["status"] == "covered_no_finding"
    assert t1105["tools_observed"] == ["browser_history"]
    assert t1105["artifact_classes_observed"] == ["browser_history"]


def test_browser_metadata_alone_does_not_claim_t1105_coverage() -> None:
    coverage = fea.build_attack_coverage(
        tool_calls=[
            {
                "tool": "browser_history",
                "tool_call_id": "tc-cookies",
                "record_type_counts": {"cookie_metadata": 4},
            }
        ],
        findings=[],
        case_completeness={
            "checks": [
                {
                    "artifact_class": "browser_history",
                    "available": True,
                    "touched": True,
                }
            ]
        },
    )
    t1105 = next(row for row in coverage["targets"] if row["technique_id"] == "T1105")

    assert t1105["status"] == "available_not_examined"
    assert "browser_history" not in t1105["tools_observed"]


def test_browser_binding_is_forwarded_to_local_rust_and_python_launchers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = '{"case_id":"dir-local","artifacts":[]}'
    monkeypatch.setenv(fea.BROWSER_CASE_BINDING_ENV, binding)
    monkeypatch.setenv("FINDEVIL_BROWSER_OUTPUT_MAX_BYTES", "123456")
    monkeypatch.setenv("FINDEVIL_FLS_TIMEOUT_SECONDS", "321")
    monkeypatch.setenv("FINDEVIL_ICAT_TIMEOUT_SECONDS", "123")
    monkeypatch.setenv("FINDEVIL_MMLS_TIMEOUT_SECONDS", "45")
    monkeypatch.setenv("FINDEVIL_SIGSTORE_EXPECTED_IDENTITY", "release@example.test")
    monkeypatch.setenv("FINDEVIL_SIGSTORE_EXPECTED_ISSUER", "https://issuer.example.test")

    assert fea._local_rust_env()[fea.BROWSER_CASE_BINDING_ENV] == binding
    assert fea._local_rust_env()["FINDEVIL_BROWSER_OUTPUT_MAX_BYTES"] == "123456"
    assert fea._local_rust_env()["FINDEVIL_FLS_TIMEOUT_SECONDS"] == "321"
    assert fea._local_rust_env()["FINDEVIL_ICAT_TIMEOUT_SECONDS"] == "123"
    assert fea._local_rust_env()["FINDEVIL_MMLS_TIMEOUT_SECONDS"] == "45"
    assert fea._local_py_env()[fea.BROWSER_CASE_BINDING_ENV] == binding
    assert fea._local_py_env()["FINDEVIL_BROWSER_OUTPUT_MAX_BYTES"] == "123456"
    assert fea._local_py_env()["FINDEVIL_FLS_TIMEOUT_SECONDS"] == "321"
    assert fea._local_py_env()["FINDEVIL_ICAT_TIMEOUT_SECONDS"] == "123"
    assert fea._local_py_env()["FINDEVIL_MMLS_TIMEOUT_SECONDS"] == "45"
    assert fea._local_py_env()["FINDEVIL_SIGSTORE_EXPECTED_IDENTITY"] == "release@example.test"
    assert "FINDEVIL_SIGSTORE_EXPECTED_IDENTITY=release@example.test" in fea._sift_py_launcher()
    assert "FINDEVIL_SIGSTORE_EXPECTED_IDENTITY" not in fea._local_rust_env()


def test_local_mcp_child_env_excludes_provider_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AWS_SECRET_ACCESS_KEY",
        "FINDEVIL_AGENT_API_KEY",
    ):
        monkeypatch.setenv(name, f"secret-{name}")
    monkeypatch.setenv("FINDEVIL_SIGNING_KEY", "/case/signing.key")

    rust_env = fea._local_rust_env()
    python_env = fea._local_py_env()

    assert rust_env["PATH"]
    assert python_env["PATH"]
    assert python_env["FINDEVIL_SIGNING_KEY"] == "/case/signing.key"
    assert all("secret-" not in value for value in rust_env.values())
    assert all("secret-" not in value for value in python_env.values())


def test_browser_resource_overrides_reach_sift_live_and_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fea, "LOCAL_MODE", False)
    monkeypatch.setattr(fea, "DOCKER_MODE", False)
    monkeypatch.setenv("FINDEVIL_BROWSER_FIELD_MAX_BYTES", "262144")

    assert "FINDEVIL_BROWSER_FIELD_MAX_BYTES" in fea._sift_rust_launcher()
    assert "FINDEVIL_BROWSER_FIELD_MAX_BYTES" in fea._sift_py_launcher()


def test_browser_lane_reports_cap_and_uses_stratified_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    entries = [
        {
            "path": f"/noise/{index:02d}.sqlite",
            "artifact_class": "browser_db",
        }
        for index in range(20)
    ]
    entries.extend(
        [
            {"path": "/profiles/default/History", "artifact_class": "browser_db"},
            {"path": "/profiles/default/Cookies", "artifact_class": "browser_db"},
        ]
    )
    rows = [
        {
            "record_type": "visit",
            "url": f"https://visit-{index}.example",
            "last_visit_time_iso": f"2026-01-01T00:00:{index:02d}Z",
        }
        for index in range(12)
    ]
    rows.append(
        {
            "record_type": "download",
            "download_id": 7,
            "source_url": "https://download.example/tool.zip",
            "start_time_iso": "2026-01-02T00:00:00Z",
        }
    )
    investigation = fea.Investigation("/case", parallel=False)
    investigation.handle = {"id": "dir-browser-case"}
    captured_specs: list[tuple[str, dict]] = []
    captured_events: list[dict] = []

    def fake_parallel(
        _rust: object, specs: list[tuple[str, dict]], **_kwargs: object
    ) -> list[dict]:
        captured_specs.extend(specs)
        return [
            {
                "browser_family": "chromium",
                "artifact_kind": "chromium_history",
                "rows_seen": len(rows),
                "truncated": True,
                "rows": rows,
            }
            for _spec in specs
        ]

    monkeypatch.setattr(investigation, "_parallel_tool_calls", fake_parallel)
    monkeypatch.setattr(investigation, "_record_tool", lambda *_args, **_kwargs: "tc-browser")
    monkeypatch.setattr(
        investigation,
        "_timeline_add",
        lambda ts, source, artifact_class, description, tcid, details: captured_events.append(
            {
                "ts": ts,
                "source": source,
                "artifact_class": artifact_class,
                "description": description,
                "tool_call_id": tcid,
                "details": details,
            }
        ),
    )

    investigation.investigate_extracted_disk_artifacts(object(), object(), entries)

    selected_paths = [spec[1]["history_path"] for spec in captured_specs]
    assert len(selected_paths) == 20
    assert selected_paths[:2] == [
        "/profiles/default/Cookies",
        "/profiles/default/History",
    ]
    assert any("skipped 2" in item for item in investigation.analysis_limitations)
    assert any("row limit" in item for item in investigation.analysis_limitations)
    assert {event["details"]["record_type"] for event in captured_events} == {
        "visit",
        "download",
    }


def test_disk_extracted_browser_rows_use_child_disk_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    investigation = fea.Investigation("/case", parallel=False)
    investigation.handle = {"id": "dir-parent"}
    captured_specs: list[tuple[str, dict]] = []

    monkeypatch.setattr(
        investigation,
        "_parallel_tool_calls",
        lambda _rust, specs, **_kwargs: (
            captured_specs.extend(specs)
            or [{"rows": [], "rows_seen": 0, "truncated": False} for _ in specs]
        ),
    )
    monkeypatch.setattr(investigation, "_record_tool", lambda *_args, **_kwargs: "tc")

    investigation.investigate_extracted_disk_artifacts(
        object(),
        object(),
        [{"path": "/case/extracted/History", "artifact_class": "browser_db"}],
        disk_case_id="disk-child-case",
    )

    assert captured_specs[0][1]["case_id"] == "disk-child-case"


def test_zip_extracted_browser_database_is_registered_before_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = {
        "path": "/case/zip/History",
        "artifact_class": "browser_db",
        "sha256": "b" * 64,
        "source_container_type": "velociraptor_zip",
    }
    investigation = fea.Investigation("/case", parallel=False)
    investigation.handle = {"id": "dir-parent"}
    case_open_calls: list[dict] = []
    browser_specs: list[tuple[str, dict]] = []

    class Rust:
        @staticmethod
        def call_tool(name: str, args: dict, **_kwargs: object) -> dict:
            assert name == "case_open"
            case_open_calls.append(args)
            return {
                "id": "zip-browser-child",
                "image_hash": "b" * 64,
                "image_size_bytes": 42,
            }

    monkeypatch.setattr(
        investigation,
        "_parallel_tool_calls",
        lambda _rust, specs, **_kwargs: (
            browser_specs.extend(specs)
            or [{"rows": [], "rows_seen": 0, "truncated": False} for _ in specs]
        ),
    )
    monkeypatch.setattr(investigation, "_record_tool", lambda *_args, **_kwargs: "tc")

    investigation.investigate_extracted_disk_artifacts(
        Rust(), object(), [entry], register_browser_cases=True
    )

    assert case_open_calls == [
        {
            "image_path": "/case/zip/History",
            "expected_sha256": "b" * 64,
            "label": "History",
        }
    ]
    assert browser_specs[0][1]["case_id"] == "zip-browser-child"
