from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def _evtx_output(event_id: int, channel: str = "Security") -> dict:
    return {
        "rows": [
            {
                "event_id": event_id,
                "channel": channel,
                "record_id": 42,
                "ts": "2019-03-19T23:35:07Z",
                "data": {},
            }
        ],
        "row_count": 1,
        "records_seen": 1,
        "parse_errors": 0,
    }


def test_recovers_confirmed_1102_from_current_agent_query() -> None:
    findings = fea.recover_agent_high_signal_findings(
        [("tc-agent-1", _evtx_output(1102))],
        existing_findings=[],
        case_id="case-agent",
        artifact_path="/evidence/Security.evtx",
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["tool_call_id"] == "tc-agent-1"
    assert finding["confidence"] == "CONFIRMED"
    assert finding["mitre_technique"] == "T1070.001"
    assert finding["asserted_values"] == [
        {
            "path": "rows[*]",
            "expected": '{"event_id": "1102", "channel": "Security"}',
            "match": "record",
        }
    ]


def test_benign_agent_query_recovers_nothing() -> None:
    assert (
        fea.recover_agent_high_signal_findings(
            [("tc-agent-1", _evtx_output(4624))],
            existing_findings=[],
            case_id="case-agent",
            artifact_path="/evidence/Security.evtx",
        )
        == []
    )


def test_existing_1102_assertion_suppresses_duplicate() -> None:
    existing = [
        {
            "mitre_technique": "T1070.001",
            "asserted_values": [
                {"path": "rows[0].event_id", "expected": "1102", "match": "exact"}
            ],
        }
    ]
    assert (
        fea.recover_agent_high_signal_findings(
            [("tc-agent-1", _evtx_output(1102))],
            existing_findings=existing,
            case_id="case-agent",
            artifact_path="/evidence/Security.evtx",
        )
        == []
    )
