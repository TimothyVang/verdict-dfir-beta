from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


def test_file_like_tokens_are_paths_not_domains() -> None:
    indicators = fea.build_indicators(
        [],
        [
            {
                "description": (
                    "Recovered ntds.dit, deleted stage.rar, and reviewed "
                    "collect_helper.ps1. Contact response.example for escalation."
                )
            }
        ],
        None,
    )

    assert {"ntds.dit", "stage.rar", "collect_helper.ps1"} <= set(indicators["file_paths"])
    assert indicators["domains"] == ["response.example"]


def test_windows_path_extraction_stops_before_prose() -> None:
    extracted = fea._extract_iocs_from_texts(
        [
            "Recovered C:\\temp\\ifm\\Active Directory\\ntds.dit; deleted archive "
            "C:\\temp\\stage.rar and reviewed C:\\temp\\collect_helper.ps1."
        ]
    )

    assert extracted["paths"] == [
        "C:\\temp\\collect_helper.ps1",
        "C:\\temp\\ifm\\Active Directory\\ntds.dit",
        "C:\\temp\\stage.rar",
    ]


def test_finding_registry_and_hash_iocs_reach_indicator_channels() -> None:
    digest = "a" * 64
    indicators = fea.build_indicators(
        [],
        [
            {
                "description": (
                    "Observed HKLM\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp; "
                    f"SHA-256 {digest}"
                )
            }
        ],
        {"aggregate_iocs": {"hashes": [digest]}},
    )

    assert indicators["registry_values"] == [
        r"HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp"
    ]
    assert indicators["hashes"] == [digest]


def test_registry_indicator_drops_trailing_prose() -> None:
    indicators = fea.build_indicators(
        [],
        [
            {
                "description": (
                    r"Observed HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run "
                    "was observed during triage."
                )
            }
        ],
        None,
    )

    assert indicators["registry_values"] == [r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"]


def test_system_hive_relative_path_becomes_registry_value() -> None:
    indicators = fea.build_indicators(
        [],
        [
            {
                "artifact_path": "SYSTEM",
                "description": (
                    "Configuration present at "
                    "ControlSet001\\Services\\PortProxy\\v4tov4\\tcp, last_write recorded."
                ),
            }
        ],
        None,
    )

    assert indicators["registry_values"] == [
        r"HKLM\SYSTEM\ControlSet001\Services\PortProxy\v4tov4\tcp"
    ]


def test_generic_file_paths_survive_indicator_extraction() -> None:
    extracted = fea._extract_iocs_from_texts(
        [
            r"Opened C:\temp\bundle.zip, \\server\share\payload.custom, "
            r"/var/lib/cases/artifact and C:\Windows\System32\drivers."
        ]
    )
    paths = set(extracted["paths"])
    assert r"C:\temp\bundle.zip" in paths
    assert r"\\server\share\payload.custom" in paths
    assert "/var/lib/cases/artifact" in paths
    assert r"C:\Windows\System32\drivers" in paths
    assert r"C:\Program Files\Acme Tool\payload.custom" in set(
        fea._extract_iocs_from_texts(
            [r"Opened C:\Program Files\Acme Tool\payload.custom; review complete."]
        )["paths"]
    )
    assert r"\\server\share\Acme Tool\payload.custom" in set(
        fea._extract_iocs_from_texts(
            [r"Opened \\server\share\Acme Tool\payload.custom; review complete."]
        )["paths"]
    )


def test_finding_prose_does_not_blindly_emit_hashes() -> None:
    indicators = fea.build_indicators(
        [],
        [{"description": f"Audit chain output hash {'a' * 64}"}],
        None,
    )
    assert indicators["hashes"] == []


def test_system_hive_registry_value_stops_before_prose() -> None:
    indicators = fea.build_indicators(
        [],
        [
            {
                "artifact_path": "SYSTEM",
                "description": (r"Found ControlSet001\Services\PortProxy\v4tov4\tcp during triage"),
            }
        ],
        None,
    )
    assert indicators["registry_values"] == [
        r"HKLM\SYSTEM\ControlSet001\Services\PortProxy\v4tov4\tcp"
    ]


def test_system_hive_registry_value_preserves_spaces_in_key_segments() -> None:
    indicators = fea.build_indicators(
        [],
        [
            {
                "artifact_path": "SYSTEM",
                "description": (
                    r"Found ControlSet001\Services\Acme Service\Parameters during triage"
                ),
            }
        ],
        None,
    )
    assert indicators["registry_values"] == [
        r"HKLM\SYSTEM\ControlSet001\Services\Acme Service\Parameters"
    ]
