"""setupapi USB install-history candidates (secondary to USBSTOR)."""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

SAMPLE = """
>>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_X&Prod_Y\\SERIAL123]
>>>  Section start 2004/08/26 12:00:00.000
     inf:      Opened PNF: 'C:\\WINDOWS\\inf\\usbstor.inf'
>>>  [Device Install - PCI\\VEN_8086]
>>>  Section start 2004/08/26 12:02:00.000
     inf:      not a usb row
"""


class TestSetupapiUsbCandidates:
    def test_usb_section_is_candidate(self) -> None:
        cands = fea.setupapi_usb_candidates(SAMPLE, source_path="/x/setupapi.dev.log")
        assert len(cands) == 1
        assert cands[0]["kind"] == "setupapi_usb"
        assert "USBSTOR" in cands[0]["device"]
        assert cands[0]["install_time_iso"] == "2004-08-26T12:00:00Z"

    def test_empty_yields_nothing(self) -> None:
        assert fea.setupapi_usb_candidates("") == []

    def test_emitter_makes_hypothesis(self) -> None:
        inv = fea.Investigation("memory.img", unattended=True, with_report=False)
        inv.handle = {"id": "case-setupapi"}
        cand = {
            "kind": "setupapi_usb",
            "device": "USBSTOR\\Disk&Ven_X",
            "install_time_iso": "2004-08-26T12:00:00Z",
            "source_path": "/x/setupapi.dev.log",
        }
        inv._emit_setupapi_usb_findings([cand], "/x/setupapi.dev.log", "tc-1")
        assert len(inv.findings_pool_b) == 1
        f = inv.findings_pool_b[0]
        assert f["confidence"] == "HYPOTHESIS"
        assert f["tool_call_id"] == "tc-1"
        assert "USB" in f["description"] or "usb" in f["description"].lower()


class TestToolTimeoutEnv:
    def test_default_tool_timeout_bounds(self) -> None:
        assert fea._default_tool_timeout() >= 30.0
        assert fea.DEFAULT_TOOL_TIMEOUT >= 30.0
