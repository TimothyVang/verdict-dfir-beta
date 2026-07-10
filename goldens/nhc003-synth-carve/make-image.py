#!/usr/bin/env python3
"""Write a tiny synthetic raw image with a planted intrusion-plan email.

Not SCHARDT content. Proves free-space / whole-image email feature recovery for
the nhc-003 *mechanism* without inventing a NIST true positive.

Usage:
  python3 goldens/nhc003-synth-carve/make-image.py [output.dd]
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "fixtures" / "nhc003-synth-carve.dd"

# Planted RFC822-ish bytes for bulk_extractor email scanner + term matching.
PLANTED_EMAIL = (
    b"From: planner@example.com\r\n"
    b"To: operator@example.com\r\n"
    b"Subject: Recovered deleted email discussing the intrusion plan\r\n"
    b"Message-ID: <nhc003-synth-001@example.com>\r\n"
    b"\r\n"
    b"This synthetic free-space message discusses the intrusion plan in detail.\r\n"
    b"Outlook free space carve fixture for VERDICT nhc-003 mechanism tests only.\r\n"
)

MARKER = b"VERDICT_NHC003_SYNTH_v1"
IMAGE_SIZE = 256 * 1024
EMAIL_OFFSET = 80_000
MARKER_OFFSET = 100_000


def write_image(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    buf = bytearray(IMAGE_SIZE)
    buf[EMAIL_OFFSET : EMAIL_OFFSET + len(PLANTED_EMAIL)] = PLANTED_EMAIL
    buf[MARKER_OFFSET : MARKER_OFFSET + len(MARKER)] = MARKER
    path.write_bytes(bytes(buf))
    return path


def main(argv: list[str]) -> int:
    out = Path(argv[1]).expanduser() if len(argv) > 1 else DEFAULT_OUT
    if not out.is_absolute():
        out = (Path.cwd() / out).resolve()
    write_image(out)
    print(f"wrote {out} ({IMAGE_SIZE} bytes)")
    print(f"  planted email offset={EMAIL_OFFSET}")
    print(f"  planted marker offset={MARKER_OFFSET} ({MARKER.decode()})")
    print("  note: synthetic mechanism fixture — not SCHARDT / not a NIST TP")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
