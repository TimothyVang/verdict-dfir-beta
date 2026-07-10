#!/usr/bin/env python3
"""Encode one Docker ``--mount`` value using Docker's CSV field grammar."""

from __future__ import annotations

import csv
import io
import sys


def encode_mount_fields(fields: list[str]) -> str:
    if not fields:
        raise ValueError("at least one mount field is required")
    if any("\r" in field or "\n" in field for field in fields):
        raise ValueError("Docker mount fields may not contain CR or LF")
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="").writerow(fields)
    return output.getvalue()


def main() -> int:
    try:
        encoded = encode_mount_fields(sys.argv[1:])
    except ValueError as exc:
        print(f"docker-mount-spec: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
