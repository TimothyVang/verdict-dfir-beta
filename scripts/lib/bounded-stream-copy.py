#!/usr/bin/env python3
"""Copy stdin to one fresh regular file with a hard byte ceiling."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: bounded-stream-copy.py OUTPUT MAX_BYTES", file=sys.stderr)
        return 2
    output = Path(sys.argv[1])
    try:
        maximum = int(sys.argv[2])
    except ValueError:
        print("bounded-stream-copy: MAX_BYTES must be an integer", file=sys.stderr)
        return 2
    if maximum < 1:
        print("bounded-stream-copy: MAX_BYTES must be positive", file=sys.stderr)
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(output, flags, 0o600)
    except OSError as exc:
        print(f"bounded-stream-copy: cannot create output: {exc}", file=sys.stderr)
        return 1
    total = 0
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as destination:
            metadata = os.fstat(destination.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OSError("output is not one unlinked regular file")
            while True:
                chunk = sys.stdin.buffer.read(64 * 1024)
                if not chunk:
                    break
                if total + len(chunk) > maximum:
                    raise OSError(f"input exceeded {maximum} bytes")
                destination.write(chunk)
                total += len(chunk)
            destination.flush()
            os.fsync(destination.fileno())
    except OSError as exc:
        output.unlink(missing_ok=True)
        print(f"bounded-stream-copy: {exc}", file=sys.stderr)
        return 1
    if total == 0:
        output.unlink(missing_ok=True)
        print("bounded-stream-copy: input was empty", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
