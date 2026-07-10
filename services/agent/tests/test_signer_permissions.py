"""Owner-only trust rules for the persistent Ed25519 custody key."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from findevil_agent.crypto.signer import LocalEd25519Signer

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX ownership/mode contract")


def _sign(key_path: Path) -> None:
    LocalEd25519Signer(key_path=key_path).sign(b"custody payload")


def test_new_key_and_parent_are_owner_only(tmp_path: Path) -> None:
    parent = tmp_path / "keys"
    parent.mkdir(mode=0o775)
    key = parent / "signing.key"

    _sign(key)

    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert key.stat().st_nlink == 1


def test_existing_group_readable_key_is_refused(tmp_path: Path) -> None:
    key = tmp_path / "signing.key"
    _sign(key)
    key.chmod(0o640)

    with pytest.raises(PermissionError, match="mode 0600"):
        _sign(key)


def test_symlinked_key_is_refused(tmp_path: Path) -> None:
    real_key = tmp_path / "real.key"
    _sign(real_key)
    link = tmp_path / "link.key"
    link.symlink_to(real_key)

    with pytest.raises(PermissionError, match="regular file"):
        _sign(link)


def test_hardlinked_key_is_refused(tmp_path: Path) -> None:
    real_key = tmp_path / "real.key"
    _sign(real_key)
    alias = tmp_path / "alias.key"
    os.link(real_key, alias)

    with pytest.raises(PermissionError, match="hard-linked"):
        _sign(alias)
