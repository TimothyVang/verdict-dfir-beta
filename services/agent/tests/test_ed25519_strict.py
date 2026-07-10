"""Strict validation before permissive platform Ed25519 verification."""

from __future__ import annotations

import pytest

from findevil_agent.crypto.ed25519_strict import validate_strict_ed25519_inputs

_L = 2**252 + 27742317777372353535851937790883648493
_PUBLIC_KEY = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a"
    "84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46b"
    "d25bf5f0595bbe24655141438e7a100b"
)


def test_accepts_canonical_prime_order_rfc8032_inputs() -> None:
    assert validate_strict_ed25519_inputs(_PUBLIC_KEY, _SIGNATURE) is None


def test_rejects_s_plus_group_order() -> None:
    malleable = bytearray(_SIGNATURE)
    s_value = int.from_bytes(malleable[32:], "little")
    malleable[32:] = (s_value + _L).to_bytes(32, "little")

    assert "scalar" in str(validate_strict_ed25519_inputs(_PUBLIC_KEY, bytes(malleable)))


@pytest.mark.parametrize(
    "public_key,signature",
    [
        (
            b"\x01" + (b"\x00" * 31),
            (b"\x01" + (b"\x00" * 31)) + (b"\x00" * 32),
        ),
        (
            bytes.fromhex("ec" + ("ff" * 30) + "7f"),
            _SIGNATURE,
        ),
        (
            _PUBLIC_KEY,
            bytes.fromhex("ec" + ("ff" * 30) + "7f") + (b"\x00" * 32),
        ),
    ],
)
def test_rejects_identity_and_small_order_points(public_key: bytes, signature: bytes) -> None:
    assert validate_strict_ed25519_inputs(public_key, signature) is not None


@pytest.mark.parametrize(
    "public_key",
    [
        (2**255 - 19).to_bytes(32, "little"),
        b"\x01" + (b"\x00" * 30) + b"\x80",
    ],
)
def test_rejects_noncanonical_public_key_encodings(public_key: bytes) -> None:
    assert "canonical" in str(validate_strict_ed25519_inputs(public_key, _SIGNATURE))
