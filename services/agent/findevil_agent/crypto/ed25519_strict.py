"""Strict validation for untrusted Ed25519 keys and signatures.

Some common Ed25519 backends accept the identity-key/identity-R/S=0 equation.
VERDICT bundles carry an untrusted embedded public key, so platform signature
verification must be preceded by canonical decoding, scalar, and subgroup
checks. This module performs those checks without treating the backend as a
public-key validator.
"""

from __future__ import annotations

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1)


def validate_strict_ed25519_inputs(public_key: bytes, signature: bytes) -> str | None:
    """Return ``None`` only for canonical prime-order Ed25519 inputs.

    The platform backend still verifies the signature equation afterwards.
    This function rejects the input classes that permissive backends can
    otherwise accept: non-canonical encodings/scalars, identity and low-order
    points, and points carrying a torsion component.
    """
    if len(public_key) != 32:
        return "public key must be exactly 32 bytes"
    if len(signature) != 64:
        return "signature must be exactly 64 bytes"
    if int.from_bytes(signature[32:], "little") >= _L:
        return "signature scalar S is non-canonical"
    try:
        point_a = _decode_point(public_key)
        point_r = _decode_point(signature[:32])
    except ValueError as exc:
        return str(exc)
    if not _has_prime_order(point_a):
        return "public key is not a non-identity prime-order point"
    if not _has_prime_order(point_r):
        return "signature R is not a non-identity prime-order point"
    return None


def _inverse(value: int) -> int:
    return pow(value, _P - 2, _P)


def _recover_x(y: int) -> int:
    denominator = (_D * y * y + 1) % _P
    if denominator == 0:
        raise ValueError("Ed25519 point has no affine x coordinate")
    xx = (y * y - 1) * _inverse(denominator) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if (x * x - xx) % _P != 0:
        raise ValueError("encoded Ed25519 point is not on the curve")
    if x & 1:
        x = _P - x
    return x


def _decode_point(encoded_point: bytes) -> tuple[int, int]:
    encoded = int.from_bytes(encoded_point, "little")
    sign = encoded >> 255
    y = encoded & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError("non-canonical Ed25519 point encoding")
    x = _recover_x(y)
    if x == 0 and sign:
        raise ValueError("non-canonical Ed25519 x=0 sign encoding")
    if (x & 1) != sign:
        x = _P - x
    point = (x, y)
    if not _on_curve(point) or _encode_point(point) != encoded_point:
        raise ValueError("non-canonical Ed25519 point encoding")
    return point


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _on_curve(point: tuple[int, int]) -> bool:
    x, y = point
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _P == 0


def _add(point_p: tuple[int, int], point_q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = point_p
    x2, y2 = point_q
    product = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + x2 * y1) * _inverse(1 + product) % _P
    y3 = (y1 * y2 + x1 * x2) * _inverse(1 - product) % _P
    return x3, y3


def _scalar_multiply(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _has_prime_order(point: tuple[int, int]) -> bool:
    return point != _IDENTITY and _scalar_multiply(point, _L) == _IDENTITY


__all__ = ["validate_strict_ed25519_inputs"]
