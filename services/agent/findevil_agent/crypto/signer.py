"""Manifest signer implementations.

The custody stack signs the canonicalized run manifest after the
hash-chained audit log and Merkle root are built. The default signer is
``LocalEd25519Signer``: a real local keypair whose signature verifies
offline from data embedded in ``run.manifest.json``. ``SigstoreSigner`` is
the customer-release identity/transparency tier when an OIDC token and
network access are available. ``StubSigner`` is explicit test/demo fallback
only and never cryptographic proof.

This module is structured so the agent never depends on the sigstore
library at import time — the abstract ``Signer`` protocol keeps tests fast
and fully offline, and Sigstore imports lazily only when requested.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class SignedBundle:
    """The minimal structure all signers produce.

    For Sigstore output, ``raw_bundle_json`` is the verbatim Sigstore Bundle
    JSON serialization. For Ed25519, it is a compact JSON object containing
    the public key and signature. For the stub, it is deterministic placeholder
    JSON that integration tests can assert against.
    """

    payload_sha256: str
    """SHA-256 hex of the exact VERDICT canonical JSON v1 payload bytes."""

    bundle_b64: str
    """Base64-encoded signer bundle JSON, ready for embedding in the
    manifest."""

    cert_fingerprint: str
    """SHA-256 hex of the Sigstore certificate or Ed25519 public key. Stub
    uses a placeholder string."""

    signed_at: str
    """UTC ISO-8601Z."""

    kind: str = "stub"
    """Which signer produced this bundle: ``"ed25519"`` (offline-verifiable
    local signature), ``"sigstore"`` (keyless Fulcio/Rekor proof), or
    ``"stub"`` (deterministic dev/offline placeholder). Recorded in the
    manifest so a verifier can tell a real proof from a placeholder without
    reaching into the bundle."""

    fallback_reason: str | None = None
    """Set when a sigstore attempt failed and the run honestly degraded to
    the stub signer (e.g. no ``$SIGSTORE_ID_TOKEN`` / no Fulcio reachability).
    ``None`` for a clean run. Lets the release gate read the *effective*
    signer instead of the *requested* one."""

    @property
    def raw_bundle_json(self) -> str:
        return base64.b64decode(self.bundle_b64).decode("utf-8")


class Signer(Protocol):
    """Abstract signer the agent depends on. ``sign(payload)`` is
    the only call site downstream code uses.
    """

    def sign(self, payload: bytes) -> SignedBundle: ...


class SigstoreSigner:
    """Production signer — keyless via sigstore-python.

    Lazily imports ``sigstore`` so test environments without
    Fulcio/Rekor reachability don't need the library installed.
    """

    def __init__(
        self,
        *,
        identity_token: str | None = None,
        oidc_issuer: str | None = None,
    ) -> None:
        self._identity_token = identity_token
        self._oidc_issuer = oidc_issuer
        self._lock = threading.Lock()
        self._signing_ctx: Any = None  # lazy-init sigstore SigningContext

    def _ensure_ctx(self) -> Any:
        with self._lock:
            if self._signing_ctx is not None:
                return self._signing_ctx
            try:
                # Lazy import — keeps test env offline-friendly.
                from sigstore.models import (  # type: ignore[import-not-found]
                    ClientTrustConfig,
                )
                from sigstore.sign import SigningContext  # type: ignore[import-not-found]
            except ImportError as exc:
                raise RuntimeError(
                    "sigstore-python is not installed. Install with `uv add sigstore` "
                    "or use StubSigner in tests."
                ) from exc
            trust_config = ClientTrustConfig.production()
            self._signing_ctx = SigningContext.from_trust_config(trust_config)
            return self._signing_ctx

    def sign(self, payload: bytes) -> SignedBundle:
        """Sign ``payload`` (canonical JSON bytes). Returns a SignedBundle."""
        if self._identity_token is None:
            raise RuntimeError(
                "SigstoreSigner requires identity_token in non-interactive mode. "
                "Acquire one via Sigstore's OIDC flow before instantiation."
            )
        ctx = self._ensure_ctx()
        from sigstore.oidc import IdentityToken  # type: ignore[import-not-found]

        identity = IdentityToken(self._identity_token)
        with ctx.signer(identity) as signer_session:
            bundle = signer_session.sign_artifact(payload)

        return SignedBundle(
            payload_sha256=hashlib.sha256(payload).hexdigest(),
            bundle_b64=base64.b64encode(bundle.to_json().encode("utf-8")).decode("ascii"),
            cert_fingerprint=_fingerprint_from_bundle_json(bundle.to_json()),
            signed_at=_utc_iso(),
            kind="sigstore",
        )


class StubSigner:
    """Deterministic offline signer for tests + demos.

    Produces a bundle that's structurally similar to a real Sigstore
    bundle (so downstream parsing code exercises the same shape) but
    contains no real cryptographic signature. ``audit.jsonl`` rows
    written under StubSigner declare ``kind="stub"`` in the manifest
    signature bundle so verifiers refuse to accept them as production proof.
    """

    def __init__(self, *, run_id: str = "stub-run") -> None:
        self._run_id = run_id
        self._counter = 0
        self._lock = threading.Lock()

    def sign(self, payload: bytes) -> SignedBundle:
        with self._lock:
            self._counter += 1
            seq = self._counter
        digest = hashlib.sha256(payload).hexdigest()
        # Deterministic stub: cert_fingerprint derived from run_id +
        # seq so two stub runs produce distinguishable but
        # reproducible "fingerprints".
        cert_fp = hashlib.sha256(f"stub:{self._run_id}:{seq}".encode("ascii")).hexdigest()
        bundle_obj: dict[str, Any] = {
            "kind": "stub",
            "run_id": self._run_id,
            "seq": seq,
            "payload_sha256": digest,
            "cert_fingerprint": cert_fp,
            "note": "StubSigner output — NOT a real Sigstore signature.",
        }
        bundle_json = json.dumps(bundle_obj, sort_keys=True, separators=(",", ":"))
        return SignedBundle(
            payload_sha256=digest,
            bundle_b64=base64.b64encode(bundle_json.encode("utf-8")).decode("ascii"),
            cert_fingerprint=cert_fp,
            signed_at=_utc_iso(),
            kind="stub",
        )


class LocalEd25519Signer:
    """Real local-keypair signer — the offline default tier.

    Signs the canonical payload bytes with an Ed25519 private key kept at a
    stable local path (``~/.findevil/signing.key`` unless overridden via
    ``FINDEVIL_SIGNING_KEY`` or the ``key_path`` argument). The key is
    auto-generated on first use (dir 0o700, file 0o600). The bundle embeds the
    public key, while ``manifest_verify`` requires its SHA-256 fingerprint from
    a trusted source outside that bundle. This provides offline key continuity;
    an embedded key alone would prove only self-consistency.

    This proves *integrity and local key continuity*, not *identity*: the
    customer-release gate still requires sigstore.
    """

    def __init__(self, key_path: os.PathLike[str] | str | None = None) -> None:
        selected = Path(key_path) if key_path is not None else _default_key_path()
        self._key_path = Path(os.path.abspath(selected.expanduser()))
        self._lock = threading.Lock()
        self._private_key: Any = None  # lazy Ed25519PrivateKey

    def _secure_parent(self) -> None:
        parent = self._key_path.parent
        current = Path(parent.anchor)
        for part in parent.parts[1:]:
            current /= part
            try:
                metadata = os.lstat(current)
            except FileNotFoundError:
                os.mkdir(current, 0o700)
                metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode):
                raise PermissionError(f"signing-key path contains a symlink: {current}")
            if not stat.S_ISDIR(metadata.st_mode):
                raise PermissionError(f"signing-key parent component is not a directory: {current}")
        metadata = os.lstat(parent)
        if os.name == "posix" and metadata.st_uid != os.geteuid():
            raise PermissionError("signing-key parent is not owned by the current user")
        os.chmod(parent, 0o700)

    @staticmethod
    def _validate_key_metadata(metadata: os.stat_result) -> None:
        if not stat.S_ISREG(metadata.st_mode):
            raise PermissionError("signing key is not a regular file")
        if metadata.st_nlink != 1:
            raise PermissionError("signing key must not be hard-linked")
        if os.name == "posix" and metadata.st_uid != os.geteuid():
            raise PermissionError("signing key is not owned by the current user")
        if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600:
            raise PermissionError("signing key must have mode 0600")

    def _read_existing_key(self) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        descriptor = os.open(self._key_path, flags)
        with os.fdopen(descriptor, "rb") as key_file:
            self._validate_key_metadata(os.fstat(key_file.fileno()))
            return key_file.read()

    def _ensure_key(self) -> Any:
        with self._lock:
            if self._private_key is not None:
                return self._private_key
            # Lazy import — cryptography ships as a sigstore dependency, but
            # keep module import time free of it for offline-light callers.
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                NoEncryption,
                PrivateFormat,
                load_pem_private_key,
            )

            self._secure_parent()
            try:
                existing = os.lstat(self._key_path)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                self._validate_key_metadata(existing)
                loaded = load_pem_private_key(self._read_existing_key(), password=None)
                if not isinstance(loaded, Ed25519PrivateKey):
                    raise ValueError("signing key is not an Ed25519 private key")
                self._private_key = loaded
            else:
                key = Ed25519PrivateKey.generate()
                pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                if hasattr(os, "O_CLOEXEC"):
                    flags |= os.O_CLOEXEC
                try:
                    descriptor = os.open(self._key_path, flags, 0o600)
                except FileExistsError as exc:
                    raise PermissionError("signing key appeared during exclusive creation") from exc
                with os.fdopen(descriptor, "wb") as fh:
                    if hasattr(os, "fchmod"):
                        os.fchmod(fh.fileno(), 0o600)
                    else:
                        os.chmod(self._key_path, 0o600)
                    fh.write(pem)
                    fh.flush()
                    os.fsync(fh.fileno())
                self._private_key = key
            return self._private_key

    def sign(self, payload: bytes) -> SignedBundle:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        key = self._ensure_key()
        digest = hashlib.sha256(payload).hexdigest()
        signature = key.sign(payload)
        public_raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        cert_fp = hashlib.sha256(public_raw).hexdigest()
        bundle_obj: dict[str, Any] = {
            "kind": "ed25519",
            "public_key_b64": base64.b64encode(public_raw).decode("ascii"),
            "signature_b64": base64.b64encode(signature).decode("ascii"),
            "payload_sha256": digest,
            "cert_fingerprint": cert_fp,
        }
        bundle_json = json.dumps(bundle_obj, sort_keys=True, separators=(",", ":"))
        return SignedBundle(
            payload_sha256=digest,
            bundle_b64=base64.b64encode(bundle_json.encode("utf-8")).decode("ascii"),
            cert_fingerprint=cert_fp,
            signed_at=_utc_iso(),
            kind="ed25519",
        )

    def public_fingerprint(self) -> str:
        """Return the stable public-key SHA-256 pin for trusted verifiers.

        The private key is created on first use using the same owner-only path
        rules as signing. Only this public fingerprint leaves the custody
        process.
        """
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        public_raw = self._ensure_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return hashlib.sha256(public_raw).hexdigest()


def _default_key_path() -> Any:
    env = os.environ.get("FINDEVIL_SIGNING_KEY")
    if env:
        return Path(env)
    return Path.home() / ".findevil" / "signing.key"


class FallbackSigner:
    """Tries a primary signer (real sigstore) and honestly degrades to a
    fallback (stub) when the primary fails — the typical offline / no-token
    case. The returned bundle carries ``kind="stub"`` and a non-empty
    ``fallback_reason`` so the release gate reads the *effective* signer, not
    the *requested* one, and never crashes a run just because Fulcio/Rekor
    (or an OIDC token) was unavailable.
    """

    def __init__(self, primary: Signer, fallback: Signer) -> None:
        self._primary = primary
        self._fallback = fallback

    def sign(self, payload: bytes) -> SignedBundle:
        try:
            return self._primary.sign(payload)
        except Exception as exc:  # degrade on ANY primary-signer failure
            bundle = self._fallback.sign(payload)
            reason = f"primary signer failed, degraded to {bundle.kind}: {exc}"
            if bundle.fallback_reason:  # nested fallback — keep the inner story
                reason = f"{reason} (after: {bundle.fallback_reason})"
            return replace(bundle, fallback_reason=reason)


def _fingerprint_from_bundle_json(bundle_json: str) -> str:
    """Best-effort cert fingerprint extraction from a Sigstore bundle.

    The bundle's verifying certificate lives at
    ``verificationMaterial.x509CertificateChain.certificates[0].rawBytes``
    in Sigstore's JSON wire format. We hash the raw bytes; failure
    falls back to a hash over the whole bundle to keep fingerprints
    populated even on schema drift.
    """
    try:
        obj = json.loads(bundle_json)
        chain = obj["verificationMaterial"]["x509CertificateChain"]["certificates"]
        if chain:
            cert_b64 = chain[0]["rawBytes"]
            return hashlib.sha256(base64.b64decode(cert_b64)).hexdigest()
    except (KeyError, json.JSONDecodeError, ValueError, TypeError):
        pass
    return hashlib.sha256(bundle_json.encode("utf-8")).hexdigest()


def _utc_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_signer(*, kind: str | None = None, **kwargs: Any) -> Signer:
    """Factory the rest of the agent calls.

    ``kind`` defaults to ``$FINDEVIL_SIGNER`` env var, falling back to
    ``"ed25519"`` — a REAL local signature that verifies offline with a
    separately trusted public-key fingerprint — so every
    run is cryptographically signed out of the box. ``"stub"`` (a placeholder,
    never proof) is explicit opt-in only. Production deployments set
    ``FINDEVIL_SIGNER=sigstore`` for identity + transparency-log tier.
    """
    actual = kind if kind is not None else os.environ.get("FINDEVIL_SIGNER", "ed25519")
    if actual == "sigstore":
        # Pick up the ambient OIDC identity from $SIGSTORE_ID_TOKEN when the
        # caller didn't pass one explicitly — this is the non-interactive path
        # the docs/manifest_finalize describe (a judge/CI exports the token
        # before sealing). Without it SigstoreSigner.sign() raises a clear
        # error rather than silently producing an unsigned bundle.
        kwargs.setdefault("identity_token", os.environ.get("SIGSTORE_ID_TOKEN"))
        return SigstoreSigner(**kwargs)
    if actual == "ed25519":
        return LocalEd25519Signer(**kwargs)
    if actual == "stub":
        return StubSigner(**kwargs)
    raise ValueError(f"unknown signer kind: {actual!r}")


__all__ = [
    "FallbackSigner",
    "LocalEd25519Signer",
    "SignedBundle",
    "Signer",
    "SigstoreSigner",
    "StubSigner",
    "make_signer",
]
