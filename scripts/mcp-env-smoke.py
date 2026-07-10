#!/usr/bin/env python3
"""Prove evidence-facing MCP launchers do not inherit ambient credentials."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_env_probe(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nenv | sort\n", encoding="utf-8")
    path.chmod(0o755)


def _run(script: str, env: dict[str, str]) -> str:
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / script)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"{script} failed ({result.returncode}): "
            f"stdout={result.stdout[-1000:]!r} stderr={result.stderr[-1000:]!r}"
        )
    return result.stdout


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="verdict-mcp-env-") as raw_temp:
        temp = Path(raw_temp)
        rust_probe = temp / "findevil-mcp-probe"
        fake_home = temp / "home"
        uv_probe = fake_home / ".local" / "bin" / "uv"
        _write_env_probe(rust_probe)
        _write_env_probe(uv_probe)

        common = {
            "HOME": str(fake_home),
            "PATH": os.environ.get("PATH", os.defpath),
            "LANG": "C.UTF-8",
            "PROJECT_LOCAL": str(temp / "project-local"),
            "FINDEVIL_HOME": str(temp / "findevil"),
            "FINDEVIL_CASE_OPEN_BINDING": '{"artifacts":[]}',
            "FINDEVIL_BROWSER_CASE_BINDING": '{"case_id":"safe"}',
            "FINDEVIL_CONTROLLER_CAPABILITY": "a" * 64,
            "FINDEVIL_OUTPUT_ROUTE": "local_controller",
            "FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS": "1",
            "FIND_EVIL_DISK_YARA_RULES": str(temp / "rules" / "disk.yar"),
            "FINDEVIL_YARA_RULES_ROOT": str(temp / "rules"),
            "FINDEVIL_HAYABUSA_RULE_SET": str(temp / "hayabusa" / "rules"),
            "FINDEVIL_FLS_TIMEOUT_SECONDS": "321",
            "FINDEVIL_ICAT_TIMEOUT_SECONDS": "123",
            "FINDEVIL_MMLS_TIMEOUT_SECONDS": "45",
            "FINDEVIL_SIGSTORE_EXPECTED_IDENTITY": "release@example.test",
            "FINDEVIL_SIGSTORE_EXPECTED_ISSUER": "https://issuer.example.test",
            "OPENAI_API_KEY": "must-not-reach-parser",
            "AWS_SECRET_ACCESS_KEY": "must-not-reach-parser-either",
            "FINDEVIL_AGENT_API_KEY": "must-not-reach-parser-three",
        }

        rust_output = _run(
            "run-mcp-rust.sh",
            {**common, "FINDEVIL_MCP_BIN": str(rust_probe)},
        )
        python_output = _run(
            "run-mcp-python.sh",
            {**common, "FINDEVIL_SIGNING_KEY": str(temp / "signing.key")},
        )
        docker_python_output = _run(
            "run-mcp-python-docker.sh",
            {
                **common,
                "FINDEVIL_SIGNING_KEY": str(temp / "signing.key"),
                "FINDEVIL_ACTIVE_CASE_DIR": str(temp / "case-001"),
                "FINDEVIL_ACTIVE_CASE_ID": "case-001",
                "FINDEVIL_ACTIVE_RUN_ID": "run-001",
                "FINDEVIL_ACTIVE_STARTED_AT": "2026-07-10T00:00:00Z",
                "FINDEVIL_ACTIVE_SIGNER": "ed25519",
                "FINDEVIL_REPLAY_DOCKER_CONTAINER": "contract-test-container",
            },
        )

        for label, output in (("Rust", rust_output), ("Python", python_output)):
            if "must-not-reach-parser" in output:
                raise AssertionError(f"{label} MCP inherited an ambient credential")
            if f"FINDEVIL_HOME={temp / 'findevil'}" not in output:
                raise AssertionError(f"{label} MCP lost its contained case home")
            if "FINDEVIL_BROWSER_CASE_BINDING=" not in output:
                raise AssertionError(f"{label} MCP lost its browser custody binding")
            if "FINDEVIL_CASE_OPEN_BINDING=" not in output:
                raise AssertionError(f"{label} MCP lost its case-open custody binding")
            if "FINDEVIL_OUTPUT_ROUTE=local_controller" not in output:
                raise AssertionError(f"{label} MCP lost its local parsed-output route")
            if "FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS=1" not in output:
                raise AssertionError(
                    f"{label} MCP lost its explicit parsed-output acknowledgment"
                )
            if "FIND_EVIL_DISK_YARA_RULES=" not in output:
                raise AssertionError(f"{label} MCP lost its approved YARA rule binding")
            if "FINDEVIL_YARA_RULES_ROOT=" not in output:
                raise AssertionError(f"{label} MCP lost its approved YARA rule root")
            if "FINDEVIL_HAYABUSA_RULE_SET=" not in output:
                raise AssertionError(
                    f"{label} MCP lost its approved Hayabusa rule-set binding"
                )
            if "FINDEVIL_FLS_TIMEOUT_SECONDS=321" not in output:
                raise AssertionError(f"{label} MCP lost its parser timeout ceiling")
            if "FINDEVIL_ICAT_TIMEOUT_SECONDS=123" not in output:
                raise AssertionError(f"{label} MCP lost its extraction timeout ceiling")
            if "FINDEVIL_MMLS_TIMEOUT_SECONDS=45" not in output:
                raise AssertionError(f"{label} MCP lost its partition timeout ceiling")
        if f"FINDEVIL_SIGNING_KEY={temp / 'signing.key'}" not in python_output:
            raise AssertionError("Python custody MCP lost its explicit signing input")
        for label, output in (
            ("Python", python_output),
            ("Docker Python", docker_python_output),
        ):
            expected_capability = "FINDEVIL_CONTROLLER_CAPABILITY=" + "a" * 64
            if expected_capability not in output:
                raise AssertionError(
                    f"{label} MCP lost its private controller capability"
                )
        if "FINDEVIL_CONTROLLER_CAPABILITY=" in rust_output:
            raise AssertionError(
                "Rust parser MCP received the private controller capability"
            )
        for label, output in (
            ("Python", python_output),
            ("Docker Python", docker_python_output),
        ):
            if "FINDEVIL_SIGSTORE_EXPECTED_IDENTITY=release@example.test" not in output:
                raise AssertionError(f"{label} MCP lost its Sigstore identity policy")
            if (
                "FINDEVIL_SIGSTORE_EXPECTED_ISSUER=https://issuer.example.test"
                not in output
            ):
                raise AssertionError(f"{label} MCP lost its Sigstore issuer policy")
        if "FINDEVIL_SIGSTORE_EXPECTED_" in rust_output:
            raise AssertionError("Rust parser MCP received custody identity policy")
        if "FINDEVIL_SIGNING_KEY=" in rust_output:
            raise AssertionError("Rust parser MCP received the signing key")
        if "FINDEVIL_REPLAY_TRANSPORT=docker" not in docker_python_output:
            raise AssertionError("Docker custody MCP lost its fixed replay transport")
        if (
            "FINDEVIL_REPLAY_DOCKER_CONTAINER=contract-test-container"
            not in docker_python_output
        ):
            raise AssertionError("Docker custody MCP lost its reviewed container name")
        if f"FINDEVIL_SIGNING_KEY={temp / 'signing.key'}" not in docker_python_output:
            raise AssertionError("Docker custody MCP lost its host signing input")
        for expected in (
            f"FINDEVIL_ACTIVE_CASE_DIR={temp / 'case-001'}",
            "FINDEVIL_ACTIVE_CASE_ID=case-001",
            "FINDEVIL_ACTIVE_RUN_ID=run-001",
            "FINDEVIL_ACTIVE_STARTED_AT=2026-07-10T00:00:00Z",
            "FINDEVIL_ACTIVE_SIGNER=ed25519",
            "FINDEVIL_CUSTODY_BOUNDARY=reserved_case",
        ):
            if expected not in docker_python_output:
                raise AssertionError(
                    f"Docker custody MCP lost launcher reservation: {expected}"
                )
        for private_dir in (
            temp / "project-local",
            temp / "project-local" / "tmp",
            temp / "project-local" / "findevil",
            temp / "project-local" / "state",
        ):
            if stat.S_IMODE(private_dir.stat().st_mode) != 0o700:
                raise AssertionError(
                    f"contained custody directory is not owner-only: {private_dir}"
                )

    print("mcp-env-smoke: OK (ambient credentials excluded from parser children)")


if __name__ == "__main__":
    main()
