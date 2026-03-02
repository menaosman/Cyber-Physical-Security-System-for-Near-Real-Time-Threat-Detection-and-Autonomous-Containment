from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class TLSConfig:
    ca_cert: Path
    client_cert: Path | None = None
    client_key: Path | None = None
    insecure: bool = False  # for dev only (skip hostname verify) if needed

def default_tls_paths(role: str, base_dir: str = "config/certificates") -> TLSConfig:
    """
    role: 'gateway-agent' | 'local-manager' | ...
    """
    base = Path(base_dir)
    ca = base / "ca.crt"
    crt = base / f"{role}.crt"
    key = base / f"{role}.key"

    # NOTE: keys are ignored by git; they exist locally.
    if not ca.exists():
        raise FileNotFoundError(f"CA cert not found: {ca}")
    if not crt.exists() or not key.exists():
        # allow running without client cert for initial local tests
        return TLSConfig(ca_cert=ca)

    return TLSConfig(ca_cert=ca, client_cert=crt, client_key=key)
