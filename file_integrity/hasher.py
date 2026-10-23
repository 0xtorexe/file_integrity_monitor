"""Module 2: Hash Generator.

Every file is read in fixed-size chunks so that large files do not have to be
loaded into memory all at once.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

ALGORITHM = "sha256"
CHUNK_SIZE = 1024 * 1024  # 1 MiB


def hash_file(path: str | Path) -> str:
    """Return the hexadecimal SHA-256 digest of ``path``."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()
