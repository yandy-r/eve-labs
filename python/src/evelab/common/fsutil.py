"""Small filesystem helpers shared by the evelab tools."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

__all__ = ["atomic_write", "is_root"]


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def atomic_write(dest: Path, data: bytes, *, tag: str = "evelab") -> None:
    """Replace ``dest`` with ``data`` atomically, keeping its mode and owner.

    The temp file sits next to ``dest`` (same filesystem), is fsynced and then
    ``os.replace``-d over it. The owner is copied only when running as root,
    so EVE (``www-data``) can still save the lab afterwards.
    """
    st = dest.stat() if dest.exists() else None
    tmp = dest.with_name(f".{dest.name}.{tag}-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644 if st is None else st.st_mode & 0o7777)
        if st is not None and is_root() and hasattr(os, "chown"):
            os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    if os.name == "posix":
        with contextlib.suppress(OSError):
            dfd = os.open(dest.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
