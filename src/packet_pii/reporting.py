"""Privacy-conscious local JSON reporting with atomic, exclusive writes.

Designed for POSIX filesystems (including macOS). Does not ship any telemetry.
The caller must provide a JSON-serializable report.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any


def write_private_report(report: dict[str, Any], target: str | Path,
                         *, overwrite: bool = False) -> None:
    """Safely write a complete report with 0600 permissions.

    By default, output is created exclusively: a pre-existing file or symlink
    is left untouched, including under concurrent writers. For explicit
    overwrites, atomic replacement ensures no partially-written report.
    Directory ownership/permissions are controlled by the user/OS.
    """
    path = Path(target)
    fd, temp_name = tempfile.mkstemp(prefix=f'.{path.name}.',
                                     suffix='.tmp', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temp_name, path)
        else:
            # Unlike a check-then-rename, this fails atomically if path exists.
            # In particular it will never follow an existing output symlink.
            os.link(temp_name, path)
            os.unlink(temp_name)
    finally:
        # Clean up on serialization errors, disk failures, or a name collision.
        if os.path.lexists(temp_name):
            os.unlink(temp_name)
