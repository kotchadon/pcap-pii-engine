"""Privacy-conscious local JSON reporting with atomic, exclusive writes.

Designed for POSIX filesystems (including macOS). Does not ship any telemetry.
The caller must provide a JSON-serializable report.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from contextlib import ExitStack
from typing import Any


def write_private_report(report: dict[str, Any], target: str | Path,
                         *, overwrite: bool = False, max_bytes: int | None = None,
                         row_sources=None) -> None:
    """Safely write a complete report with 0600 permissions.

    By default, output is created exclusively: a pre-existing file or symlink
    is left untouched, including under concurrent writers. For explicit
    overwrites, atomic replacement ensures no partially-written report.
    Directory ownership/permissions are controlled by the user/OS.
    """
    if max_bytes is not None and (type(max_bytes) is not int or max_bytes <= 0):
        raise ValueError('max_bytes must be a positive integer')
    path = Path(target)
    fd, temp_name = tempfile.mkstemp(prefix=f'.{path.name}.',
                                     suffix='.tmp', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            output = _BudgetWriter(stream,max_bytes)
            if row_sources is None:
                json.dump(report, output, ensure_ascii=False, indent=2, allow_nan=False)
            else:
                output.write('{')
                for index,(key,value) in enumerate(report.items()):
                    if index: output.write(',')
                    output.write(json.dumps(key)+':')
                    if key in row_sources:
                        output.write('[')
                        for row_index,line in enumerate(row_sources[key]):
                            if row_index: output.write(',')
                            output.write(line.rstrip('\n'))
                        output.write(']')
                    else:
                        json.dump(value,output,ensure_ascii=False,allow_nan=False)
                output.write('}')
            output.write('\n')
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


class ReportLimitError(ValueError):
    """No complete report fits the configured output budget."""


class _BudgetWriter:
    def __init__(self, stream, maximum):
        self.stream, self.maximum, self.written = stream, maximum, 0

    def write(self, text):
        if self.maximum is not None:
            size = len(text.encode('utf-8'))
            if size > self.maximum-self.written:
                raise ReportLimitError('Report exceeds configured byte budget')
            self.written += size
        return self.stream.write(text)


class _Rows:
    def __init__(self, stream, owner):
        self.stream, self.owner, self.count = stream, owner, 0

    def __len__(self):
        return self.count

    def append(self, row):
        text = json.dumps(row,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n'
        size = len(text.encode('utf-8'))
        if size > self.owner.maximum-self.owner.written:
            raise ReportLimitError('Report spool exceeds configured byte budget')
        self.stream.write(text)
        self.owner.written += size
        self.count += 1

    def iter_json(self):
        self.stream.flush()
        self.stream.seek(0)
        yield from self.stream


class ReportSpool:
    """Private temporary row storage, bounded by encoded bytes, no pickle."""
    def __init__(self,directory,maximum):
        self.directory,self.maximum,self.written = directory,maximum,0
        self.stack=ExitStack()

    def __enter__(self):
        try:
            for name in ('flows','findings'):
                stream=self.stack.enter_context(tempfile.TemporaryFile(
                    mode='w+t',encoding='utf-8',prefix='.pcap-pii-',dir=self.directory))
                os.fchmod(stream.fileno(),0o600)
                setattr(self,name,_Rows(stream,self))
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self,*exc):
        self.stack.close()
