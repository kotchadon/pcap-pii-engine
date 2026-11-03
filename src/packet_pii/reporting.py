"""Privacy-conscious local JSON reporting with atomic, exclusive writes.

Designed for POSIX filesystems (including macOS). Does not ship any telemetry.
The caller must provide a JSON-serializable report.
"""
from __future__ import annotations

import json
import gzip
import io
import os
from pathlib import Path
import tempfile
from contextlib import ExitStack
from typing import Any


def write_private_report(report: dict[str, Any], target: str | Path,
                         *, overwrite: bool = False, max_bytes: int | None = None,
                         row_sources=None, before_publish=None) -> None:
    """Safely write a complete report with 0600 permissions.

    By default, output is created exclusively: a pre-existing file or symlink
    is left untouched, including under concurrent writers. For explicit
    overwrites, atomic replacement ensures no partially-written report.
    Directory ownership/permissions are controlled by the user/OS.
    A target ending in ``.json.gz`` opts into lossless gzip (level 1). The
    decompressed JSON is identical to plain output. ``max_bytes`` continues to
    bound UTF-8 JSON bytes before compression; compression never expands the
    allowed analysis or evidence budget. Gzip headers contain no filename/time.
    """
    if max_bytes is not None and (type(max_bytes) is not int or max_bytes <= 0):
        raise ValueError('max_bytes must be a positive integer')
    path = Path(target)
    fd, temp_name = tempfile.mkstemp(prefix=f'.{path.name}.',
                                     suffix='.tmp', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as raw, ExitStack() as encoders:
            sink = raw
            if path.name.endswith('.json.gz'):
                sink = encoders.enter_context(gzip.GzipFile(
                    filename='', mode='wb', fileobj=raw, compresslevel=1, mtime=0))
            stream = encoders.enter_context(io.TextIOWrapper(sink, encoding='utf-8', newline='\n'))
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
            # Detach text buffering before closing gzip: the trailer must reach
            # disk before fsync/publication, while the raw descriptor stays open.
            stream.detach()
            encoders.pop_all()  # detached TextIOWrapper cannot be closed again
            if sink is not raw:
                sink.close()
            raw.flush()
            os.fsync(raw.fileno())
        if before_publish is not None:
            before_publish()
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


# One configured encoder per row format: json.dumps with non-default arguments builds a new encoder on every call,
# which dominated spooling of hundreds of thousands of evidence rows. Output is byte-identical.
_ROW_ENCODER = json.JSONEncoder(ensure_ascii=False, separators=(',', ':'), allow_nan=False)


class _Rows:
    def __init__(self, stream, owner, kind):
        self.stream, self.owner, self.kind, self.count = stream, owner, kind, 0

    def __len__(self):
        return self.count

    def append(self, row):
        encoded = _ROW_ENCODER.encode(row)
        text = encoded+'\n'
        size = len(text.encode('utf-8'))
        if size > self.owner.maximum-self.owner.written:
            raise ReportLimitError('Report spool exceeds configured byte budget')
        self.stream.write(text)
        self.owner.written += size
        if self.owner.encoded_row_observer is not None:
            self.owner.encoded_row_observer(self.kind, row, encoded)
        if self.owner.row_observer is not None:
            self.owner.row_observer(self.kind, row)
        self.count += 1

    def iter_json(self):
        self.stream.flush()
        self.stream.seek(0)
        yield from self.stream


class ReportSpool:
    """Private temporary row storage, bounded by encoded bytes, no pickle."""
    def __init__(self,directory,maximum,*,row_observer=None,encoded_row_observer=None):
        self.directory,self.maximum,self.written = directory,maximum,0
        self.row_observer = row_observer
        self.encoded_row_observer = encoded_row_observer
        self.stack=ExitStack()

    def __enter__(self):
        try:
            for name in ('flows','findings','ml_field_coverage',
                         'packet_evidence','stream_evidence','http_evidence','field_evidence'):
                stream=self.stack.enter_context(tempfile.TemporaryFile(
                    mode='w+t',encoding='utf-8',prefix='.pcap-pii-',dir=self.directory))
                os.fchmod(stream.fileno(),0o600)
                setattr(self,name,_Rows(stream,self,name))
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self,*exc):
        self.stack.close()


class _IndexedRows:
    """JSON rows kept in the dashboard's existing private SQLite index.

    The ordinary CLI keeps using ReportSpool. Dashboard scans can reuse the
    indexed JSON as their report source, avoiding a second multi-GiB plaintext
    spool. No evidence fields, IDs or original bytes are discarded.
    """
    def __init__(self, owner, kind):
        self.owner, self.kind, self.count = owner, kind, 0

    def __len__(self):
        return self.count

    def append(self, row):
        encoded = _ROW_ENCODER.encode(row)
        size = len(encoded.encode('utf-8')) + 1
        if size > self.owner.maximum - self.owner.written:
            raise ReportLimitError('Indexed evidence exceeds configured uncompressed byte budget')
        # This observer inserts the identical JSON into the job's SQLite index.
        # A failed insert must not be counted as a successfully stored row.
        self.owner.encoded_row_observer(self.kind, row, encoded)
        self.owner.written += size
        self.count += 1

    def iter_json(self):
        # All row production is complete before publication begins. One cursor
        # streams one row at a time; neither Python nor the caller builds an
        # in-memory list of millions of evidence records.
        self.owner.connection.commit()
        cursor = self.owner.connection.execute(
            'SELECT data FROM rows WHERE kind=? ORDER BY n', (self.kind,))
        try:
            for (encoded,) in cursor:
                yield encoded + '\n'
        finally:
            cursor.close()


class IndexedReportSpool:
    """Alternative bounded row source for indexed dashboard jobs.

    Requires an existing private SQLite connection and a callback that stores
    every encoded row in that connection. The caller owns transaction lifecycle,
    cleanup, access control and the SQLite disk cap. No temporary report spool
    is created: the final JSON is streamed from the index.
    """
    ROW_NAMES = ('flows', 'findings', 'ml_field_coverage',
                 'packet_evidence', 'stream_evidence', 'http_evidence', 'field_evidence')

    def __init__(self, connection, maximum, *, encoded_row_observer):
        if encoded_row_observer is None:
            raise ValueError('Indexed report storage requires an indexed-row writer')
        self.connection = connection
        self.maximum = maximum
        self.encoded_row_observer = encoded_row_observer
        self.written = 0

    def __enter__(self):
        for name in self.ROW_NAMES:
            setattr(self, name, _IndexedRows(self, name))
        return self

    def __exit__(self, *exc):
        # JobManager commits, closes and removes the index if anything fails.
        return False
