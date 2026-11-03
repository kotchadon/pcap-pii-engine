"""Indexed report streaming: no duplicated plaintext spool, no lost evidence."""
import json
import sqlite3
import pytest

from packet_pii.reporting import IndexedReportSpool, ReportLimitError, _ROW_ENCODER


def test_indexed_rows_stream_exact_json_and_preserve_metadata():
    with sqlite3.connect(':memory:') as conn:
        conn.execute('CREATE TABLE rows(kind TEXT,n INTEGER,data TEXT,PRIMARY KEY(kind,n))')
        counts = {}
        def observe(kind, row, encoded):
            n = counts.get(kind, 0)
            conn.execute('INSERT INTO rows VALUES(?,?,?)', (kind, n, encoded))
            counts[kind] = n + 1
        fields = [
            {'evidence_id': 'field-1', 'location': 'json_body.profile.email',
             'stream_ranges': [{'start': 0, 'end': 16}],
             'transformations': [], 'value': 'alex@example.invalid'},
            {'evidence_id': 'field-2', 'location': 'json_body.profile.name',
             'stream_ranges': [{'start': 16, 'end': 32}],
             'transformations': ['json_parse'], 'value': 'Fictional Person'},
        ]
        with IndexedReportSpool(conn, 4096, encoded_row_observer=observe) as spool:
            for row in fields:
                spool.field_evidence.append(row)
            spool.findings.append({'pii_type': 'EMAIL', 'field_ids': ['field-1']})
            assert len(spool.field_evidence) == 2
            assert len(spool.findings) == 1
            assert list(spool.field_evidence.iter_json()) == [
                _ROW_ENCODER.encode(row) + '\n' for row in fields]
            assert json.loads(''.join(spool.findings.iter_json())) == {
                'pii_type': 'EMAIL', 'field_ids': ['field-1']}
            assert spool.written == sum(
                len(_ROW_ENCODER.encode(row).encode('utf-8')) + 1
                for row in fields + [{'pii_type': 'EMAIL', 'field_ids': ['field-1']}])
        assert counts == {'field_evidence': 2, 'findings': 1}


def test_indexed_spool_rejects_oversized_rows_before_index_insert():
    with sqlite3.connect(':memory:') as conn:
        conn.execute('CREATE TABLE rows(kind TEXT,n INTEGER,data TEXT,PRIMARY KEY(kind,n))')
        counts = []
        def observe(kind, row, encoded):
            counts.append(kind)
        with IndexedReportSpool(conn, 10, encoded_row_observer=observe) as spool:
            with pytest.raises(ReportLimitError, match='uncompressed byte budget'):
                spool.field_evidence.append({'value': 'SECRET-do-not-retain'})
        assert not counts


def test_indexed_storage_requires_real_writer():
    with sqlite3.connect(':memory:') as conn:
        with pytest.raises(ValueError, match='indexed-row writer'):
            IndexedReportSpool(conn, 100, encoded_row_observer=None)
