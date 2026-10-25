"""The index can consume the exact JSON already validated and spooled."""
import json

import pytest

from packet_pii.reporting import ReportSpool


def test_encoded_observer_receives_identical_json_without_second_encoding(tmp_path, monkeypatch):
    from packet_pii import reporting
    calls = []
    original = reporting._ROW_ENCODER.encode
    monkeypatch.setattr(reporting._ROW_ENCODER, 'encode', lambda row: (calls.append(row), original(row))[1])
    seen = []; legacy = []
    row = {'evidence_id': 'field-1', 'unicode': 'ก', 'ranges': [{'start': 1, 'end': 3}]}
    with ReportSpool(tmp_path, 10000, row_observer=lambda *args: legacy.append(args),
                     encoded_row_observer=lambda *args: seen.append(args)) as spool:
        spool.field_evidence.append(row)
        line, = spool.field_evidence.iter_json()
        assert seen == [('field_evidence', row, line.rstrip('\n'))]
        assert legacy == [('field_evidence', row)] and calls == [row]
        assert json.loads(seen[0][2]) == row


def test_encoding_error_never_reaches_index_observer(tmp_path):
    seen = []
    with ReportSpool(tmp_path, 10000, encoded_row_observer=lambda *args: seen.append(args)) as spool:
        with pytest.raises(ValueError):
            spool.findings.append({'score': float('nan')})
        assert seen == [] and len(spool.findings) == 0
