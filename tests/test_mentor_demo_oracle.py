"""Negative provenance tests: plausible but wrong report coordinates must fail."""
import copy
import json
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

from test_http_investigation import evidence

ROOT=Path(__file__).resolve().parents[1]


def reference():
    pytest.importorskip('dpkt');pytest.importorskip('h11')
    spec=spec_from_file_location('mentor_reference_negative',ROOT/'scripts/validation/verify_mentor_demo.py')
    module=module_from_spec(spec);spec.loader.exec_module(module);return module


@pytest.mark.parametrize('corruption',['shifted_stream','wrong_direction','wrong_file_offset'])
def test_independent_oracle_rejects_plausible_wrong_provenance(evidence,tmp_path,corruption):
    path,_,report,_=evidence
    report=copy.deepcopy(report)
    stream=report['http_evidence'][0]['stream_id']
    if corruption=='shifted_stream':
        for row in report['stream_evidence']:
            if row.get('row_type')=='source_range' and row['stream_id']==stream:
                row['stream_start']+=17;row['stream_end']+=17
        for row in report['field_evidence']:
            if row['stream_id']==stream:
                for interval in row['stream_ranges']:
                    interval['start']+=17;interval['end']+=17
    elif corruption=='wrong_direction':
        row=next(r for r in report['stream_evidence'] if r['evidence_id']==stream)
        row['direction']=['198.51.100.20',80,'192.0.2.10',50123]
    else:
        for row in report['stream_evidence']:
            if row.get('row_type')=='source_range' and row['stream_id']==stream:
                row['file_start']+=1;row['file_end']+=1
    candidate=tmp_path/'wrong.json';candidate.write_text(json.dumps(report))
    with pytest.raises(AssertionError):reference().verify(path,candidate)


def test_fixture_header_stable_when_python_gzip_os_marker_changes(monkeypatch,tmp_path):
    from test_http_investigation import fixture
    original=fixture.gzip.compress
    def newer_header(*args,**kwargs):
        raw=bytearray(original(*args,**kwargs));raw[9]=255;return bytes(raw)
    monkeypatch.setattr(fixture.gzip,'compress',newer_header)
    result=fixture.write_demo(tmp_path/'demo.pcap')
    assert result['sha256']=='fa0070187d39425fc03bf15ba1700cfe1c57a20e724af03a4338c10676ed9d83'
