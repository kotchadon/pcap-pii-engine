"""Read-only verification of existing TRACE TCP diagnostic index."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys


def test_retained_tcp_diagnostics_are_categorised_without_exposing_values(tmp_path):
    job_dir = tmp_path / 'trace_jobs_fictional' / 'job'
    job_dir.mkdir(parents=True)
    db = sqlite3.connect(job_dir / 'index.sqlite')
    db.execute('CREATE TABLE rows (kind TEXT, n INTEGER, data TEXT, PRIMARY KEY(kind,n))')
    rows = [
        ('findings', 0, {'pii_type':'EMAIL','value':'PRIVATE-DEMO-VALUE'}),
        ('findings', 1, {'pii_type':'USERNAME','value':'PRIVATE-DEMO-VALUE'}),
        ('http_evidence',0,{'row_type':'http','message_id':'test-message'}),
        ('stream_evidence',0,{'row_type':'stream','unsafe':True,'diagnostics':['reset_observed']}),
        ('stream_evidence',1,{'row_type':'stream','unsafe':True,'diagnostics':['sequence_gap','fin_boundary_mismatch']}),
        ('stream_evidence',2,{'row_type':'stream','unsafe':False,'diagnostics':['retransmission']}),
        ('stream_evidence',3,{'row_type':'source_range','unsafe':False,'frame_id':'frame_1'}),
    ]
    db.executemany('INSERT INTO rows VALUES(?,?,?)',
                   [(kind,seq,json.dumps(row)) for kind,seq,row in rows])
    db.commit()
    db.close()
    script = Path(__file__).resolve().parents[1] / 'scripts/validation/diagnose_retained_tcp_warnings.py'
    env = {**os.environ, 'TMPDIR':str(tmp_path), 'TMP':str(tmp_path), 'TEMP':str(tmp_path)}
    finished = subprocess.run([sys.executable, str(script), '--findings','2'],
                              env=env,text=True,capture_output=True,check=True)
    result = json.loads(finished.stdout)
    assert result['findings']==2
    assert result['http_messages']==1
    assert result['tcp_directions']==3
    assert result['unsafe_tcp_directions']==2
    assert result['tcp_diagnostics_for_unsafe_directions']=={
        'fin_boundary_mismatch':1,'reset_observed':1,'sequence_gap':1}
    assert 'PRIVATE-DEMO-VALUE' not in finished.stdout
    refused = subprocess.run([sys.executable,str(script),'--findings','3'],
                             env=env,text=True,capture_output=True)
    assert refused.returncode != 0
    assert 'No retained completed index' in refused.stderr
