#!/usr/bin/env python3
"""Execute the fictional mentor demo through real authenticated HTTP APIs.

No private input accepted, model downloads, training, or external page fetching.
Optional TShark runs locally. A real browser is a separate acceptance gate.
"""
import argparse
from contextlib import contextmanager
import hashlib
from http.client import HTTPConnection
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'src'))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False)+'\n')


def subset_capture(raw, excluded):
    result=bytearray(raw[:24]); position=24; frame=0
    while position<len(raw):
        frame+=1
        length=struct.unpack_from('<I',raw,position+8)[0]
        end=position+16+length
        require(end<=len(raw),'Invalid fixture PCAP record')
        if frame not in excluded:
            result.extend(raw[position:end])
        position=end
    return bytes(result)


@contextmanager
def server():
    from packet_pii.dashboard import DashboardServer
    s=DashboardServer(('127.0.0.1',0),max_upload=65536,
                      assessment_budget=None,retain_capture_for_inspection=True)
    thread=threading.Thread(target=s.serve_forever,daemon=True);thread.start()
    try:
        yield s
    finally:
        s.shutdown();s.server_close();thread.join(5)


def api(s, method, path, body=None, headers=None, expected=200, auth=True):
    c=HTTPConnection('127.0.0.1',s.server_port,timeout=20)
    h={'X-Dashboard-Token':s.token} if auth else {}
    h.update(headers or {})
    try:
        c.request(method,path,body=body,headers=h)
        response=c.getresponse(); raw=response.read(2*1024*1024+1)
        require(len(raw)<=2*1024*1024,'Demo API output exceeds 2 MiB')
        require(response.status==expected,f'{method} {path}: expected {expected}, got {response.status}')
        return json.loads(raw)
    finally:
        c.close()


def upload(s, path, request_id):
    receipt=api(s,'POST','/api/jobs',path.read_bytes(),
                {'Content-Type':'application/octet-stream','X-Capture-Name':path.name,
                 'X-Request-ID':request_id,'X-Detection-Mode':'rules','X-Analysis-Profile':'standard'},expected=202)
    job=s.jobs.get(receipt['job_id'])
    job.thread.join(20)  # Await this tiny job once; no repeated status polling.
    require(not job.thread.is_alive() and job.status=='completed','Fixture scan failed or timed out')
    return '/api/jobs/'+job.job_id


def tshark_verify(capture, verification, directory):
    executable=shutil.which('tshark')
    if not executable:
        return {'status':'blocked','reason':'TShark not installed; run documented macOS check'}
    version=subprocess.run([executable,'--version'],check=True,capture_output=True,text=True,timeout=15).stdout.splitlines()[0]
    fields=['frame.number','ip.src','tcp.srcport','ip.dst','tcp.dstport','tcp.seq_raw',
            'tcp.ack_raw','tcp.flags','tcp.payload','tcp.analysis.retransmission',
            'tcp.analysis.out_of_order','http.request.method','http.response.code']
    command=[executable,'-n','-r',str(capture),'-o','tcp.reassemble_out_of_order:TRUE','-T','fields']
    for field in fields:
        command.extend(['-e',field])
    result=subprocess.run(command,check=True,capture_output=True,text=True,timeout=30)
    (directory/'tshark-packets.tsv').write_text('\t'.join(fields)+'\n'+result.stdout)
    rows=[dict(zip(fields,line.split('\t'))) for line in result.stdout.splitlines()]
    require(len(rows)==11,'TShark packet count differs')
    require([(int(r['tcp.seq_raw']),int(r['tcp.ack_raw']),int(r['tcp.flags'],16)) for r in rows[:3]]==
            [(1000,0,2),(9000,1001,18),(1001,9001,16)],'TShark handshake differs')
    require(int(rows[3]['tcp.seq_raw'])>int(rows[4]['tcp.seq_raw']),'TShark reordered sequence differs')
    require(rows[4]['tcp.payload']==rows[5]['tcp.payload'] and rows[4]['tcp.seq_raw']==rows[5]['tcp.seq_raw'],
            'TShark repeated segment differs')
    for interval in verification['exact_email_source_intervals']:
        row=rows[interval['frame']-1];payload=bytes.fromhex(row['tcp.payload'].replace(':',''))
        offset=interval['tcp_seq_start']-int(row['tcp.seq_raw'])
        require(payload[offset:offset+interval['stream_end']-interval['stream_start']].hex()==interval['hex'],
                'TShark payload slice differs from original byte evidence')
    methods=[r['http.request.method'] for r in rows if r['http.request.method']]
    statuses=[r['http.response.code'] for r in rows if r['http.response.code']]
    require(methods==['POST','GET'] and statuses==['100','200','200'],'TShark HTTP messages differ')
    # Save actual dissector labels; heuristic labels are not proof of ordering.
    return {'status':'passed','version':version,'handshake_sequence_and_original_payload_slices':True,
            'tcp_reassemble_out_of_order':True,
            'observed_http_methods':methods,'observed_http_statuses':statuses,
            'retransmission_flag_frames':[int(r['frame.number']) for r in rows if r['tcp.analysis.retransmission']],
            'out_of_order_flag_frames':[int(r['frame.number']) for r in rows if r['tcp.analysis.out_of_order']]}


def run(directory):
    from packet_pii.static_page import export_document
    generator=load('mentor_generator',ROOT/'examples/generate_mentor_demo.py')
    reference=load('mentor_reference',ROOT/'scripts/validation/verify_mentor_demo.py')
    capture=directory/'mentor-demo.pcap';oracle=generator.write_demo(capture)
    incomplete=directory/'missing-response-packet.pcap'
    incomplete.write_bytes(subset_capture(capture.read_bytes(),{9}))
    midstream=directory/'missing-handshake.pcap'
    midstream.write_bytes(subset_capture(capture.read_bytes(),{1,2,3}))
    with server() as s:
        base=upload(s,capture,'mentor-complete-fixture')
        report=api(s,'GET',base+'/report');write_json(directory/'trace-report.json',report)
        require(report['summary']['http_messages']==5 and report['summary']['http_transactions']==2,'Wrong HTTP reconstruction')
        require(report['summary']['rules_findings']==9,'Fixture rule findings changed; inspect rather than update blindly')
        require(report['summary']['tcp_capture_completeness']=='unknown','Fixture lacks FIN: do not claim whole connection complete')
        require(report['summary']['ml_inference_invoked'] is False,'Rules-only demo unexpectedly invoked ML')
        verification=reference.verify(capture,directory/'trace-report.json')
        tx=api(s,'GET',base+'/conversations')
        require(tx['total']==2,'Conversation grouping differs')
        finding=next(f for f in report['findings'] if f['pii_type']=='EMAIL' and f['http_message_id']==report['http_evidence'][0]['http_message_id'])
        field_id=finding['evidence']['field_ids'][0]
        detail=api(s,'GET',base+'/investigation?'+urlencode({'message_id':finding['http_message_id'],'field_id':field_id}))
        require(detail['verification']['coverage_complete'] and detail['verification']['scope']=='whole_field','Field coverage differs')
        require([r['frame_index'] for r in detail['source_ranges']]==[5,4],'Wrong supporting frame order')
        require(b''.join(capture.read_bytes()[r['file_start']:r['file_end']] for r in detail['source_ranges'])==oracle['email'].encode(),
                'Selected finding does not link to original email bytes')
        write_json(directory/'trace-investigation.json',{'finding':finding,**detail})
        mid=report['http_evidence'][2]['http_message_id']
        body=json.dumps({'message_id':mid,'acknowledge_sensitive_content':True,'representation':'static'})
        headers={'Content-Type':'application/json'}
        api(s,'POST',base+'/content',body,headers,expected=403,auth=False)
        no_ack=json.dumps({'message_id':mid,'acknowledge_sensitive_content':False})
        api(s,'POST',base+'/content',no_ack,headers,expected=400)
        recovered=api(s,'POST',base+'/content',body,headers)
        actual=recovered['text'].encode('utf-8')
        require(recovered['status']=='recovered' and len(actual)==verification['html_body_bytes'] and
                hashlib.sha256(actual).hexdigest()==verification['html_body_sha256'],
                'Recovered source does not match independent h11 response body')
        (directory/'captured-response.html.txt').write_bytes(actual)  # Raw source must not open as executable HTML.
        write_json(directory/'recovered-content.json',recovered)
        (directory/'captured-page.static.html').write_text(export_document(recovered['static_representation']))
        gap_base=upload(s,incomplete,'mentor-missing-response')
        gap=api(s,'GET',gap_base+'/report');write_json(directory/'incomplete-report.json',gap)
        require(gap['summary']['http_observed_incomplete'] and gap['summary']['stream_gaps']==1,'Missing packet not disclosed')
        require(not any(m.get('status')==200 for m in gap['http_evidence']),'Incomplete response fabricated as complete')
        api(s,'POST',gap_base+'/content',body,headers,expected=400)  # Same message ID now belongs to a request: never old-job HTML.
        mid_base=upload(s,midstream,'mentor-missing-handshake')
        partial=api(s,'GET',mid_base+'/report');write_json(directory/'midstream-report.json',partial)
        streams=[r for r in partial['stream_evidence'] if r.get('row_type')=='stream']
        require(streams and all(not r['syn_observed'] for r in streams),'Uncaptured handshake inferred')
        require(partial['summary']['tcp_capture_completeness']=='unknown','Missing handshake completeness invented')
    verification.update({'rules_findings':9,'authenticated_http_workflow':'passed',
                         'source_matches_independent_response_body':True,
                         'missing_response_packet':{'status':'passed','http_messages':gap['summary']['http_messages'],
                                                    'http_observed_incomplete':True,'final_200_recovered':False},
                         'missing_handshake':{'status':'passed','syn_observed':False,'connection_completeness':'unknown'},
                         'static_representation':'lossy_inert_text_and_structure_no_resources',
                         'browser':{'status':'not_run','command':'node scripts/validation/browser_mentor_demo.cjs http://127.0.0.1:8765 '+str(capture.name)},
                         'v2':{'status':'not_run','reason':'Separate genuine-checkpoint acceptance required; this demo is rules-only'},
                         'platform':{'system':platform.system(),'machine':platform.machine(),'python':platform.python_version()},
                         'scope':'Fictional protocol/provenance demonstration, not measured detection accuracy'})
    verification['tshark']=tshark_verify(capture,verification,directory)
    verification['wireshark_tshark_executed']=verification['tshark']['status']=='passed'
    write_json(directory/'verification.json',verification)
    lines=['# Actual original-byte evidence — fictional email','',
           'All ranges are half-open. Rows are in reconstructed stream order. Whole-field support; not an exact detector substring.','',
           'Capture SHA-256: `'+verification['capture_sha256']+'`','',
           f"Client `{oracle['client']}` → server `{oracle['server']}`; session 1; `{detail['message']['stream_id']}`; `{finding['http_message_id']}`; `{field_id}`; EMAIL.",'',
           '| Frame | TCP sequence | Stream bytes | Capture-file bytes | Frame bytes | Actual hex | Actual fictional text |',
           '|---|---|---|---|---|---|---|']
    for r in verification['exact_email_source_intervals']:
        lines.append(f"| {r['frame']} | [{r['tcp_seq_start']}, {r['tcp_seq_end']}) | [{r['stream_start']}, {r['stream_end']}) | [{r['file_start']}, {r['file_end']}) | [{r['frame_start']}, {r['frame_end']}) | `{r['hex']}` | `{r['ascii']}` |")
    (directory/'EVIDENCE.md').write_text('\n'.join(lines)+'\n')
    hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.iterdir()) if p.is_file()}
    write_json(directory/'artifact-sha256.json',hashes)
    return verification


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path('demo-output'))
    args=parser.parse_args()
    if not __debug__:
        parser.error('Do not disable Python assertions for reference validation')
    if sys.version_info<(3,10):
        parser.error('Python 3.10+ required')
    try:
        import dpkt, h11
    except ImportError:
        parser.error('Install small reference dependencies: python3 -m pip install dpkt==1.9.8 h11==0.16.0')
    target=args.output.resolve()
    if target.exists():
        parser.error('Output already exists; choose a fresh --output directory')
    target.parent.mkdir(parents=True,exist_ok=True)
    old_umask=os.umask(0o077)
    stage=Path(tempfile.mkdtemp(prefix='.mentor-staging-',dir=target.parent))
    try:
        result=run(stage)
        os.replace(stage,target)
    except BaseException:
        shutil.rmtree(stage,ignore_errors=True)
        raise
    finally:
        os.umask(old_umask)
    print(json.dumps({'required_demo_assertions':'passed','output':str(target),
                      'tshark':result['tshark'],'browser':'separate acceptance, not run by this command',
                      'html_source':'captured-response.html.txt','inert_page':'captured-page.static.html'},indent=2))
    print('Dashboard: PYTHONPATH=src python3 -m packet_pii.dashboard --port 8765 --retain-capture-for-inspection')
    print('Upload '+str(target/'mentor-demo.pcap')+'; see docs/integration/MENTOR_DEMO_COMPLETION.md')


if __name__=='__main__':
    main()
