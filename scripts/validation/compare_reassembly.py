#!/usr/bin/env python3
"""Small-capture byte oracle plus optional independent dpkt/h11 verification.

Use captures from generate_captures.py. This tool bounds input to 2 MiB, checks
all directional SHA-256 digests against pre-segmentation bytes, checks every
packet with independently implemented decoders, and compares HTTP boundaries
with h11. No traffic contents are logged. Optional tools are dev-only.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import hashlib
import ipaddress
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from generate_captures import conversation
from packet_pii.capture import CaptureDiagnostics, decode_tcp, endpoint_key, read_frames, reassemble_detailed
from packet_pii.http_extract import parse_http_stream_with_spans


def compare(path, seed=20261014, independent=False, manifest=None):
    flows = defaultdict(list)
    diagnostics = CaptureDiagnostics()
    checks, boundary_checks, checksum_checks, packet_count, http_count = 0,0,0,0,0
    h11_version = dpkt_version = None
    if independent:
        import dpkt
        import h11
        h11_version,dpkt_version = h11.__version__,dpkt.__version__
    for frame in read_frames(path,max_file_bytes=2*1024*1024,diagnostics=diagnostics):
        packet_count += 1
        packet = decode_tcp(frame)
        assert packet is not None, 'generator produced unsupported packet'
        flows[endpoint_key(packet)].append(packet)
        if independent:
            ref_ip = dpkt.ethernet.Ethernet(frame.data).data
            ref = ref_ip.data
            assert str(ipaddress.ip_address(ref_ip.src)) == packet.src
            assert ref.seq == packet.seq and ref.data == packet.payload
            raw_ip = frame.data[14:]; ihl = (raw_ip[0]&15)*4
            assert dpkt.in_cksum(raw_ip[:ihl]) == 0
            pseudo = raw_ip[12:20]+bytes([0,6])+len(raw_ip[ihl:]).to_bytes(2,'big')
            assert dpkt.in_cksum(pseudo+raw_ip[ihl:]) == 0
            checksum_checks += 1
    assert flows and not diagnostics.incomplete, "empty or damaged capture"
    for packets in flows.values():
        client = next(p for p in packets if p.flags == 2)
        flow_id = (int(client.src.split('.')[-1])-1)*60000+client.sport-1024
        _,expected = conversation(flow_id,seed)
        for is_request in (True,False):
            direction = [p for p in packets if ((p.src,p.sport)==(client.src,client.sport)) == is_request]
            result = reassemble_detailed(direction)
            prefix = 'request' if is_request else 'response'
            assert not result.unsafe and not result.diagnostics
            assert hashlib.sha256(result.data).hexdigest() == expected[prefix+'_sha256']
            spans = parse_http_stream_with_spans(result.data)
            assert len(spans) == expected['http_messages']//2
            checks += 1
            http_count += len(spans)
            if independent and client.dport == 80:
                remaining = result.data
                for span in spans:
                    conn = h11.Connection(h11.SERVER if is_request else h11.CLIENT)
                    if not is_request:
                        conn.send(h11.Request(method='GET',target='/',headers=[('host','example.test')]))
                        conn.send(h11.EndOfMessage())
                    conn.receive_data(remaining)
                    body = bytearray()
                    while True:
                        event = conn.next_event()
                        assert event not in (h11.NEED_DATA,h11.PAUSED), 'reference incomplete'
                        if isinstance(event,h11.Data):
                            body.extend(event.data)
                        if isinstance(event,h11.EndOfMessage):
                            break
                    trailing,_ = conn.trailing_data
                    assert len(remaining)-len(trailing) == span.end_offset-span.start_offset
                    assert bytes(body) == span.message.body
                    remaining = trailing
                    boundary_checks += 1
                assert not remaining
    if manifest is not None:
        assert packet_count == manifest['packets'] and len(flows) == manifest['flows']
        assert http_count == manifest['http_messages']
        assert Path(path).stat().st_size == manifest['capture_bytes']
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == manifest['sha256']
    return {'flows':len(flows),'directional_digest_checks':checks,
            'independent_packet_checks':checksum_checks,'independent_http_boundaries':boundary_checks,
            'h11_version':h11_version,'dpkt_version':dpkt_version,'status':'passed'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture',type=Path)
    p.add_argument('--seed',type=int,default=20261014)
    p.add_argument('--independent',action='store_true')
    p.add_argument('--manifest',type=Path)
    args = p.parse_args()
    manifest = json.loads(args.manifest.read_text()) if args.manifest else None
    print(json.dumps(compare(args.capture,args.seed,args.independent,manifest),indent=2))

if __name__ == '__main__':
    main()
