#!/usr/bin/env python3
"""Streaming, deterministic SYN/data/FIN captures; synthetic documentation IPs.

No project decoder/reassembler is imported. Files are created exclusively.
Memory is bounded by one batch of 16 independent conversations, regardless of
requested capture size. The last complete batch may exceed the requested size.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
import random
import struct

MIB = 1024 * 1024


def checksum(data: bytes) -> int:
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data)//2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def tcp_frame(src, dst, sport, dport, seq, ack, flags, payload=b''):
    """Ethernet / IPv4 / TCP with computed IP and TCP checksums."""
    sip, dip = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    tcp = struct.pack('!HHIIBBHHH',sport,dport,seq & 0xffffffff,ack & 0xffffffff,
                      0x50,flags,32768,0,0) + payload
    pseudo = sip+dip+struct.pack('!BBH',0,6,len(tcp))
    tcp = tcp[:16]+struct.pack('!H',checksum(pseudo+tcp))+tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),0,0x4000,64,6,0,sip,dip)
    ip = ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return bytes.fromhex('0200000000020200000000010800')+ip+tcp


def messages(flow_id, count=12):
    """Independent application oracle: exact wire bytes before segmentation."""
    requests, responses = [], []
    for i in range(count):
        marker = f'{flow_id:08d}-{i:03d}'
        if i % 4 == 0:
            request = (f'GET /lookup?id={marker}&email=fixture{flow_id}%40example.test HTTP/1.1\r\n'
                       'Host: example.test\r\n\r\n').encode()
        else:
            if i % 4 == 1:
                kind = 'application/json'
                body = json.dumps({'record':marker,'name':'Fictional Example',
                    'email':f'fixture{flow_id}@example.test','notes':('synthetic-'+marker+' ') * 45},
                    separators=(',',':')).encode()
            else:
                kind = 'application/x-www-form-urlencoded'
                body = (f'record={marker}&status=example&notes=' + ('nonpersonal'+marker)*55).encode()
            header = (f'POST /submit/{marker} HTTP/1.1\r\nHost: example.test\r\nContent-Type: {kind}\r\n').encode()
            if i % 4 == 3:
                request = header+b'Transfer-Encoding: chunked\r\n\r\n'
                request += f'{len(body):x};fixture=yes\r\n'.encode()+body+b'\r\n0\r\nX-Fixture: yes\r\n\r\n'
            else:
                request = header+f'Content-Length: {len(body)}\r\n\r\n'.encode()+body
        if i % 3 == 0:
            response = b'HTTP/1.1 204 No Content\r\n\r\n'
        else:
            body = json.dumps({'id':marker,'status':'synthetic'}).encode()
            coding = b''
            if i % 3 == 1:
                body = gzip.compress(body,mtime=0)
                coding = b'Content-Encoding: gzip\r\n'
            response = (b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'+coding+
                        f'Content-Length: {len(body)}\r\n\r\n'.encode()+body)
        requests.append(request); responses.append(response)
    return b''.join(requests), b''.join(responses)


def conversation(flow_id, seed):
    rng = random.Random((seed << 32) + flow_id)
    src, dst = f'192.0.2.{1 + flow_id//60000}', '198.51.100.20'
    sport, dport = 1024+flow_id%60000, 80 if flow_id % 10 else 9000
    request, response = messages(flow_id)
    count = 24
    if dport != 80:
        request, response, count = (f'SYNTHETIC BINARY {flow_id}\0'.encode()*130,
                                    b'EXAMPLE NON-HTTP RESPONSE\0',0)
    cseq = 0xfffffff0 if flow_id % 7 == 0 else rng.randrange(1,1 << 30)
    sseq = rng.randrange(1,1 << 30)
    frames = [tcp_frame(src,dst,sport,dport,cseq,0,2),
              tcp_frame(dst,src,dport,sport,sseq,cseq+1,0x12),
              tcp_frame(src,dst,sport,dport,cseq+1,sseq+1,0x10)]
    for direction, wire, start, ack in [(0,request,cseq+1,sseq+1),
                                       (1,response,sseq+1,cseq+1+len(request))]:
        segments = []
        offset = 0
        while offset < len(wire):
            end = min(len(wire),offset+rng.randint(480,1400))
            args = (src,dst,sport,dport) if direction == 0 else (dst,src,dport,sport)
            segments.append(tcp_frame(*args,start+offset,ack,0x18,wire[offset:end]))
            offset = end
        if flow_id % 3 == 0 and len(segments) > 2:
            segments[0],segments[1] = segments[1],segments[0]
        if flow_id % 4 == 0:
            segments.insert(1,segments[0])  # exact retransmission
        frames.extend(segments)
    cend,send = cseq+1+len(request), sseq+1+len(response)
    frames.extend([tcp_frame(src,dst,sport,dport,cend,send,0x11),
                   tcp_frame(dst,src,dport,sport,send,cend+1,0x11),
                   tcp_frame(src,dst,sport,dport,cend+1,send+1,0x10)])
    expected = {'flow_id':flow_id,'src':src,'sport':sport,'dst':dst,'dport':dport,
        'request_sha256':hashlib.sha256(request).hexdigest(),
        'response_sha256':hashlib.sha256(response).hexdigest(),
        'request_bytes':len(request),'response_bytes':len(response),'http_messages':count}
    return frames,expected


def generate(path: Path, size_mib: float, seed=20261014):
    if not 0 < size_mib <= 512 or seed < 0:
        raise ValueError('size_mib must be in (0, 512]; seed must be nonnegative')
    size,packet_count,flow_id,http_count,payload_count = 24,0,0,0,0
    digest = hashlib.sha256()
    with path.open('xb') as out:
        def write(data):
            out.write(data); digest.update(data)
        write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        while size < size_mib*MIB:
            batch = []
            for _ in range(16):
                frames,expected = conversation(flow_id,seed)
                batch.append(iter(frames))
                http_count += expected['http_messages']
                payload_count += expected['request_bytes']+expected['response_bytes']
                flow_id += 1
            while batch:
                remaining = []
                for packets in batch:
                    frame = next(packets,None)
                    if frame is None:
                        continue
                    sec,frac = divmod(packet_count,1000000)
                    write(struct.pack('<IIII',1700000000+sec,frac,len(frame),len(frame))+frame)
                    size += 16+len(frame); packet_count += 1
                    remaining.append(packets)
                batch = remaining
    return {'generator_version':1,'seed':seed,'requested_mib':size_mib,'capture_bytes':size,
            'packets':packet_count,'flows':flow_id,'http_messages':http_count,
            'unique_payload_bytes':payload_count,'sha256':digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--size-mib',type=float,required=True)
    parser.add_argument('--seed',type=int,default=20261014)
    args = parser.parse_args()
    print(json.dumps(generate(args.output,args.size_mib,args.seed),indent=2))

if __name__ == '__main__':
    main()
