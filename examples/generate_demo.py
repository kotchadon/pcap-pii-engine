"""Generate synthetic, non-personal PCAP for reproducible local tests."""
from pathlib import Path
import gzip
import socket
import struct
import sys


def tcp_frame(source: str, sport: int, target: str, dport: int, seq: int, payload: bytes=b'', flags: int=0x18) -> bytes:
    src=socket.inet_aton(source)
    dst=socket.inet_aton(target)
    tcph=struct.pack('!HHIIHHHH',sport,dport,seq,0,(5<<12)|flags,8192,0,0)
    total=20+len(tcph)+len(payload)
    iph=struct.pack('!BBHHHBBH4s4s',0x45,0,total,0,0x4000,64,6,0,src,dst)
    eth=b'\x02\x00\x00\x00\x00\x02'+b'\x02\x00\x00\x00\x00\x01'+b'\x08\x00'
    return eth+iph+tcph+payload


def packets() -> list[tuple[float,bytes]]:
    reqbody=(b'{"email":"student@example.com","password":"demo-only-secret",'
             b'"card":"4111 1111 1111 1111","full_name":"Alex Example"}')
    request=(b'POST /submit?phone=0412345678 HTTP/1.1\r\n'
             b'Host: demo.example\r\nContent-Type: application/json\r\n'
             b'Authorization: Bearer demo-token-123\r\n'
             b'Content-Length: '+str(len(reqbody)).encode()+b'\r\n\r\n'+reqbody)
    response_body=gzip.compress(b'{"email":"reply@example.com"}')
    response=(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
              b'Content-Encoding: gzip\r\nContent-Length: '
              +str(len(response_body)).encode()+b'\r\n\r\n'+response_body)
    client='192.0.2.10'; server='198.51.100.20'
    def outbound(seq,payload=b'',flags=0x18):
        return tcp_frame(client,50123,server,80,seq,payload,flags)
    def inbound(seq,payload=b'',flags=0x18):
        return tcp_frame(server,80,client,50123,seq,payload,flags)
    # Deliberately put request segments into the capture out of order.
    a,b,c=request[:67],request[67:141],request[141:]
    return [
        (1.0,outbound(1000,b'',0x02)),
        (1.01,inbound(2000,b'',0x12)),
        (1.02,outbound(1001,b'',0x10)),
        (1.10,outbound(1001+len(a),b)),
        (1.11,outbound(1001,a)),
        (1.12,outbound(1001+len(a)+len(b),c)),
        (1.13,outbound(1001+len(a),b)), # retransmission
        (1.30,inbound(2001,response)),
    ]


def write_pcap(path: Path) -> None:
    with open(path,'wb') as out:
        out.write(b'\xd4\xc3\xb2\xa1')
        out.write(struct.pack('<HHiIII',2,4,0,0,65535,1))
        for timestamp,packet in packets():
            secs=int(timestamp); micros=int(round((timestamp-secs)*1e6))
            out.write(struct.pack('<IIII',secs,micros,len(packet),len(packet)))
            out.write(packet)


def write_pcapng(path: Path) -> None:
    def block(kind,body):
        body+=b'\x00'*((-len(body))%4)
        size=12+len(body)
        return struct.pack('<II',kind,size)+body+struct.pack('<I',size)
    with open(path,'wb') as out:
        out.write(block(0x0a0d0d0a,b'\x4d\x3c\x2b\x1a'+struct.pack('<HHq',1,0,-1)))
        out.write(block(1,struct.pack('<HHi',1,0,65535)))
        for timestamp,pkt in packets():
            ts=int(round(timestamp*1e6))
            epb=struct.pack('<IIIII',0,ts>>32,ts&0xffffffff,len(pkt),len(pkt))+pkt
            out.write(block(6,epb))

if __name__=='__main__':
    destination=Path(sys.argv[1]) if len(sys.argv)>1 else Path('demo.pcap')
    if destination.suffix.lower()=='.pcapng':
        write_pcapng(destination)
    else:
        write_pcap(destination)
    print('Wrote synthetic capture:',destination)
