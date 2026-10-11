"""Minimal bounded HTTP/1.x stream parser and structured-field extraction."""
from __future__ import annotations
import json
import re
import zlib
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

MAX_HTTP_BODY = 2*1024*1024
MAX_HTTP_HEADER = 64*1024
METHODS = (b'GET ',b'POST ',b'PUT ',b'PATCH ',b'DELETE ',b'HEAD ',b'OPTIONS ')


@dataclass(frozen=True)
class HttpMessage:
    start_line: str
    headers: dict[str,str]
    body: bytes
    is_request: bool


def _chunked(data: bytes, position: int) -> tuple[bytes,int] | None:
    result = bytearray()
    for _ in range(10000):
        end = data.find(b'\r\n',position)
        if end < 0 or end - position > 128:
            return None
        try:
            size = int(data[position:end].split(b';',1)[0],16)
        except ValueError:
            return None
        position = end+2
        if size == 0:
            if len(data) < position+2:
                return None
            if data[position:position+2] == b'\r\n':
                return bytes(result),position+2
            trailer_end = data.find(b'\r\n\r\n',position)
            return (bytes(result),trailer_end+4) if trailer_end >= 0 else None
        if size > MAX_HTTP_BODY or len(result)+size > MAX_HTTP_BODY or position+size+2 > len(data):
            return None
        result.extend(data[position:position+size]); position += size
        if data[position:position+2] != b'\r\n':
            return None
        position += 2
    return None


def parse_http_stream(data: bytes) -> list[HttpMessage]:
    messages = []
    offset = 0
    while offset < len(data) and len(messages)<10000:
        # Resynchronize only at the start of a HTTP message.
        candidate = data[offset:]
        if not (candidate.startswith(METHODS) or candidate.startswith(b'HTTP/1.')):
            return messages
        header_end = data.find(b'\r\n\r\n',offset,min(len(data),offset+MAX_HTTP_HEADER))
        if header_end == -1:
            break
        head = data[offset:header_end].decode('iso-8859-1','replace')
        lines = head.split('\r\n')
        headers = {}
        if not lines:
            break
        for line in lines[1:]:
            if ':' in line:
                k,v = line.split(':',1)
                headers[k.lower().strip()] = v.strip()
        body_at = header_end + 4
        if 'chunked' in headers.get('transfer-encoding','').lower():
            parsed = _chunked(data,body_at)
            if parsed is None:
                break
            body,next_at = parsed
        elif 'content-length' in headers:
            try:
                size = int(headers['content-length'])
            except ValueError:
                break
            if size<0 or size>MAX_HTTP_BODY or body_at+size>len(data):
                break
            body=data[body_at:body_at+size];next_at=body_at+size
        else:
            # Body framing without a length is not inferred. For many GETs and
            # status responses this is OK; close-delimited bodies are omitted.
            body=b''; next_at=body_at
        messages.append(HttpMessage(lines[0],headers,body,not lines[0].startswith('HTTP/')))
        if next_at<=offset:
            break
        offset=next_at
    return messages


def _decoded_body(message: HttpMessage) -> str:
    body = message.body
    encoding=message.headers.get('content-encoding','').lower()
    try:
        if 'gzip' in encoding:
            obj = zlib.decompressobj(16+zlib.MAX_WBITS)
            body = obj.decompress(body,MAX_HTTP_BODY+1)
            if not obj.eof or len(body)>MAX_HTTP_BODY:
                return ''
        elif 'deflate' in encoding:
            obj = zlib.decompressobj()
            body=obj.decompress(body,MAX_HTTP_BODY)
            if not obj.eof:
                return ''
    except (OSError,zlib.error,EOFError):
        return ''
    if len(body)>MAX_HTTP_BODY:
        return ''
    charset='utf-8'
    match=re.search(r'charset\s*=\s*["\']?([\w-]+)',message.headers.get('content-type',''),re.I)
    if match:
        charset=match.group(1)
    try:
        return body.decode(charset,'replace')
    except LookupError:
        return body.decode('utf-8','replace')


def _flatten(value, path: str) -> list[tuple[str,str]]:
    if isinstance(value,dict):
        result=[]
        for key,child in value.items():
            result.extend(_flatten(child,f'{path}.{key}'))
        return result
    if isinstance(value,list):
        result=[]
        for i,child in enumerate(value):
            result.extend(_flatten(child,f'{path}[{i}]'))
        return result
    return [(path,str(value))] if value is not None else []


def extract_fields(message: HttpMessage) -> list[tuple[str,str]]:
    fields: list[tuple[str,str]]=[]
    for name,value in message.headers.items():
        fields.append((f'header.{name}',value))
    if message.is_request:
        parts=message.start_line.split(' ')
        if len(parts)>=2:
            for key,value in parse_qsl(urlsplit(parts[1]).query,keep_blank_values=True):
                fields.append((f'query_parameter.{key}',value))
    body=_decoded_body(message)
    ct=message.headers.get('content-type','').lower()
    if 'application/json' in ct or (body.strip().startswith(('{','['))):
        try:
            fields.extend(_flatten(json.loads(body),'json_body'))
        except (ValueError,RecursionError):
            pass
    elif 'application/x-www-form-urlencoded' in ct:
        for key,value in parse_qsl(body,keep_blank_values=True):
            fields.append((f'form.{key}',value))
    elif 'multipart/form-data' in ct:
        # Avoid treating binary file attachments as text. Text form fields only.
        match=re.search(r'boundary=(?:"([^"]+)"|([^;\s]+))',message.headers.get('content-type',''),re.I)
        if match:
            boundary=(match.group(1) or match.group(2)).encode()
            for part in message.body.split(b'--'+boundary)[1:]:
                header_end=part.find(b'\r\n\r\n')
                if header_end<0 or header_end>8192:
                    continue
                part_header=part[:header_end].decode('iso-8859-1','replace')
                field=re.search(r'name="([^"]+)"',part_header)
                if field and 'filename=' not in part_header.lower():
                    raw=part[header_end+4:].rstrip(b'\r\n-')
                    if len(raw)<MAX_HTTP_BODY:
                        fields.append((f'form.{field.group(1)}',raw.decode('utf-8','replace')))
    elif body and len(body)<=MAX_HTTP_BODY:
        fields.append(('body.text',body))
    return fields
