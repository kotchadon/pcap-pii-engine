"""Value-free, bounded joins from detector output to captured source bytes.

These helpers never infer raw byte offsets from decoded character offsets.
The capture identity scopes all IDs; IDs alone are not globally unique.
"""
from __future__ import annotations

EVIDENCE_VERSION = '1.0.0'
EVIDENCE_ARRAYS = ('packet_evidence', 'stream_evidence', 'http_evidence', 'field_evidence')
MAX_FIELD_RANGES = 64
MAX_FINDING_CANDIDATES = 64


def packet_metadata(frame, packet, reason):
    row = {name: getattr(frame, name) for name in (
        'frame_index', 'record_offset', 'data_offset', 'captured_length', 'wire_length',
        'timestamp', 'timestamp_resolution', 'linktype', 'interface_id', 'section_index', 'truncated')}
    row.update(evidence_id=f'frame_{frame.frame_index}', disposition='tcp_decoded' if packet else reason)
    if packet:
        row['tcp_datagram'] = {name: getattr(packet, name) for name in (
            'src', 'dst', 'sport', 'dport', 'seq', 'ack', 'flags', 'network_protocol',
            'network_offset', 'payload_offset', 'ipv4_checksum', 'tcp_checksum', 'reassembled_fragments')}
        row['tcp_datagram']['payload_length'] = len(packet.payload)
    return row


def stream_rows(stream_id, flow_id, direction, assembled, packets):
    """One bounded row per source interval, rather than an unbounded nested list."""
    yield dict(evidence_id=stream_id, row_type='stream', stream_id=stream_id, flow_id=flow_id,
               direction=list(direction), base_seq=assembled.base_seq,
               safe_prefix_length=len(assembled.safe_prefix), unsafe=assembled.unsafe,
               diagnostics=list(assembled.diagnostics),
               syn_observed=any(p.flags & 2 for p in packets),
               fin_observed=any(p.flags & 1 for p in packets),
               rst_observed=any(p.flags & 4 for p in packets),
               boundary_quality='observations_only_completeness_unknown')
    for index, item in enumerate(assembled.source_ranges):
        source = item.source
        yield dict(evidence_id=f'{stream_id}_range_{index}', row_type='source_range',
                   stream_id=stream_id, flow_id=flow_id,
                   stream_start=item.stream_start, stream_end=item.stream_end,
                   tcp_seq_start=item.tcp_seq_start, tcp_seq_end=item.tcp_seq_end,
                   frame_id=f'frame_{source.frame_index}', frame_index=source.frame_index,
                   frame_start=source.frame_start, frame_end=source.frame_end,
                   file_start=None if source.data_offset is None else source.data_offset+source.frame_start,
                   file_end=None if source.data_offset is None else source.data_offset+source.frame_end,
                   granularity='exact_raw_range')


def field_metadata(message_id, stream_id, fields, sources, safe_location):
    if len(fields) != len(sources):
        raise ValueError('Field evidence must align with extraction')
    rows = []
    by_location = {}
    for index, ((location, _value), source) in enumerate(zip(fields, sources)):
        item = dict(source)
        if len(item['stream_ranges']) > MAX_FIELD_RANGES:
            # The message remains resolvable. Never silently drop dependencies
            # while leaving an exact or transformed-field claim behind.
            item.update(stream_ranges=[], granularity='message_level_only',
                        limitations=item['limitations'] + ['field_source_range_limit'])
        field_id = f'{message_id}_field_{index}'
        item.update(evidence_id=field_id, field_id=field_id, http_message_id=message_id,
                    stream_id=stream_id, field_index=index, location=safe_location(location))
        rows.append(item)
        by_location.setdefault(location, []).append(field_id)
    return rows, by_location


def attach_finding_evidence(entry, message_id, fields_by_location, field_count):
    """ML supplies decoded spans; legacy rules only identify candidate fields."""
    index = entry.get('field_index')
    result = {'http_message_id': message_id, 'scope': 'field', 'raw_detection_span': 'unavailable'}
    if type(index) is int and 0 <= index < field_count:
        result['field_ids'] = [f'{message_id}_field_{index}']
        result['decoded_text_span'] = {'start': entry['span_start'], 'end': entry['span_end']}
        result['limitations'] = ['decoded_character_offsets_are_not_capture_byte_offsets']
    else:
        candidates = fields_by_location.get(entry['location'], [])
        result['field_ids'] = candidates if len(candidates) <= MAX_FINDING_CANDIDATES else []
        result['scope'] = 'candidate_fields' if result['field_ids'] else 'message'
        result['limitations'] = ['rule_detector_does_not_supply_a_decoded_span']
        if len(candidates) != 1:
            result['limitations'].append('field_identity_ambiguous')
    entry['evidence'] = result
