"""Hand-written annotations for the 12-conversation VP showcase capture (a *demonstration*, not an independent benchmark).

The showcase was designed by the TRACE team to exercise the pipeline, so annotating it demonstrates the evaluator on a
familiar file; it says little about general accuracy. The annotation table below was written by hand from the scenario
definitions in examples/generate_showcase.py (it lists values the scenarios insert) - never from detector output.
Only the listed fields are annotated (annotation_scope = listed_fields_only).

Usage: python scripts/groundtruth/build_showcase_manifest.py [output_manifest.json]
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'examples'))
import generate_showcase as showcase  # noqa: E402

# (scenario index, location, field text, gold label or None for a deliberate negative, category)
ANNOTATIONS = (
    (0, 'json_body.shipping.recipient', 'Priyanka Venkataraman', 'PERSON_NAME', 'positive:request'),
    (0, 'json_body.audit.actor', 'night_owl_77', 'USERNAME', 'positive:request'),
    (1, 'json_body.username', 'violet_dev22', 'USERNAME', 'positive:request'),
    (2, 'json_body.full_name', 'Alex Example', 'PERSON_NAME', 'positive:request'),
    (3, 'json_body.order.currency', 'AUD', None, 'hard_negative:identifier_lookalike'),
    (4, 'form.full_name', 'Fatima Khan', 'PERSON_NAME', 'positive:request'),
    (5, 'json_body.audit.actor', 'night_owl_77', 'USERNAME', 'positive:request'),
    (6, 'json_body.shipping.recipient', 'Priyanka Venkataraman', 'PERSON_NAME', 'positive:request'),
    (8, 'json_body.invoice.billed_to', 'Johnson & Johnson', None, 'hard_negative:company_name'),
    (9, 'json_body.geo.place', 'Madison', None, 'hard_negative:given_name_lookalike'),
    (10, 'json_body.username', 'robot_test_44', 'USERNAME', 'positive:request'),
    (11, 'json_body.user', 'night_owl_77', 'USERNAME', 'positive:request'),
)


def build() -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        pcap = Path(tmp) / 'showcase.pcap'
        showcase.write_pcap(pcap)
        data = pcap.read_bytes()
    fields = []
    for n, (index, location, text, label, category) in enumerate(ANNOTATIONS, 1):
        fields.append({
            'field_id': f'show{n:02d}',
            'flow': {'client': f'{showcase.CLIENT}{10 + index}:{42000 + index}', 'server': f'{showcase.SERVER}{20 + index % 3}:80'},
            'message': {'type': 'request', 'ordinal': 1}, 'location': location,
            'text_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(), 'text_length': len(text),
            'spans': [{'start': 0, 'end': len(text), 'label': label}] if label else [], 'category': category})
    return {
        'schema_version': 'trace-ground-truth/1',
        'dataset': {
            'name': 'TRACE VP showcase (hand-designed demonstration)', 'kind': 'hand_designed_demonstration',
            'description': ('Hand annotations over the 12-conversation showcase the TRACE team designed. A demonstration of the '
                            'evaluator on a familiar file, NOT an independent benchmark and NOT evidence of general accuracy.'),
            'created': '2025-06-02', 'synthetic': True,
            'provenance': {'label_source': 'human_annotation', 'labels_derived_from_model_output': False, 'annotators': 1,
                           'generator': 'scripts/groundtruth/build_showcase_manifest.py',
                           'notes': 'Written by hand from scenario definitions; only the listed fields are annotated.'}},
        'capture': {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)},
        'labels': ['PERSON_NAME', 'USERNAME'], 'annotation_scope': 'listed_fields_only', 'fields': fields}


if __name__ == '__main__':
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'examples/groundtruth/showcase_demo.manifest.json'
    target.write_text(json.dumps(build(), ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    print(target)
