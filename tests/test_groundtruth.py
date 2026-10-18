"""Ground-truth manifest validation and the exact-span evaluator.

Small hand-computed cases use deterministic detector doubles so every expected count can be derived by hand; the committed
controlled fixture is checked for reproducibility and (with the real V2 ensemble, when available) against the committed result.
"""
import copy
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from packet_pii.engine import analyze
from packet_pii.groundtruth import (EVAL_LABELS, EvaluationCollector, EvaluationRejected, ManifestError, evaluate_capture,
                                    export_result, load_manifest, parse_manifest, prf, sha256_file, text_sha256)
from packet_pii.hybrid import InferenceError
from packet_pii.ml import EntityLabel, EntitySpan, ScoreType
from packet_pii.ml_runner import MLWorkBudget
from test_vp_qa_support import build_pcap, conversation, ok_response, post_json, v2_detector

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / 'examples' / 'groundtruth'
CLIENT, SERVER = '192.0.2.10:43000', '198.51.100.20:80'

BODY = {'full_name': 'Alex Example', 'note': 'Please contact Alex Example today', 'handle': 'night_owl_77',
        'company': 'Harborview Ltd', 'username': 'kestrel_moss19', 'other': 'plain text'}
# (location, gold spans) - gold constructed by hand from BODY
GOLD = {'json_body.full_name': [(0, 12, 'PERSON_NAME')], 'json_body.note': [(15, 27, 'PERSON_NAME')],
        'json_body.handle': [(0, 12, 'USERNAME')], 'json_body.company': [], 'json_body.username': [(0, 14, 'USERNAME')],
        'json_body.other': []}


class Scripted:
    """Detector double: predictions are scripted per exact field text, independent of any real model."""
    model_version = 'scripted-1'
    SCRIPT = {'Alex Example': [(0, 12, 'PERSON_NAME')],                       # exact, same span as the rule finding
              'Please contact Alex Example today': [(15, 22, 'PERSON_NAME')],  # boundary mismatch
              'night_owl_77': [(0, 12, 'PERSON_NAME')],                        # right span, wrong label
              'Harborview Ltd': [(0, 10, 'PERSON_NAME')]}                      # false positive in a negative field

    def __init__(self, fail=False):
        self.fail, self.seen = fail, []

    def predict_fields(self, fields):
        if self.fail:
            raise RuntimeError('model exploded')
        self.seen += [f.text for f in fields]
        return [EntitySpan(f.field_index, EntityLabel(label), s, e, self.model_version, .9, ScoreType.UNCALIBRATED_MODEL_SCORE)
                for f in fields for s, e, label in self.SCRIPT.get(f.text, [])]


def manifest_doc(capture: Path, gold=GOLD, body=BODY, scope='listed_fields_only', **dataset):
    fields = []
    for n, (location, spans) in enumerate(gold.items(), 1):
        text = body[location.split('.', 1)[1]]
        fields.append({'field_id': f'g{n:02d}', 'flow': {'client': CLIENT, 'server': SERVER},
                       'message': {'type': 'request', 'ordinal': 1}, 'location': location,
                       'text_sha256': text_sha256(text), 'text_length': len(text), 'category': 'positive' if spans else 'hard_negative:test',
                       'spans': [{'start': a, 'end': b, 'label': l} for a, b, l in spans]})
    return {'schema_version': 'trace-ground-truth/1',
            'dataset': {'name': 'unit test case', 'kind': 'controlled_synthetic_fixture', 'description': 'hand-computed',
                        'created': '2025-06-02', 'synthetic': True,
                        'provenance': {'label_source': 'constructed_by_generator', 'labels_derived_from_model_output': False}, **dataset},
            'capture': {'sha256': sha256_file(capture), 'bytes': capture.stat().st_size},
            'labels': ['PERSON_NAME', 'USERNAME'], 'annotation_scope': scope, 'fields': fields}


def raw(doc):
    return json.dumps(doc, ensure_ascii=False).encode('utf-8')


@pytest.fixture
def case(tmp_path):
    path = build_pcap(tmp_path / 'case.pcap', [conversation(0, post_json(BODY), ok_response())])
    return path, manifest_doc(path)


# ------------------------------------------------------------------ manifest validation
def test_committed_fixture_manifest_is_valid_and_bound_to_its_capture():
    manifest = load_manifest(FIXTURE_DIR / 'controlled_fixture_v1.manifest.json')
    assert manifest.capture_sha256 == sha256_file(FIXTURE_DIR / 'controlled_fixture_v1.pcap')
    public = manifest.public()
    assert public['labels_derived_from_model_output'] is False and public['label_source'] == 'constructed_by_generator'
    assert (public['fields'], public['gold_spans']) == (740, 64) and public['positive_fields'] + public['negative_fields'] == 740
    assert public['negative_fields'] > 10 * public['positive_fields'] / 2                  # negatives dominate, as in real traffic


def test_committed_fixture_is_reproducible_from_the_generator(tmp_path):
    sys.path.insert(0, str(ROOT / 'examples'))
    import generate_groundtruth_fixture as generator
    pcap, manifest = generator.generate(tmp_path)
    for produced in (pcap, manifest):
        assert produced.read_bytes() == (FIXTURE_DIR / produced.name).read_bytes(), produced.name


def test_generator_has_no_dependency_on_trace_or_any_model():
    source = (ROOT / 'examples' / 'generate_groundtruth_fixture.py').read_text(encoding='utf-8')
    assert 'packet_pii' not in source and 'torch' not in source


def test_python_validator_and_json_schema_agree_on_the_committed_manifest():
    jsonschema = pytest.importorskip('jsonschema')
    schema = json.loads((ROOT / 'schemas' / 'ground-truth-v1.schema.json').read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    document = json.loads((FIXTURE_DIR / 'controlled_fixture_v1.manifest.json').read_text())
    jsonschema.validate(document, schema)
    parse_manifest(raw(document))


def mutations():
    yield 'unknown_top_level', lambda d: d.__setitem__('extra', 1)
    yield 'wrong_version', lambda d: d.__setitem__('schema_version', 'trace-ground-truth/2')
    yield 'model_derived_labels', lambda d: d['dataset']['provenance'].__setitem__('labels_derived_from_model_output', True)
    yield 'missing_attestation', lambda d: d['dataset']['provenance'].pop('labels_derived_from_model_output')
    yield 'bad_kind', lambda d: d['dataset'].__setitem__('kind', 'model_output')
    yield 'bad_label_source', lambda d: d['dataset']['provenance'].__setitem__('label_source', 'model_predictions')
    yield 'human_without_annotators', lambda d: d['dataset']['provenance'].__setitem__('label_source', 'human_annotation')
    yield 'bad_capture_hash', lambda d: d['capture'].__setitem__('sha256', 'ABC')
    yield 'unsupported_label', lambda d: d.__setitem__('labels', ['EMAIL'])
    yield 'duplicate_labels', lambda d: d.__setitem__('labels', ['USERNAME', 'USERNAME'])
    yield 'bad_scope', lambda d: d.__setitem__('annotation_scope', 'everything')
    yield 'no_fields', lambda d: d.__setitem__('fields', [])
    yield 'span_past_end', lambda d: d['fields'][0]['spans'][0].__setitem__('end', 999)
    yield 'empty_span', lambda d: d['fields'][0]['spans'][0].__setitem__('end', 0)
    yield 'span_label_outside_manifest_labels', lambda d: (d.__setitem__('labels', ['USERNAME']))
    yield 'overlapping_spans', lambda d: d['fields'][0]['spans'].append({'start': 5, 'end': 8, 'label': 'USERNAME'})
    yield 'duplicate_field_id', lambda d: d['fields'][1].__setitem__('field_id', d['fields'][0]['field_id'])
    yield 'duplicate_address', lambda d: d['fields'][1].update(location=d['fields'][0]['location'])
    yield 'bad_ip', lambda d: d['fields'][0]['flow'].__setitem__('client', 'not-an-ip:80')
    yield 'bad_port', lambda d: d['fields'][0]['flow'].__setitem__('server', '198.51.100.20:99999')
    yield 'bad_message_type', lambda d: d['fields'][0]['message'].__setitem__('type', 'trailer')
    yield 'zero_ordinal', lambda d: d['fields'][0]['message'].__setitem__('ordinal', 0)
    yield 'bad_text_hash', lambda d: d['fields'][0].__setitem__('text_sha256', 'f' * 63)
    yield 'unknown_field_property', lambda d: d['fields'][0].__setitem__('predicted', [])
    yield 'long_location', lambda d: d['fields'][0].__setitem__('location', 'x' * 1025)
    yield 'bad_category', lambda d: d['fields'][0].__setitem__('category', 'has space')


@pytest.mark.parametrize('name,mutate', list(mutations()), ids=[n for n, _ in mutations()])
def test_invalid_manifests_are_rejected(case, name, mutate):
    _, doc = case
    doc = copy.deepcopy(doc)
    mutate(doc)
    with pytest.raises(ManifestError):
        parse_manifest(raw(doc))


@pytest.mark.parametrize('payload', [b'', b'not json', b'[]', b'{"schema_version": NaN}', b'\xff\xfe', b'{' * 5000])
def test_non_manifest_payloads_are_rejected(payload):
    with pytest.raises(ManifestError):
        parse_manifest(payload)


def test_json_schema_rejects_the_schema_expressible_mutations(case):
    jsonschema = pytest.importorskip('jsonschema')
    schema = json.loads((ROOT / 'schemas' / 'ground-truth-v1.schema.json').read_text())
    expressible = {'unknown_top_level', 'wrong_version', 'model_derived_labels', 'missing_attestation', 'bad_kind', 'bad_label_source',
                   'bad_capture_hash', 'unsupported_label', 'duplicate_labels', 'bad_scope', 'no_fields', 
                   'zero_ordinal', 'bad_message_type', 'bad_text_hash', 'unknown_field_property', 'long_location', 'bad_category'}
    _, doc = case
    jsonschema.validate(doc, schema)
    for name, mutate in mutations():
        if name in expressible:
            broken = copy.deepcopy(doc)
            mutate(broken)
            assert list(jsonschema.Draft202012Validator(schema).iter_errors(broken)), name


# ------------------------------------------------------------------ metric arithmetic
def test_prf_handles_zero_denominators_without_inventing_numbers():
    assert prf(0, 0, 0)['precision'] is None and prf(0, 0, 0)['recall'] is None and prf(0, 0, 0)['f1'] is None
    no_predictions = prf(0, 0, 3)
    assert (no_predictions['precision'], no_predictions['recall'], no_predictions['f1']) == (None, 0.0, None)
    assert any('precision' in note for note in no_predictions['undefined'])
    no_gold = prf(0, 4, 0)
    assert (no_gold['precision'], no_gold['recall'], no_gold['f1']) == (0.0, None, None)
    assert prf(0, 2, 2)['f1'] == 0.0                                                  # both defined and zero: F1 is a real 0
    assert prf(3, 1, 1) == {**prf(3, 1, 1), 'precision': 0.75, 'recall': 0.75, 'f1': 0.75}
    assert prf(5, 0, 0)['precision'] == 1.0 and prf(5, 0, 0)['recall'] == 1.0
    ci = prf(8, 2, 2)['precision_ci95']
    assert 0 < ci[0] < 0.8 < ci[1] < 1


# ------------------------------------------------------------------ hand-computed evaluation
def run(case, detector=None, **kw):
    path, doc = case
    return evaluate_capture(path, parse_manifest(raw(doc)), detector=detector, **kw)


def test_rules_only_evaluation_matches_hand_counts(case):
    result = run(case)
    assert result['status'] == 'complete' and list(result['systems']) == ['rules_only']
    system = result['systems']['rules_only']
    assert (system['micro']['tp'], system['micro']['fp'], system['micro']['fn']) == (2, 0, 2)
    assert system['scored_fields'] == 6 and system['gold_spans_scored'] == 4
    assert system['per_label']['PERSON_NAME']['tp'] == 1 and system['per_label']['USERNAME']['tp'] == 1
    assert result['analysis']['ml_coverage_status'] == 'not_requested' and result['model_version'] is None


def test_model_only_rules_only_and_combined_match_hand_counts_without_double_counting(case):
    result = run(case, Scripted())
    systems = result['systems']
    model, combined = systems['model_only'], systems['rules_plus_model']
    assert (model['micro']['tp'], model['micro']['fp'], model['micro']['fn']) == (1, 3, 3)
    assert model['micro']['precision'] == 0.25 and model['micro']['recall'] == 0.25 and model['micro']['f1'] == 0.25
    pn, un = model['per_label']['PERSON_NAME'], model['per_label']['USERNAME']
    assert (pn['tp'], pn['fp'], pn['fn']) == (1, 3, 1)             # note, handle (wrong label) and company are PERSON_NAME FPs
    assert (un['tp'], un['fp'], un['fn'], un['precision'], un['recall'], un['f1']) == (0, 0, 2, None, 0.0, None)
    assert model['macro']['labels_averaged'] == ['PERSON_NAME', 'USERNAME'] and model['macro']['precision'] is None
    assert model['error_breakdown'] == {'false_positive': {'boundary_mismatch': 1, 'negative_field': 1, 'wrong_label': 1},
                                        'false_negative': {'boundary_mismatch': 1, 'missed': 1, 'wrong_label': 1}}
    # combined: the identical full_name span from rule AND model counts once; the rule recovers the missed username
    assert (combined['micro']['tp'], combined['micro']['fp'], combined['micro']['fn']) == (2, 3, 2)
    assert combined['true_positives_by_detector'] == {'bilstm+rule': 1, 'rule': 1}
    assert systems['rules_only']['micro']['tp'] == 2
    # negative fields contribute false positives
    assert model['negative_fields'] == {'scored': 2, 'with_false_positive': 1, 'by_category': {'hard_negative:test': {'scored': 2, 'with_false_positive': 1}}}
    assert result['status'] == 'complete' and result['model_version'] == 'scripted-1'


def test_error_samples_are_offsets_and_field_ids_only(case):
    result = run(case, Scripted())
    text = json.dumps(result)
    for secret in ('Alex Example', 'night_owl_77', 'kestrel_moss19', 'Harborview', 'contact Alex'):
        assert secret not in text
    sample = result['systems']['model_only']['error_samples'][0]
    assert set(sample) <= {'error', 'type', 'field_id', 'label', 'predicted_span', 'gold_span', 'detectors'}
    assert all(isinstance(v, (str, list)) for v in sample.values())
    assert 'json_body' not in text                                                    # locations are never exported


def test_model_budget_skips_make_the_result_partial_and_unscored(case):
    result = run(case, Scripted(), ml_budget=MLWorkBudget(max_fields=2))
    assert result['status'] == 'partial' and 'NOT full-file accuracy' in result['scope']
    model = result['systems']['model_only']
    assert model['unscored_fields']['skipped:field_budget'] > 0 and model['scored_fields'] < 6
    assert result['systems']['rules_only']['scored_fields'] == 6 and result['systems']['rules_only']['unscored_fields'] == {}
    assert result['analysis']['ml_coverage_status'] == 'partial' and result['analysis']['analysis_incomplete'] is True
    skipped = model['unscored_fields']['skipped:field_budget']
    assert model['scored_fields'] + skipped == 6


def test_policy_excluded_fields_are_scored_as_model_misses_not_hidden(tmp_path):
    body = {'full_name': 'Alex Example'}
    request = post_json(body, extra_headers=b'X-Customer-Name: Blake Fictional\r\n')
    path = build_pcap(tmp_path / 'h.pcap', [conversation(0, request, ok_response())])
    doc = manifest_doc(path, gold={'json_body.full_name': [(0, 12, 'PERSON_NAME')]}, body=body)
    doc['fields'].append({'field_id': 'hdr', 'flow': {'client': CLIENT, 'server': SERVER}, 'message': {'type': 'request', 'ordinal': 1},
                          'location': 'header.x-customer-name', 'text_sha256': text_sha256('Blake Fictional'), 'text_length': 15,
                          'spans': [{'start': 0, 'end': 15, 'label': 'PERSON_NAME'}], 'category': 'positive:header'})
    result = evaluate_capture(path, parse_manifest(raw(doc)), detector=Scripted())
    model = result['systems']['model_only']
    assert model['error_breakdown']['false_negative'] == {'excluded_by_policy': 1}
    assert result['systems']['rules_only']['error_breakdown']['false_negative'] == {'missed': 1}


def test_unannotated_fields_make_an_exhaustive_manifest_partial(case):
    path, doc = case
    doc = copy.deepcopy(doc)
    doc['annotation_scope'] = 'all_fields_in_listed_messages'
    result = evaluate_capture(path, parse_manifest(raw(doc)))
    assert result['status'] == 'partial' and result['alignment']['unannotated_fields_in_listed_messages'] > 0


# ------------------------------------------------------------------ binding and alignment
def test_capture_hash_mismatch_is_rejected_before_analysis(case, tmp_path):
    path, doc = case
    other = build_pcap(tmp_path / 'other.pcap', [conversation(0, post_json({**BODY, 'other': 'changed'}), ok_response())])
    with pytest.raises(EvaluationRejected, match='SHA-256'):
        evaluate_capture(other, parse_manifest(raw(doc)))
    doc = copy.deepcopy(doc)
    doc['capture']['bytes'] += 1
    collector = EvaluationCollector(parse_manifest(raw(doc)))
    with pytest.raises(EvaluationRejected, match='size'):
        collector.finish(capture_sha256=doc['capture']['sha256'], capture_bytes=doc['capture']['bytes'] - 1, summary={}, metadata={}, model_requested=False)


def test_unaligned_fields_are_counted_and_mark_the_result_partial(case):
    path, doc = case
    doc = copy.deepcopy(doc)
    doc['fields'][0]['text_sha256'] = '0' * 64                                    # annotation describes different text
    doc['fields'][1]['location'] = 'json_body.nonexistent'                         # field not present
    doc['fields'][2]['message']['ordinal'] = 9                                     # message not present
    result = evaluate_capture(path, parse_manifest(raw(doc)))
    assert result['status'] == 'partial'
    assert result['alignment']['unaligned'] == {'text_mismatch': 1, 'field_not_found': 1, 'message_not_found': 1}
    assert result['alignment']['aligned'] == 3 and result['systems']['rules_only']['scored_fields'] == 3


def test_nothing_alignable_is_rejected(case):
    path, doc = case
    doc = copy.deepcopy(doc)
    for entry in doc['fields']:
        entry['flow']['client'] = '192.0.2.99:1'
    with pytest.raises(EvaluationRejected, match='no manifest field'):
        evaluate_capture(path, parse_manifest(raw(doc)))


def test_repeated_locations_use_the_occurrence_index(tmp_path):
    request = post_json(b'{"names":["Alex Example","Blake Fictional"]}')
    path = build_pcap(tmp_path / 'r.pcap', [conversation(0, request, ok_response())])
    fields = []
    for n, text in enumerate(('Alex Example', 'Blake Fictional')):
        fields.append({'field_id': f'r{n}', 'flow': {'client': CLIENT, 'server': SERVER}, 'message': {'type': 'request', 'ordinal': 1},
                       'location': f'json_body.names[{n}]', 'text_sha256': text_sha256(text), 'text_length': len(text),
                       'spans': [{'start': 0, 'end': len(text), 'label': 'PERSON_NAME'}]})
    doc = manifest_doc(path, gold={'json_body.full_name': []}, body={'full_name': 'x'})
    doc['fields'] = fields
    result = evaluate_capture(path, parse_manifest(raw(doc)), detector=Scripted())
    assert result['alignment']['aligned'] == 2


def test_two_requests_in_one_session_are_addressed_by_ordinal(tmp_path):
    first, second = post_json({'cart': 'c-1'}), post_json({'owner': 'Alex Example'})
    request = first + second
    path = build_pcap(tmp_path / 'k.pcap', [conversation(0, request, ok_response() + ok_response())])
    doc = manifest_doc(path, gold={'json_body.owner': [(0, 12, 'PERSON_NAME')]}, body={'owner': 'Alex Example'})
    doc['fields'][0]['message']['ordinal'] = 2
    result = evaluate_capture(path, parse_manifest(raw(doc)), detector=Scripted())
    assert result['alignment']['aligned'] == 1 and result['systems']['model_only']['micro']['tp'] == 1
    doc['fields'][0]['message']['ordinal'] = 1                                      # the first request has no such field
    with pytest.raises(EvaluationRejected):
        evaluate_capture(path, parse_manifest(raw(doc)), detector=Scripted())


# ------------------------------------------------------------------ independence and failure handling
def test_reference_labels_do_not_change_with_the_detector(case):
    """The evaluator never derives labels from predictions: different detectors give different scores, identical gold."""
    a = run(case, Scripted())
    perfect = Scripted()
    perfect.SCRIPT = {'Alex Example': [(0, 12, 'PERSON_NAME')], 'Please contact Alex Example today': [(15, 27, 'PERSON_NAME')],
                      'night_owl_77': [(0, 12, 'USERNAME')], 'kestrel_moss19': [(0, 14, 'USERNAME')]}
    b = run(case, perfect)
    assert a['systems']['model_only']['gold_spans_scored'] == b['systems']['model_only']['gold_spans_scored'] == 4
    assert b['systems']['model_only']['micro']['f1'] == 1.0 and a['systems']['model_only']['micro']['f1'] == 0.25
    assert b['systems']['model_only']['error_breakdown'] == {'false_positive': {}, 'false_negative': {}}


def test_a_model_failure_produces_no_evaluation(case):
    with pytest.raises(InferenceError):
        run(case, Scripted(fail=True))


def test_result_records_provenance_versions_and_hashes(case):
    path, doc = case
    result = run(case, Scripted())
    assert result['schema_version'] == 'trace-ground-truth-evaluation/1'
    assert result['capture']['sha256'] == sha256_file(path) and result['capture']['verified_against_manifest'] is True
    assert result['manifest']['sha256'] == hashlib.sha256(raw(doc)).hexdigest() and result['manifest']['verified'] is True
    assert result['manifest']['label_source'] == 'constructed_by_generator'
    assert result['analysis_version']['engine'] == 'pcap-pii-engine' and result['ml_work_limits']['profile'] == 'standard'
    assert result['generated_at'].endswith('+00:00') and result['notes']
    assert set(EVAL_LABELS) == {'PERSON_NAME', 'USERNAME'}


def test_export_is_private_and_does_not_overwrite(case, tmp_path):
    result = run(case)
    target = tmp_path / 'evaluation.json'
    export_result(result, target)
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600 and json.loads(target.read_text())['status'] == 'complete'
    with pytest.raises(FileExistsError):
        export_result(result, target)
    export_result(result, target, overwrite=True)


def test_evaluation_is_deterministic(case):
    strip = lambda r: {k: v for k, v in r.items() if k != 'generated_at'}
    assert strip(run(case, Scripted())) == strip(run(case, Scripted()))


# ------------------------------------------------------------------ real fixture
def fixture_paths():
    return FIXTURE_DIR / 'controlled_fixture_v1.pcap', load_manifest(FIXTURE_DIR / 'controlled_fixture_v1.manifest.json')


def test_fixture_rules_only_evaluation_is_complete_and_fully_aligned():
    pcap, manifest = fixture_paths()
    result = evaluate_capture(pcap, manifest)
    assert result['status'] == 'complete' and result['alignment']['aligned'] == 740
    assert result['alignment']['unannotated_fields_in_listed_messages'] == 0 and result['alignment']['unaligned'] == {}
    assert result['analysis']['analysis_incomplete'] is False


def test_fixture_v2_evaluation_reproduces_the_committed_result():
    committed = json.loads((ROOT / 'docs/ml/results/groundtruth_controlled_v1_v2.json').read_text())
    pcap, manifest = fixture_paths()
    result = evaluate_capture(pcap, manifest, detector=v2_detector())
    assert result['status'] == committed['status'] == 'complete' and result['model_version'] == committed['model_version']
    assert result['manifest']['sha256'] == committed['manifest']['sha256'] and result['capture']['sha256'] == committed['capture']['sha256']
    for name in ('rules_only', 'model_only', 'rules_plus_model'):
        now, then = result['systems'][name], committed['systems'][name]
        assert now['scored_fields'] == then['scored_fields'] and now['gold_spans_scored'] == then['gold_spans_scored']
        for key in ('tp', 'fp', 'fn'):
            assert abs(now['micro'][key] - then['micro'][key]) <= 1, (name, key)       # tolerate one borderline span across platforms
        assert abs(now['micro']['f1'] - then['micro']['f1']) < 0.03, name


def showcase_capture(tmp_path):
    sys.path.insert(0, str(ROOT / 'examples'))
    import generate_showcase
    path = tmp_path / 'showcase.pcap'
    generate_showcase.write_pcap(path)
    return path


def test_showcase_demo_manifest_is_labelled_a_demonstration_and_binds_to_the_generated_capture(tmp_path):
    manifest = load_manifest(FIXTURE_DIR / 'showcase_demo.manifest.json')
    assert manifest.kind == 'hand_designed_demonstration' and 'NOT an independent benchmark' in manifest.description
    result = evaluate_capture(showcase_capture(tmp_path), manifest)
    assert result['status'] == 'complete' and result['alignment']['aligned'] == 12 == result['alignment']['manifest_fields']
    assert result['manifest']['kind'] == 'hand_designed_demonstration' and result['manifest']['annotation_scope'] == 'listed_fields_only'


def test_showcase_demo_v2_evaluation_reproduces_the_committed_result(tmp_path):
    committed = json.loads((ROOT / 'docs/ml/results/groundtruth_showcase_demo_v2.json').read_text())
    result = evaluate_capture(showcase_capture(tmp_path), load_manifest(FIXTURE_DIR / 'showcase_demo.manifest.json'), detector=v2_detector())
    assert result['capture']['sha256'] == committed['capture']['sha256'] and result['manifest']['sha256'] == committed['manifest']['sha256']
    for name in ('rules_only', 'model_only', 'rules_plus_model'):
        for key in ('tp', 'fp', 'fn'):
            assert abs(result['systems'][name]['micro'][key] - committed['systems'][name]['micro'][key]) <= 1, (name, key)
