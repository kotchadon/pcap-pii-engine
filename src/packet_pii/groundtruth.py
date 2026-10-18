"""File-specific ground-truth evaluation: validated manifests and an exact-span evaluator.

A manifest is an *independent* statement of which spans in which decoded HTTP fields of one capture are PERSON_NAME or
USERNAME. The evaluator compares TRACE's detections against it. Reference labels come only from the manifest, never from a
detector's output, and the result states exactly what was scored, what could not be scored and why.

Design rules enforced here:
  * the manifest is bound to the capture by SHA-256 and to every field by a SHA-256 of its decoded text;
  * a field that could not be aligned, or that the model was never allowed to see (a budget skip), is *unscored* and the
    result is ``partial`` - partial metrics are never presented as full-file accuracy;
  * negative fields (empty span list) contribute false positives; unmatched out-of-scope detections are counted by type only;
  * the exported result contains hashes, counts, field ids and offsets - never raw field text, values or locations.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 'trace-ground-truth/1'
RESULT_SCHEMA_VERSION = 'trace-ground-truth-evaluation/1'
EVAL_LABELS = ('PERSON_NAME', 'USERNAME')
KINDS = ('controlled_synthetic_fixture', 'hand_designed_demonstration', 'human_annotated_capture')
LABEL_SOURCES = ('constructed_by_generator', 'human_annotation')
MAX_MANIFEST_BYTES = 16 * 2**20
MAX_FIELDS = 100_000
MAX_ERROR_SAMPLES = 500
# Rule findings that map onto the evaluated labels. Key-based rules cover the whole field value.
_RULE_LABELS = {'USERNAME': 'USERNAME', 'PERSON_NAME_CANDIDATE': 'PERSON_NAME'}
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_ID = re.compile(r'[A-Za-z0-9_.-]{1,64}\Z')
_CATEGORY = re.compile(r'[A-Za-z0-9_.:-]{1,64}\Z')
_ENDPOINT = re.compile(r'(.{2,45}):([0-9]{1,5})\Z')

NOTES = (
    'Metrics describe this capture and these annotations only; they are not a general accuracy claim for TRACE or the model.',
    'Spans are matched exactly (same field, label, start and end in code points); near-misses count as an error.',
    'Confidence intervals are Wilson binomial intervals that treat spans as independent; no F1 interval is computed.',
    'Rule findings for USERNAME and PERSON_NAME_CANDIDATE cover the whole field value and are scored as whole-field spans.',
)


class ManifestError(ValueError):
    """The manifest is malformed or inconsistent; nothing is evaluated."""


class EvaluationRejected(ValueError):
    """The manifest cannot be applied to this capture (for example a SHA-256 mismatch)."""


# ------------------------------------------------------------------------------------------------ manifest
@dataclass(frozen=True)
class GoldField:
    field_id: str
    message_key: tuple          # (client_ip, client_port, server_ip, server_port, session, message_type, ordinal)
    location: str
    occurrence: int
    text_sha256: str
    text_length: int
    spans: tuple                # sorted tuple of (start, end, label)
    category: str | None


@dataclass(frozen=True)
class Manifest:
    sha256: str
    name: str
    kind: str
    description: str
    created: str
    synthetic: bool
    provenance: dict
    capture_sha256: str
    capture_bytes: int | None
    labels: tuple
    annotation_scope: str
    fields: tuple

    def public(self) -> dict:
        return {'sha256': self.sha256, 'name': self.name, 'kind': self.kind, 'description': self.description,
                'created': self.created, 'synthetic': self.synthetic, 'labels': list(self.labels),
                'annotation_scope': self.annotation_scope, 'fields': len(self.fields),
                'positive_fields': sum(1 for f in self.fields if f.spans),
                'negative_fields': sum(1 for f in self.fields if not f.spans),
                'gold_spans': sum(len(f.spans) for f in self.fields),
                'label_source': self.provenance['label_source'], 'generator': self.provenance.get('generator'),
                'labels_derived_from_model_output': False}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def text_sha256(text: str) -> str:
    return sha256_bytes(text.encode('utf-8', 'surrogatepass'))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def _int(value, name: str, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, f'{name} must be an integer >= {minimum}')
    return value


def _str(value, name: str, low: int = 1, high: int = 2000) -> str:
    _require(isinstance(value, str) and low <= len(value) <= high, f'{name} must be a string of {low}..{high} characters')
    return value


def _endpoint(value, name: str) -> tuple:
    _require(isinstance(value, str), f'{name} must be "ip:port"')
    match = _ENDPOINT.fullmatch(value)
    _require(match is not None, f'{name} must be "ip:port"')
    host, port = match.group(1).strip('[]'), int(match.group(2))
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        raise ManifestError(f'{name} has an invalid IP address') from None
    _require(0 < port < 65536, f'{name} has an invalid port')
    return host, port


def _only(obj, allowed: set, name: str) -> None:
    _require(isinstance(obj, dict), f'{name} must be an object')
    extra = set(obj) - allowed
    _require(not extra, f'{name} has unknown properties: {sorted(extra)[:3]}')


def parse_manifest(raw: bytes) -> Manifest:
    """Validate manifest bytes strictly. Unknown properties are rejected so typos cannot silently change meaning."""
    _require(isinstance(raw, (bytes, bytearray)) and 0 < len(raw) <= MAX_MANIFEST_BYTES, 'manifest size is invalid')
    try:
        data = json.loads(bytes(raw).decode('utf-8'), parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ManifestError('manifest is not valid UTF-8 JSON') from None
    _only(data, {'schema_version', 'dataset', 'capture', 'labels', 'annotation_scope', 'fields'}, 'manifest')
    _require(data.get('schema_version') == SCHEMA_VERSION, f'schema_version must be "{SCHEMA_VERSION}"')

    dataset = data.get('dataset')
    _only(dataset, {'name', 'kind', 'description', 'created', 'synthetic', 'provenance'}, 'dataset')
    name = _str(dataset.get('name'), 'dataset.name', 1, 200)
    _require(dataset.get('kind') in KINDS, f'dataset.kind must be one of {KINDS}')
    description = _str(dataset.get('description', ''), 'dataset.description', 0, 2000)
    created = _str(dataset.get('created'), 'dataset.created', 10, 40)
    try:
        datetime.fromisoformat(created.replace('Z', '+00:00'))
    except ValueError:
        raise ManifestError('dataset.created must be an ISO-8601 date') from None
    _require(type(dataset.get('synthetic')) is bool, 'dataset.synthetic must be a boolean')
    provenance = dataset.get('provenance')
    _only(provenance, {'label_source', 'labels_derived_from_model_output', 'generator', 'annotators', 'notes'}, 'dataset.provenance')
    _require(provenance.get('label_source') in LABEL_SOURCES, f'provenance.label_source must be one of {LABEL_SOURCES}')
    _require(provenance.get('labels_derived_from_model_output') is False,
             'provenance.labels_derived_from_model_output must be false: model output cannot be reference truth')
    if 'generator' in provenance:
        _str(provenance['generator'], 'provenance.generator', 1, 200)
    if 'annotators' in provenance:
        _int(provenance['annotators'], 'provenance.annotators', 1)
    if 'notes' in provenance:
        _str(provenance['notes'], 'provenance.notes', 0, 2000)
    if provenance['label_source'] == 'human_annotation':
        _require('annotators' in provenance, 'human annotation requires provenance.annotators')

    capture = data.get('capture')
    _only(capture, {'sha256', 'bytes'}, 'capture')
    _require(isinstance(capture.get('sha256'), str) and _HEX64.fullmatch(capture['sha256']), 'capture.sha256 must be 64 lowercase hex characters')
    capture_bytes = _int(capture['bytes'], 'capture.bytes', 1) if 'bytes' in capture else None

    labels = data.get('labels')
    _require(isinstance(labels, list) and labels and all(l in EVAL_LABELS for l in labels) and len(set(labels)) == len(labels),
             f'labels must be a non-empty unique subset of {EVAL_LABELS}')
    _require(data.get('annotation_scope') in ('listed_fields_only', 'all_fields_in_listed_messages'),
             'annotation_scope must be "listed_fields_only" or "all_fields_in_listed_messages"')

    entries = data.get('fields')
    _require(isinstance(entries, list) and 1 <= len(entries) <= MAX_FIELDS, f'fields must hold 1..{MAX_FIELDS} entries')
    fields, ids, keys = [], set(), set()
    for n, entry in enumerate(entries):
        where = f'fields[{n}]'
        _only(entry, {'field_id', 'flow', 'message', 'location', 'occurrence', 'text_sha256', 'text_length', 'spans', 'category'}, where)
        field_id = entry.get('field_id')
        _require(isinstance(field_id, str) and _ID.fullmatch(field_id), f'{where}.field_id is invalid')
        _require(field_id not in ids, f'{where}.field_id is duplicated')
        ids.add(field_id)
        flow = entry.get('flow')
        _only(flow, {'client', 'server', 'session'}, f'{where}.flow')
        client, server = _endpoint(flow.get('client'), f'{where}.flow.client'), _endpoint(flow.get('server'), f'{where}.flow.server')
        session = _int(flow.get('session', 1), f'{where}.flow.session', 1)
        message = entry.get('message')
        _only(message, {'type', 'ordinal'}, f'{where}.message')
        _require(message.get('type') in ('request', 'response'), f'{where}.message.type must be request or response')
        ordinal = _int(message.get('ordinal'), f'{where}.message.ordinal', 1)
        location = _str(entry.get('location'), f'{where}.location', 1, 1024)
        occurrence = _int(entry.get('occurrence', 0), f'{where}.occurrence', 0)
        digest = entry.get('text_sha256')
        _require(isinstance(digest, str) and _HEX64.fullmatch(digest), f'{where}.text_sha256 must be 64 lowercase hex characters')
        length = _int(entry.get('text_length'), f'{where}.text_length', 1)
        category = entry.get('category')
        if category is not None:
            _require(isinstance(category, str) and _CATEGORY.fullmatch(category), f'{where}.category is invalid')
        spans = entry.get('spans')
        _require(isinstance(spans, list) and len(spans) <= 1000, f'{where}.spans must be a list')
        parsed = []
        for m, span in enumerate(spans):
            _only(span, {'start', 'end', 'label'}, f'{where}.spans[{m}]')
            start, end = _int(span.get('start'), f'{where}.spans[{m}].start'), _int(span.get('end'), f'{where}.spans[{m}].end')
            _require(start < end <= length, f'{where}.spans[{m}] must satisfy 0 <= start < end <= text_length')
            _require(span.get('label') in labels, f'{where}.spans[{m}].label must be one of the manifest labels')
            parsed.append((start, end, span['label']))
        parsed.sort()
        _require(all(a[1] <= b[0] for a, b in zip(parsed, parsed[1:])), f'{where}.spans must not overlap')
        message_key = (*client, *server, session, message['type'], ordinal)
        unique = (message_key, location, occurrence)
        _require(unique not in keys, f'{where} duplicates another field address')
        keys.add(unique)
        fields.append(GoldField(field_id, message_key, location, occurrence, digest, length, tuple(parsed), category))
    return Manifest(sha256_bytes(bytes(raw)), name, dataset['kind'], description, created, dataset['synthetic'], dict(provenance),
                    capture['sha256'], capture_bytes, tuple(labels), data['annotation_scope'], tuple(fields))


def load_manifest(path: str | Path) -> Manifest:
    source = Path(path)
    if source.stat().st_size > MAX_MANIFEST_BYTES:
        raise ManifestError('manifest is too large')
    return parse_manifest(source.read_bytes())


# ------------------------------------------------------------------------------------------------ metrics helpers
def _wilson(successes: int, total: int, z: float = 1.959964) -> list | None:
    if total <= 0:
        return None
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def prf(tp: int, fp: int, fn: int) -> dict:
    """Precision/recall/F1 with explicit handling of zero denominators (undefined is ``None``, never a made-up 0 or 1)."""
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    if precision is None or recall is None:
        f1 = None
    else:
        f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    undefined = []
    if precision is None:
        undefined.append('precision: no predictions (TP + FP = 0)')
    if recall is None:
        undefined.append('recall: no gold spans (TP + FN = 0)')
    if f1 is None and not undefined:
        undefined.append('f1: undefined')
    return {'tp': tp, 'fp': fp, 'fn': fn,
            'precision': None if precision is None else round(precision, 4),
            'recall': None if recall is None else round(recall, 4),
            'f1': None if f1 is None else round(f1, 4),
            'precision_ci95': _wilson(tp, tp + fp), 'recall_ci95': _wilson(tp, tp + fn),
            'undefined': undefined}


def _overlap(a: tuple, b: tuple) -> bool:
    return a[0] < b[1] and b[0] < a[1]


# ------------------------------------------------------------------------------------------------ collector
class EvaluationCollector:
    """Receives engine callbacks for the manifest's messages only and keeps hashes, never raw text."""

    def __init__(self, manifest: Manifest):
        self.manifest = manifest
        self._wanted = {f.message_key for f in manifest.fields}
        self._messages: dict[tuple, dict] = {}
        self._by_id: dict[str, tuple] = {}
        self._dispositions: dict[tuple, str] = {}
        self._model: list[tuple] = []           # (message_id, field_index, label, start, end)
        self.out_of_scope_rules: Counter = Counter()
        self.out_of_scope_model: Counter = Counter()
        self.observed_messages = 0

    # engine field_observer
    def observe_message(self, info: dict) -> None:
        self.observed_messages += 1
        key = (*info['client'], *info['server'], info['session'], info['message_type'], info['ordinal'])
        if key not in self._wanted:
            return
        fields = info['fields']
        catalogue, occurrences, locations = [], Counter(), {}
        for index, (location, text) in enumerate(fields):
            occurrence = occurrences[location]
            occurrences[location] += 1
            digest = text_sha256(text)
            catalogue.append((location, digest, len(text)))
            locations[(location, occurrence)] = index
        rule_spans = defaultdict(set)
        by_hash = defaultdict(list)
        for index, (location, digest, _) in enumerate(catalogue):
            by_hash[(location, digest[:16])].append(index)
        for detection in info['rule_detections']:
            label = _RULE_LABELS.get(detection.pii_type)
            if label is None:
                self.out_of_scope_rules[detection.pii_type] += 1
                continue
            for index in by_hash.get((detection.location, detection.fingerprint), ()):
                rule_spans[index].add((0, catalogue[index][2], label))
        self._messages[key] = {'id': info['http_message_id'], 'catalogue': catalogue, 'locations': locations,
                               'rule_spans': dict(rule_spans), 'quality': dict(info['quality'])}
        self._by_id[info['http_message_id']] = key

    # engine disposition_observer
    def observe_disposition(self, message_id: str, index: int, status: str) -> None:
        if message_id in self._by_id:
            self._dispositions[(message_id, index)] = status

    # report rows (row_observer, or iterate report['findings'])
    def observe_finding(self, kind: str, row: dict) -> None:
        if kind != 'findings' or row.get('detector') != 'bilstm':
            return
        if row['pii_type'] not in EVAL_LABELS:
            self.out_of_scope_model[row['pii_type']] += 1
            return
        if row['http_message_id'] in self._by_id:
            self._model.append((row['http_message_id'], row['field_index'], row['pii_type'], row['span_start'], row['span_end']))

    def observe_report(self, report: dict) -> None:
        for row in report['findings']:
            self.observe_finding('findings', row)

    # ------------------------------------------------------------------ evaluation
    def finish(self, *, capture_sha256: str, capture_bytes: int | None, summary: dict, metadata: dict,
               model_requested: bool) -> dict:
        manifest = self.manifest
        if capture_sha256 != manifest.capture_sha256:
            raise EvaluationRejected('capture SHA-256 does not match the manifest: the annotations describe a different file')
        if manifest.capture_bytes is not None and capture_bytes is not None and manifest.capture_bytes != capture_bytes:
            raise EvaluationRejected('capture size does not match the manifest')

        model_by_field = defaultdict(set)
        for message_id, index, label, start, end in self._model:
            model_by_field[(message_id, index)].add((start, end, label))

        rows, unaligned = [], Counter()
        for gold in manifest.fields:
            message = self._messages.get(gold.message_key)
            if message is None:
                unaligned['message_not_found'] += 1
                continue
            index = message['locations'].get((gold.location, gold.occurrence))
            if index is None:
                unaligned['field_not_found'] += 1
                continue
            location, digest, length = message['catalogue'][index]
            if digest != gold.text_sha256 or length != gold.text_length:
                unaligned['text_mismatch'] += 1
                continue
            status = self._dispositions.get((message['id'], index), 'not_observed') if model_requested else 'model_not_requested'
            rows.append({'gold': gold, 'message': message, 'index': index,
                         'rules': message['rule_spans'].get(index, set()),
                         'model': model_by_field.get((message['id'], index), set()),
                         'status': status})
        if not rows:
            raise EvaluationRejected('no manifest field could be aligned with the capture; nothing can be scored')

        systems = {'rules_only': self._score('rules_only', rows, model_requested)}
        if model_requested:
            systems['model_only'] = self._score('model_only', rows, model_requested)
            systems['rules_plus_model'] = self._score('rules_plus_model', rows, model_requested)

        unscored = {name: s['unscored_fields'] for name, s in systems.items()}
        partial = bool(sum(unaligned.values())) or any(sum(v.values()) for v in unscored.values())
        unannotated = None
        if manifest.annotation_scope == 'all_fields_in_listed_messages':
            listed = {(f.message_key, f.location, f.occurrence) for f in manifest.fields}
            unannotated = sum(1 for key, m in self._messages.items() for (loc, occ) in m['locations']
                              if (key, loc, occ) not in listed)
            partial = partial or unannotated > 0
        summary_keys = ('ml_coverage_status', 'ml_coverage_ratio', 'ml_fields_eligible', 'ml_fields_evaluated', 'ml_fields_skipped',
                        'ml_fields_skipped_by_reason', 'analysis_incomplete', 'stream_gaps', 'unterminated_http_messages',
                        'http_messages', 'fields_extracted')
        return {
            'schema_version': RESULT_SCHEMA_VERSION,
            'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'status': 'partial' if partial else 'complete',
            'scope': ('Metrics are file-specific: they describe the scored fields of this capture against the supplied annotations. '
                      + ('PARTIAL: some annotated fields could not be scored; this is NOT full-file accuracy.' if partial else
                         'Every annotated field was aligned and scored.')),
            'capture': {'sha256': capture_sha256, 'bytes': capture_bytes, 'verified_against_manifest': True},
            'manifest': {**manifest.public(), 'verified': True},
            'model_version': metadata.get('ml_model_version'),
            'detection_method': metadata.get('detection_method'),
            'analysis_version': {'engine': metadata.get('engine'), 'version': metadata.get('version'),
                                 'report_schema_version': metadata.get('report_schema_version')},
            'ml_work_limits': metadata.get('ml_work_limits'),
            'analysis': {k: summary.get(k) for k in summary_keys},
            'alignment': {'manifest_fields': len(manifest.fields), 'aligned': len(rows), 'unaligned': dict(unaligned),
                          'unannotated_fields_in_listed_messages': unannotated,
                          'messages_in_capture_observed': self.observed_messages},
            'systems': systems,
            'out_of_scope_detections': {'rules': dict(self.out_of_scope_rules), 'model': dict(self.out_of_scope_model)},
            'notes': list(NOTES),
        }

    def _score(self, system: str, rows: list, model_requested: bool) -> dict:
        labels = self.manifest.labels
        counts = {label: Counter() for label in labels}
        errors: Counter = Counter()
        fp_types: Counter = Counter()
        fn_types: Counter = Counter()
        samples: list[dict] = []
        unscored: Counter = Counter()
        negatives = Counter()
        categories = defaultdict(Counter)
        detectors_on_tp: Counter = Counter()
        scored = 0
        for row in rows:
            gold: GoldField = row['gold']
            status = row['status']
            if system != 'rules_only' and not (status in ('evaluated', 'excluded_by_policy', 'empty')):
                unscored[status if status != 'not_observed' else 'model_status_unknown'] += 1
                continue
            predictions: dict[tuple, set] = defaultdict(set)
            if system in ('rules_only', 'rules_plus_model'):
                for span in row['rules']:
                    if span[2] in labels:
                        predictions[span].add('rule')
            if system in ('model_only', 'rules_plus_model'):
                for span in row['model']:
                    if span[2] in labels:
                        predictions[span].add('bilstm')
            gold_set = set(gold.spans)
            scored += 1
            field_fp = 0
            for span, detectors in predictions.items():
                if span in gold_set:
                    counts[span[2]]['tp'] += 1
                    detectors_on_tp['+'.join(sorted(detectors))] += 1
                    continue
                counts[span[2]]['fp'] += 1
                field_fp += 1
                kind = self._classify_fp(span, gold)
                fp_types[kind] += 1
                if len(samples) < MAX_ERROR_SAMPLES:
                    samples.append({'error': 'false_positive', 'type': kind, 'field_id': gold.field_id, 'label': span[2],
                                    'predicted_span': [span[0], span[1]], 'detectors': sorted(detectors)})
            for span in gold_set - set(predictions):
                counts[span[2]]['fn'] += 1
                kind = self._classify_fn(span, predictions, status, system)
                fn_types[kind] += 1
                if len(samples) < MAX_ERROR_SAMPLES:
                    samples.append({'error': 'false_negative', 'type': kind, 'field_id': gold.field_id, 'label': span[2],
                                    'gold_span': [span[0], span[1]]})
            if not gold.spans:
                negatives['scored'] += 1
                negatives['with_false_positive'] += field_fp > 0
            if gold.category:
                categories[gold.category]['scored'] += 1
                categories[gold.category]['with_false_positive'] += field_fp > 0
        per_label = {}
        for label in labels:
            c = counts[label]
            per_label[label] = {**prf(c['tp'], c['fp'], c['fn']), 'support': c['tp'] + c['fn'], 'predicted': c['tp'] + c['fp']}
        total = Counter()
        for label in labels:
            total.update(counts[label])
        micro = prf(total['tp'], total['fp'], total['fn'])
        averaged = [l for l in labels if per_label[l]['support'] > 0]
        macro = {'labels_averaged': averaged}
        for metric in ('precision', 'recall', 'f1'):
            values = [per_label[l][metric] for l in averaged if per_label[l][metric] is not None]
            macro[metric] = round(sum(values) / len(values), 4) if values and len(values) == len(averaged) else None
        return {
            'description': {'rules_only': 'Deterministic rules only (whole-field USERNAME / PERSON_NAME_CANDIDATE findings).',
                            'model_only': 'Contextual model predictions only (rules ignored).',
                            'rules_plus_model': 'Union of rule and model predictions; an identical span from both counts once.'}[system],
            'scored_fields': scored, 'unscored_fields': dict(unscored),
            'gold_spans_scored': micro['tp'] + micro['fn'], 'predicted_spans': micro['tp'] + micro['fp'],
            'per_label': per_label, 'micro': micro, 'macro': macro,
            'negative_fields': {'scored': negatives['scored'], 'with_false_positive': negatives['with_false_positive'],
                                'by_category': {k: dict(v) for k, v in sorted(categories.items())
                                                if k.startswith(('negative', 'hard_negative'))}},
            'categories': {k: dict(v) for k, v in sorted(categories.items())},
            'error_breakdown': {'false_positive': dict(sorted(fp_types.items())), 'false_negative': dict(sorted(fn_types.items()))},
            'true_positives_by_detector': dict(sorted(detectors_on_tp.items())),
            'error_samples': samples, 'error_samples_truncated': (sum(fp_types.values()) + sum(fn_types.values())) > len(samples),
        }

    @staticmethod
    def _classify_fp(span: tuple, gold: GoldField) -> str:
        if not gold.spans:
            return 'negative_field'
        for g in gold.spans:
            if (g[0], g[1]) == (span[0], span[1]):
                return 'wrong_label'
        for g in gold.spans:
            if _overlap(g, span):
                return 'boundary_mismatch' if g[2] == span[2] else 'overlaps_other_label'
        return 'spurious_in_positive_field'

    @staticmethod
    def _classify_fn(span: tuple, predictions: dict, status: str, system: str) -> str:
        for p in predictions:
            if (p[0], p[1]) == (span[0], span[1]):
                return 'wrong_label'
        for p in predictions:
            if _overlap(p, span):
                return 'boundary_mismatch' if p[2] == span[2] else 'overlaps_other_label'
        if system != 'rules_only' and status == 'excluded_by_policy':
            return 'excluded_by_policy'
        return 'missed'


# ------------------------------------------------------------------------------------------------ convenience API
def evaluate_capture(capture_path: str | Path, manifest: Manifest, *, detector=None, ml_budget='standard',
                     profile: str = 'standard', limits=None) -> dict:
    """Analyse ``capture_path`` through the real engine and score it against ``manifest``.

    Rules-only when ``detector`` is None. Raises ``EvaluationRejected`` before running anything expensive if the capture's
    SHA-256 differs from the manifest's.
    """
    from .engine import analyze
    capture_hash = sha256_file(capture_path)
    if capture_hash != manifest.capture_sha256:
        raise EvaluationRejected('capture SHA-256 does not match the manifest: the annotations describe a different file')
    collector = EvaluationCollector(manifest)
    report = analyze(capture_path, ml_detector=detector, ml_budget=ml_budget, profile=profile, limits=limits,
                     field_observer=collector.observe_message, disposition_observer=collector.observe_disposition)
    collector.observe_report(report)
    return collector.finish(capture_sha256=capture_hash, capture_bytes=Path(capture_path).stat().st_size,
                            summary=report['summary'], metadata=report['metadata'], model_requested=detector is not None)


def export_result(result: dict, target: str | Path, *, overwrite: bool = False) -> None:
    """Write the evaluation JSON privately (mode 0600), refusing to replace a file unless asked."""
    import os
    path = Path(target)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2, allow_nan=False)
        handle.write('\n')
