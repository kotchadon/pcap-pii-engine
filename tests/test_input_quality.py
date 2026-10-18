"""F-10: upstream evidence-quality flags reach ML findings without changing model input or predictions."""
import pytest

from packet_pii.engine import analyze
from packet_pii.hybrid import infer_http_fields
from packet_pii.ml import EntityLabel, EntitySpan, ScoreType
from test_vp_qa_support import ml_findings, one_request_pcap, post_json


class Marker:
    """Test double: flags every 'Alex Example' and records exactly what the model was shown."""
    model_version = 'test-model'

    def __init__(self):
        self.seen = []

    def predict_fields(self, fields):
        self.seen += [(f.location, f.text, dict(f.context)) for f in fields]
        return [EntitySpan(f.field_index, EntityLabel.PERSON_NAME, f.text.find('Alex'), f.text.find('Alex') + 12,
                           self.model_version, .9, ScoreType.UNCALIBRATED_MODEL_SCORE)
                for f in fields if 'Alex Example' in f.text]


FIELDS = [('json_body.recipient', 'Alex Example')]


def test_flags_are_attached_to_findings_and_do_not_change_predictions():
    clean, flagged = Marker(), Marker()
    a = infer_http_fields(FIELDS, clean)
    b = infer_http_fields(FIELDS, flagged, quality={'stream_gap': 'true', 'capture_incomplete': 'true', 'unknown_flag': 'true'})
    assert 'input_quality' not in a.findings[0]
    assert b.findings[0]['input_quality'] == ['capture_incomplete', 'stream_gap']      # unknown keys are ignored
    strip = lambda f: {k: v for k, v in f.items() if k != 'input_quality'}
    assert strip(b.findings[0]) == strip(a.findings[0])                                # same span, score and offsets
    assert [(l, t) for l, t, _ in clean.seen] == [(l, t) for l, t, _ in flagged.seen]  # model text/location input unchanged


def test_replacement_characters_are_flagged_and_mostly_garbage_is_excluded():
    model = Marker()
    result = infer_http_fields([('json_body.a', 'Alex Example �'), ('json_body.b', '���� x')], model)
    assert result.fields_evaluated == 1 and result.fields_excluded == 1
    assert result.findings[0]['input_quality'] == ['decode_replaced']


def test_engine_marks_findings_from_an_incomplete_capture(tmp_path):
    good = one_request_pcap(tmp_path, post_json({'recipient': 'Alex Example'}), name='g.pcap')
    truncated = tmp_path / 't.pcap'
    truncated.write_bytes(good.read_bytes()[:-25])                                     # cut the final record
    for path, expected in ((good, None), (truncated, ['capture_incomplete'])):
        findings = ml_findings(analyze(path, ml_detector=Marker()))
        assert findings, path
        assert all(f.get('input_quality') == expected for f in findings), path
