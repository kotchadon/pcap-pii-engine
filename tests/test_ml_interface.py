import logging
import math

import pytest

from packet_pii.ml import (ContextualPIIDetector, EntityLabel, EntitySpan, FieldInput,
                           MlValidationError, ScoreType, ValidationLimits, run_detector,
                           validate_fields, validate_spans)

SECRET = "hunter2-SECRET-tok3n"


def span(**kw):
    base = dict(field_index=0, label="USERNAME", start=0, end=3, model_version="m1")
    base.update(kw)
    return EntitySpan(**base)


class Fake:
    model_version = "fake-0"

    def __init__(self, spans):
        self.spans, self.calls = spans, 0

    def predict_fields(self, fields):
        self.calls += 1
        return list(self.spans)


def test_valid_definitions():
    f = FieldInput(0, "json_body.user.name", "alice", {"k": "v"})
    assert f.context["k"] == "v"
    s = span(score=0.5, score_type="uncalibrated_model_score")
    assert s.label is EntityLabel.USERNAME and s.score == 0.5
    assert isinstance(Fake([]), ContextualPIIDetector)


def test_unicode_offsets_are_code_points():
    text = "héllo 😀 Zoë"
    start = text.index("Zoë")
    s = span(label="PERSON_NAME", start=start, end=start + 3)
    f = FieldInput(0, "a", text)
    out = validate_spans([s], [f])
    assert text[out[0].start:out[0].end] == "Zoë"
    with pytest.raises(MlValidationError):
        validate_spans([span(end=len(text) + 1)], [f])


@pytest.mark.parametrize("kw", [
    dict(start=3, end=3), dict(start=5, end=2), dict(start=-1, end=2), dict(start=True, end=2),
    dict(start=0.0, end=2), dict(label="CREDIT_CARD"), dict(model_version=" "),
    dict(field_index=-1), dict(field_index=True),
])
def test_invalid_spans_rejected(kw):
    with pytest.raises(MlValidationError):
        span(**kw)


def test_span_must_match_request():
    f = FieldInput(0, "a", "abc")
    with pytest.raises(MlValidationError):
        validate_spans([span(field_index=9)], [f])
    with pytest.raises(MlValidationError):
        validate_spans([span(), span()], [f])


def test_repeated_locations_distinct_identities():
    fs = [FieldInput(0, "header.x", "alice"), FieldInput(1, "header.x", "bob")]
    out = run_detector(Fake([span(field_index=1, end=3), span(field_index=0, end=5)]), fs)
    assert [s.field_index for s in out] == [0, 1]
    with pytest.raises(MlValidationError):
        validate_fields([FieldInput(0, "x", "a"), FieldInput(0, "y", "b")])


def test_empty_input_and_empty_text():
    d = Fake([span()])
    assert run_detector(d, []) == [] and d.calls == 0
    f = FieldInput(0, "a", "")
    assert run_detector(Fake([]), [f]) == []
    with pytest.raises(MlValidationError):
        run_detector(Fake([span()]), [f])  # nothing can fit in empty text


@pytest.mark.parametrize("score", [-0.1, 1.1, math.nan, math.inf, -math.inf, "0.5", True])
def test_invalid_scores(score):
    with pytest.raises(MlValidationError):
        span(score=score, score_type="uncalibrated_model_score")


def test_score_type_consistency():
    with pytest.raises(MlValidationError):
        span(score=0.5)  # type 'none' with a score
    with pytest.raises(MlValidationError):
        span(score_type="uncalibrated_model_score")  # type without score
    with pytest.raises(MlValidationError):
        span(score=0.5, score_type="probability")
    assert span(score=1, score_type=ScoreType.CALIBRATED_PROBABILITY).score == 1.0


def test_oversized_and_malformed_input():
    lim = ValidationLimits(max_fields=2, max_field_chars=5)
    with pytest.raises(MlValidationError):
        validate_fields([FieldInput(0, "a", "x" * 6)], lim)
    with pytest.raises(MlValidationError):
        validate_fields([FieldInput(i, "a", "x") for i in range(3)], lim)
    for bad in ("abc", [("a", "b")], None, 5):
        with pytest.raises(MlValidationError):
            validate_fields(bad)
    with pytest.raises(MlValidationError):
        FieldInput(0, "", "x")
    with pytest.raises(MlValidationError):
        FieldInput(0, "a", b"bytes")
    with pytest.raises(MlValidationError):
        run_detector(type("N", (), {"model_version": "n", "predict_fields": lambda s, f: None})(),
                     [FieldInput(0, "a", "x")])


def test_no_sensitive_leak_in_errors_repr_or_logs(caplog):
    caplog.set_level(logging.DEBUG)
    text = f"password={SECRET}"
    f = FieldInput(0, "body.password", text)
    assert SECRET not in repr(f)
    msgs = []
    for fn in (
        lambda: validate_fields([f], ValidationLimits(max_field_chars=3)),
        lambda: validate_spans([span(end=len(text) + 5)], [f]),
        lambda: FieldInput(0, "loc", SECRET.encode()),
        lambda: span(label=SECRET),
        lambda: span(model_version=SECRET * 100),
        lambda: span(score=SECRET, score_type="uncalibrated_model_score"),
    ):
        with pytest.raises(MlValidationError) as e:
            fn()
        msgs.append(str(e.value))
    assert all(SECRET not in m for m in msgs)
    assert SECRET not in caplog.text


def test_deterministic_validation():
    fs = [FieldInput(i, "a", "abcdef") for i in range(3)]
    spans = [span(field_index=2, end=2), span(field_index=0, start=2, end=4), span(field_index=0, end=2)]
    a = validate_spans(spans, fs)
    b = validate_spans(list(reversed(spans)), fs)
    assert a == b and [(s.field_index, s.start) for s in a] == [(0, 0), (0, 2), (2, 0)]
    errs = set()
    for _ in range(3):
        with pytest.raises(MlValidationError) as e:
            validate_spans([span(end=99)], fs)
        errs.add(str(e.value))
    assert len(errs) == 1
