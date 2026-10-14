"""ML input-quality policy for extracted HTTP field text (torch-free; no host-engine imports).

The detector consumes *extracted field text and its location*, never raw packets. This module defines which fields the
contextual model should not see, and which upstream quality signals must survive into any downstream finding. It does
NOT modify ``FieldInput``/``EntitySpan``: upstream quality flags travel in ``FieldInput.context`` (str -> str).

Context keys recognised (value ``"true"`` / ``"1"`` / ``"yes"``):
  ``truncated``           field text was cut (size cap, incomplete body, chunk missing)
  ``stream_gap``          the TCP stream this field came from had a reassembly gap
  ``capture_incomplete``  capture-level truncation / malformed records were reported
  ``decode_replaced``     bytes were decoded with replacement characters
  ``fragment``            text is known to be a partial value (e.g. split across messages)

Policy
  * secret-bearing keys (password / token / cookie ...) are EXCLUDED from name tagging: the model was not trained on
    credentials and produced false positives there; the deterministic rules own them;
  * empty / one-character / mostly-replacement-character text is skipped;
  * fields with upstream quality flags are still analysed but reported in ``partial_evidence`` so that findings can be
    marked as potentially incomplete / non-exhaustive. ML cannot restore bytes that were never captured.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence

from .detector import ContextualPIIDetector, run_detector
from .schema import DEFAULT_LIMITS, EntitySpan, FieldInput, ValidationLimits, validate_fields

# mirrors packet_pii.detect.SECRET_KEYS (copied, not imported: the ML package stays independent of the rules engine)
SECRET_KEYS = re.compile(r'(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|auth(?:orization)?|'
                         r'session[_-]?(?:id|token)|bearer|set-cookie|cookie|token|credential)', re.I)
QUALITY_FLAGS = ("truncated", "stream_gap", "capture_incomplete", "decode_replaced", "fragment")
_TRUE = {"true", "1", "yes"}
MIN_CHARS = 2
MAX_REPLACEMENT_RATIO = 0.3


@dataclass(frozen=True)
class FieldScreen:
    eligible: bool
    skip_reasons: tuple = ()
    quality_flags: tuple = ()


@dataclass(frozen=True)
class PolicyResult:
    spans: list
    screens: dict = field(default_factory=dict)          # field_index -> FieldScreen (no text inside)
    partial_evidence: frozenset = frozenset()            # field_index values whose findings may be incomplete/unreliable
    skipped: dict = field(default_factory=dict)          # field_index -> skip reasons


def screen_field(f: FieldInput) -> FieldScreen:
    reasons = []
    if SECRET_KEYS.search(f.location):
        reasons.append("secret_bearing_key")
    n = len(f.text)
    if n == 0:
        reasons.append("empty_text")
    elif len(f.text.strip()) < MIN_CHARS:
        reasons.append("too_short")
    elif f.text.count("�") / n > MAX_REPLACEMENT_RATIO:
        reasons.append("mostly_replacement_chars")
    flags = [k for k in QUALITY_FLAGS if f.context.get(k, "").strip().lower() in _TRUE]
    if "�" in f.text and "decode_replaced" not in flags:
        flags.append("decode_replaced")
    return FieldScreen(not reasons, tuple(reasons), tuple(sorted(flags)))


def run_with_policy(detector: ContextualPIIDetector, fields: Sequence[FieldInput],
                    limits: ValidationLimits = DEFAULT_LIMITS) -> PolicyResult:
    """Screen fields, run the detector on eligible ones only, and surface partial-evidence markers."""
    fields = validate_fields(fields, limits)
    screens = {f.field_index: screen_field(f) for f in fields}
    eligible = [f for f in fields if screens[f.field_index].eligible]
    spans: list[EntitySpan] = run_detector(detector, eligible, limits) if eligible else []
    partial = frozenset(s.field_index for s in spans if screens[s.field_index].quality_flags)
    skipped = {i: s.skip_reasons for i, s in screens.items() if not s.eligible}
    return PolicyResult(spans, screens, partial, skipped)
