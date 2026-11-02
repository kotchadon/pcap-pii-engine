"""High-capacity ML coverage is opt-in and must keep every safety limit."""
from pathlib import Path

import pytest

from packet_pii.ml_runner import MLWorkBudget, ML_PROFILES


ROOT = Path(__file__).resolve().parents[1]


def test_high_capacity_extends_field_coverage_without_changing_defaults():
    standard = MLWorkBudget.for_profile('standard')
    extended = MLWorkBudget.for_profile('extended')
    complete = MLWorkBudget.for_profile('complete')
    high = MLWorkBudget.for_profile('high_capacity')
    assert standard.max_fields == 10_000
    assert extended.max_fields == 100_000
    assert complete.max_fields == 1_000_000
    assert high.name == 'high_capacity'
    assert high.max_fields == 2_500_000
    assert high.max_characters == 500_000_000
    assert high.max_seconds == 3_600.0
    assert high.batch_fields == standard.batch_fields == complete.batch_fields
    assert high.batch_characters == standard.batch_characters == complete.batch_characters
    assert high.max_field_chars == standard.max_field_chars
    assert high.max_fields <= high.CEILING_FIELDS
    assert high.max_characters <= high.CEILING_CHARACTERS
    assert high.max_seconds <= high.CEILING_SECONDS
    assert 'high_capacity' in ML_PROFILES
    assert MLWorkBudget().max_fields == standard.max_fields
    assert MLWorkBudget().max_seconds == standard.max_seconds


def test_high_capacity_is_exposed_to_UI_and_remains_explicit_opt_in():
    html = (ROOT / 'src/packet_pii/dashboard_static/index.html').read_text()
    assert '<option value="high_capacity" selected>' in html
    assert '2,500,000' in html
    assert 'TRACE will show any fields skipped' in html
    lab = (ROOT / 'src/packet_pii/dashboard_static/lab.js').read_text()
    assert "headers['X-ML-Coverage']=st.mlProfile" in lab
    assert "st={mlProfile:'high_capacity'" in lab
    source = (ROOT / 'src/packet_pii/dashboard.py').read_text()
    assert "ml_profile not in ML_PROFILES" in source


def test_high_capacity_is_not_unlimited():
    with pytest.raises(ValueError, match='absolute ceiling'):
        MLWorkBudget(max_fields=MLWorkBudget.CEILING_FIELDS + 1)
    with pytest.raises(ValueError, match='absolute ceiling'):
        MLWorkBudget(max_characters=MLWorkBudget.CEILING_CHARACTERS + 1)
    with pytest.raises(ValueError, match='max_seconds'):
        MLWorkBudget(max_seconds=MLWorkBudget.CEILING_SECONDS + 1)
