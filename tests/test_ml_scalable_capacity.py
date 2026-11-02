"""High-field-capacity user choices: bounded, real engine budgets, not cosmetic labels."""
from pathlib import Path
import re

import pytest

from packet_pii.ml_runner import MLWorkBudget, ML_PROFILES

ROOT = Path(__file__).resolve().parents[1]
CAPACITY = {
    "high_capacity": (2_500_000, 500_000_000, 3_600),
    "capacity_5m": (5_000_000, 1_000_000_000, 4_500),
    "capacity_8m": (8_000_000, 1_600_000_000, 5_700),
    "capacity_10m": (10_000_000, 2_000_000_000, 6_600),
    "capacity_15m": (15_000_000, 3_000_000_000, 7_200),
}


@pytest.mark.parametrize("profile,expected", CAPACITY.items())
def test_capacity_budget_is_real_and_bounded(profile, expected):
    b = MLWorkBudget.for_profile(profile)
    assert (b.max_fields, b.max_characters, b.max_seconds) == expected
    assert b.name == profile
    assert b.batch_fields == 256
    assert b.batch_characters == 262_144
    assert b.max_field_chars == MLWorkBudget().max_field_chars
    assert b.max_fields <= b.CEILING_FIELDS
    assert b.max_characters <= b.CEILING_CHARACTERS
    assert b.max_seconds <= b.CEILING_SECONDS
    assert b.public()["max_fields"] == expected[0]


def test_legacy_profiles_remain_valid_for_api_but_not_in_web_selector():
    assert MLWorkBudget().max_fields == 10_000
    assert MLWorkBudget.for_profile("standard").max_fields == 10_000
    assert MLWorkBudget.for_profile("extended").max_fields == 100_000
    assert MLWorkBudget.for_profile("complete").max_fields == 1_000_000
    assert all(profile in ML_PROFILES for profile in CAPACITY)
    html = (ROOT / "src/packet_pii/dashboard_static/index.html").read_text()
    select = re.search(r'<select id="ml-profile">(?P<options>.*?)</select>', html, re.DOTALL)
    assert select is not None
    options = select.group("options")
    assert re.findall(r'<option value="([^"]+)"', options) == list(CAPACITY)
    for old in ('standard', 'extended', 'complete'):
        assert f'<option value="{old}">' not in options
    assert '<option value="high_capacity" selected>' in options
    js = (ROOT / "src/packet_pii/dashboard_static/lab.js").read_text()
    assert "st={mlProfile:'high_capacity'" in js
    assert "headers['X-ML-Coverage']=st.mlProfile" in js


def test_ceiling_enforced_independently_of_selected_profile():
    assert MLWorkBudget.CEILING_FIELDS == 15_000_000
    assert MLWorkBudget.CEILING_CHARACTERS == 3_000_000_000
    with pytest.raises(ValueError, match="absolute ceiling"):
        MLWorkBudget(max_fields=15_000_001)
    with pytest.raises(ValueError, match="absolute ceiling"):
        MLWorkBudget(max_characters=3_000_000_001)
    with pytest.raises(ValueError, match="max_seconds"):
        MLWorkBudget(max_seconds=7_201)
    with pytest.raises(ValueError, match="batch_fields"):
        MLWorkBudget(batch_fields=257)
    with pytest.raises(ValueError, match="max_field_chars"):
        MLWorkBudget(max_field_chars=MLWorkBudget().max_field_chars + 1)
