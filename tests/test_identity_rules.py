"""Identity/demographic rule categories (taxonomy v1). All values are fictional."""
import time

import pytest

from packet_pii.detect import REDACTED, detect_fields
from packet_pii.identity_rules import IDENTITY_CATEGORIES

IDFA = 'E621E1F8-C36C-495A-93FC-0C247A3E6E5F'
GAID = '38400000-8cf0-11bd-b23e-10b96e40000d'
OTHER_UUID = '9b2f6c1e-4d7a-4c3b-8e2f-1a6d5c4b3a29'
NIL = '00000000-0000-0000-0000-000000000000'
EXISTING = {'EMAIL', 'IP_ADDRESS', 'PHONE', 'CREDIT_CARD', 'CREDENTIAL_OR_TOKEN', 'USERNAME', 'PERSON_NAME_CANDIDATE'}


def found(fields, **kw):
    """{location: category} for identity categories only."""
    return {d.location: d.pii_type for d in detect_fields(fields, **kw) if d.pii_type in IDENTITY_CATEGORIES}


def one(location, value, **kw):
    return found([(location, value)], **kw).get(location)


# ---------------------------------------------------------------- advertising identifiers
@pytest.mark.parametrize('location,value,expected', [
    ('json_body.idfa', IDFA, 'APPLE_ADVERTISING_ID'),
    ('json_body.idfa', IDFA.lower(), 'APPLE_ADVERTISING_ID'),
    ('json_body.device.ios_advertising_id', IDFA, 'APPLE_ADVERTISING_ID'),
    ('query_parameter.idfa', IDFA, 'APPLE_ADVERTISING_ID'),
    ('form.appleAdvertisingId', IDFA, 'APPLE_ADVERTISING_ID'),
    ('header.x-idfa', IDFA, 'APPLE_ADVERTISING_ID'),
    ('json_body.events[3].context.device.IDFA', IDFA, 'APPLE_ADVERTISING_ID'),
    ('json_body.gaid', GAID, 'ANDROID_ADVERTISING_ID'),
    ('json_body.gaid', GAID.upper(), 'ANDROID_ADVERTISING_ID'),
    ('query_parameter.aaid', GAID, 'ANDROID_ADVERTISING_ID'),
    ('form.google_advertising_id', GAID, 'ANDROID_ADVERTISING_ID'),
    ('json_body.gps_adid', GAID, 'ANDROID_ADVERTISING_ID'),
    ('json_body.android.advertising_id', GAID, 'ANDROID_ADVERTISING_ID'),   # platform from parent path
    ('json_body.advertising_id', GAID, 'ADVERTISING_ID'),                  # no platform evidence: unattributed
    ('json_body.device.ifa', IDFA, 'ADVERTISING_ID'),
])
def test_advertising_id_positive(location, value, expected):
    assert one(location, value) == expected


@pytest.mark.parametrize('location,value', [
    ('json_body.request_id', OTHER_UUID), ('header.x-correlation-id', OTHER_UUID), ('json_body.session_uuid', OTHER_UUID),
    ('json_body.transaction_id', OTHER_UUID), ('json_body.record.uuid', OTHER_UUID), ('json_body.uuid', OTHER_UUID),
    ('json_body.idfa', NIL), ('json_body.gaid', NIL), ('json_body.advertising_id', NIL),
    ('json_body.idfa', 'ffffffff-ffff-ffff-ffff-ffffffffffff'),
    ('json_body.idfa', 'E621E1F8-C36C-495A-93FC-0C247A3E6E5G'),  # non-hex
    ('json_body.idfa', 'E621E1F8C36C495A93FC0C247A3E6E5F'),       # unhyphenated: not accepted (documented)
    ('json_body.idfa', ' ' + IDFA), ('json_body.idfa', IDFA + ';x'), ('json_body.idfa', IDFA[:-1]),
    ('json_body.idfa', ''), ('json_body.idfa', 'null'), ('json_body.idfa', 'unknown'),
    ('json_body.idfa_hash', IDFA), ('json_body.myidfa', IDFA), ('json_body.idfa_enabled', 'true'),
    ('json_body.ad_id', OTHER_UUID), ('json_body.adid', OTHER_UUID),  # advertisement / Adjust IDs, not IDFA/GAID
    ('json_body.app_set_id', OTHER_UUID), ('json_body.firebase_installation_id', OTHER_UUID),
    ('body.text', 'idfa=' + IDFA),
])
def test_advertising_id_negative(location, value):
    assert one(location, value) is None


def test_generic_advertising_id_uses_sibling_platform_in_enclosing_scope():
    assert found([('json_body.device.os', 'iOS 17.4'), ('json_body.device.ifa', IDFA)]) == {
        'json_body.device.ifa': 'APPLE_ADVERTISING_ID'}
    assert found([('json_body.platform', 'android'), ('json_body.app.advertising_id', GAID)]) == {
        'json_body.app.advertising_id': 'ANDROID_ADVERTISING_ID'}
    assert found([('query_parameter.os', 'Android'), ('query_parameter.advertising_id', GAID)]) == {
        'query_parameter.advertising_id': 'ANDROID_ADVERTISING_ID'}
    assert found([('header.x-platform', 'ios'), ('json_body.advertising_id', IDFA)]) == {
        'json_body.advertising_id': 'APPLE_ADVERTISING_ID'}


def test_platform_evidence_from_a_sibling_array_element_is_not_used():
    fields = [('json_body.events[0].os', 'android'), ('json_body.events[1].advertising_id', GAID)]
    assert found(fields) == {'json_body.events[1].advertising_id': 'ADVERTISING_ID'}


def test_conflicting_platform_context_is_never_attributed():
    assert found([('json_body.os', 'android'), ('json_body.idfa', IDFA)]) == {'json_body.idfa': 'ADVERTISING_ID'}
    assert found([('json_body.os', 'ios'), ('json_body.platform', 'android'), ('json_body.advertising_id', GAID)]) == {
        'json_body.advertising_id': 'ADVERTISING_ID'}
    assert one('json_body.ios.gaid', GAID) == 'ADVERTISING_ID'


def test_platform_values_are_strict():
    # "android-ish" free text or a user agent is not a platform declaration.
    assert found([('json_body.os', 'not android'), ('json_body.advertising_id', GAID)]) == {
        'json_body.advertising_id': 'ADVERTISING_ID'}
    assert found([('header.user-agent', 'Mozilla/5.0 (Linux; Android 14)'), ('json_body.advertising_id', GAID)]) == {
        'json_body.advertising_id': 'ADVERTISING_ID'}


# ---------------------------------------------------------------- age
@pytest.mark.parametrize('location,value', [
    ('json_body.age', '27'), ('json_body.user.age', '27'), ('json_body.profile.age', '64'), ('json_body.person.age', '5'),
    ('json_body.customer.age', '101'), ('json_body.users[2].age', '33'), ('json_body.data.user.age', '41'),
    ('json_body.user.traits.age', '19'), ('json_body.user_properties.age', '22'), ('query_parameter.age', '27'),
    ('form.user_age', '45'), ('form.user[age]', '45'), ('json_body.userAge', '30'), ('json_body.age', '27 years'),
    ('json_body.age', '27y'), ('json_body.age_years', '8'), ('json_body.age', ' 27 '), ('json_body.age', '120'),
])
def test_age_positive(location, value):
    assert one(location, value) == 'AGE'


@pytest.mark.parametrize('location,value', [
    ('query_parameter.page', '27'), ('json_body.retry_count', '27'), ('json_body.stage', '3'), ('json_body.message', '27'),
    ('json_body.agent', '27'), ('json_body.usage', '27'), ('json_body.max_age', '27'), ('json_body.age_group', '25-34'),
    ('header.age', '27'), ('header.cache-control', 'max-age=27'), ('json_body.cache.age', '27'),
    ('json_body.product.age', '27'), ('json_body.account.age', '27'), ('json_body.item.age', '27'),
    ('json_body.age', '1990'), ('json_body.age', '1990-04-01'), ('json_body.age', '0'), ('json_body.age', '121'),
    ('json_body.age', '27.5'), ('json_body.age', '27.0'), ('json_body.age', '-27'), ('json_body.age', '027'),
    ('json_body.age', ''), ('json_body.age', 'null'), ('json_body.age', 'twenty'), ('json_body.age', '1.2.3'),
    ('json_body.age', '27 days'), ('json_body.birth_year', '1990'), ('json_body.dob', '1990-04-01'),
    ('json_body.âge', '27'), ('json_body.ａｇｅ', '27'), ('body.text', 'age: 27'),
])
def test_age_negative(location, value):
    assert one(location, value) is None


# ---------------------------------------------------------------- gender / sex
@pytest.mark.parametrize('location,value,expected', [
    ('json_body.gender', 'female', 'GENDER'), ('json_body.profile.gender', 'Male', 'GENDER'),
    ('json_body.user.gender', 'non-binary', 'GENDER'), ('json_body.user.gender', 'Non_Binary', 'GENDER'),
    ('form.user_gender', 'genderqueer', 'GENDER'), ('json_body.gender_identity', 'trans woman', 'GENDER'),
    ('json_body.user.gender', 'M', 'GENDER'), ('query_parameter.gender', 'f', 'GENDER'),
    ('json_body.sex', 'female', 'SEX'), ('json_body.patient.sex', 'M', 'SEX'), ('json_body.sex_at_birth', 'male', 'SEX'),
    ('json_body.profile.sex', 'intersex', 'SEX'), ('form.legal_sex', 'F', 'SEX'),
])
def test_gender_sex_positive(location, value, expected):
    assert one(location, value) == expected


@pytest.mark.parametrize('location,value', [
    ('json_body.sexuality', 'female'), ('json_body.section', 'male'), ('json_body.sextant', 'male'),
    ('json_body.gendered_content', 'female'), ('json_body.product.gender', 'female'), ('json_body.item.gender', 'male'),
    ('json_body.gender', 'O'), ('json_body.gender', 'U'), ('json_body.sex', 'X'), ('json_body.gender', '1'),
    ('json_body.gender', '2'), ('json_body.sex', '0'), ('json_body.gender', 'unknown'), ('json_body.gender', 'other'),
    ('json_body.gender', 'prefer not to say'), ('json_body.gender', ''), ('json_body.gender', 'null'),
    ('json_body.gender', 'true'), ('json_body.gender', 'blue'), ('json_body.gender', 'mens'),
    ('json_body.gender', 'female female'), ('header.gender', 'female'), ('json_body.user.name', 'Maria Garcia'),
    ('json_body.username', 'jessica_smith'), ('body.text', 'gender: female'),
])
def test_gender_sex_negative(location, value):
    assert one(location, value) is None


def test_no_demographic_inference_from_names_or_usernames():
    fields = [('json_body.first_name', 'Maria'), ('json_body.last_name', 'Garcia'), ('json_body.username', 'mr_john'),
              ('json_body.bio', 'I am a 27 year old woman'), ('json_body.title', 'Mrs')]
    kinds = {d.pii_type for d in detect_fields(fields)}
    assert not kinds & {'AGE', 'GENDER', 'SEX'}


# ---------------------------------------------------------------- device / account identifiers
@pytest.mark.parametrize('location,value,expected', [
    ('json_body.device_id', 'a1b2c3d4e5f60718', 'DEVICE_ID'), ('json_body.android_id', '9f3c2a7b1e4d6c80', 'DEVICE_ID'),
    ('json_body.idfv', OTHER_UUID, 'DEVICE_ID'), ('json_body.device.id', OTHER_UUID, 'DEVICE_ID'),
    ('header.x-device-id', 'dev-58201934', 'DEVICE_ID'),
    ('json_body.user_id', '58201934', 'USER_ACCOUNT_ID'), ('json_body.user.id', '42', 'USER_ACCOUNT_ID'),
    ('json_body.account_id', 'acct_7Hq2x9', 'USER_ACCOUNT_ID'), ('query_parameter.customerId', 'C-000193', 'USER_ACCOUNT_ID'),
    ('json_body.users[0].id', OTHER_UUID, 'USER_ACCOUNT_ID'), ('header.x-user-id', '58201934', 'USER_ACCOUNT_ID'),
])
def test_identifier_positive(location, value, expected):
    assert one(location, value) == expected


@pytest.mark.parametrize('location,value', [
    ('json_body.id', '58201934'), ('json_body.order.id', '58201934'), ('json_body.contact.id', '58201934'),
    ('json_body.uid', '58201934'), ('json_body.client_id', '58201934'), ('json_body.request_id', OTHER_UUID),
    ('json_body.device_id', 'unknown-device'), ('json_body.device_id', 'web'), ('json_body.device_id', NIL),
    ('json_body.device_id', '0000000000000000'), ('json_body.device.model', 'SM-G991B'),
    ('json_body.user_id', 'null'), ('json_body.user_id', 'anonymous'), ('json_body.user_id', '0'),
    ('json_body.user_id', '-1'), ('json_body.user_id', ''), ('json_body.user_id', 'has space'),
    ('json_body.user_id', 'x' * 200), ('json_body.user.id_type', 'email'), ('json_body.app_set_id', OTHER_UUID),
])
def test_identifier_negative(location, value):
    assert one(location, value) is None


def test_identifier_does_not_steal_existing_categories():
    # session/auth identifiers remain credentials; email-shaped user IDs remain EMAIL.
    kinds = {(d.location, d.pii_type) for d in detect_fields([('json_body.session_id', OTHER_UUID),
                                                               ('json_body.user_id', 'ana@example.org')])}
    assert ('json_body.session_id', 'CREDENTIAL_OR_TOKEN') in kinds
    assert ('json_body.user_id', 'EMAIL') in kinds
    assert not any(k == 'USER_ACCOUNT_ID' for _, k in kinds) and not any(k == 'DEVICE_ID' for _, k in kinds)


# ---------------------------------------------------------------- privacy, scores, attribution
def test_masked_by_default_and_raw_only_when_authorised():
    fields = [('json_body.idfa', IDFA), ('json_body.age', '27'), ('json_body.gender', 'female'),
              ('json_body.sex', 'male'), ('json_body.user_id', '58201934'), ('json_body.device_id', 'a1b2c3d4e5f60718')]
    masked = {d.pii_type: d.value for d in detect_fields(fields)}
    assert masked['AGE'] == masked['GENDER'] == masked['SEX'] == REDACTED
    assert masked['USER_ACCOUNT_ID'] == '****'   # short identifiers reveal nothing
    assert masked['APPLE_ADVERTISING_ID'] == 'E6***5F'
    assert masked['DEVICE_ID'] == 'a1***18'
    for _, raw in fields:
        assert raw not in masked.values()
    assert {d.value for d in detect_fields(fields, include_values=True)} == {v for _, v in fields}


def test_rules_attribution_and_heuristic_scores():
    detections = [d for d in detect_fields([('json_body.idfa', IDFA), ('json_body.age', '27'), ('json_body.sex', 'M')])
                  if d.pii_type in IDENTITY_CATEGORIES]
    assert len(detections) == 3
    assert all(d.detector == 'rule' for d in detections)
    assert all(0.8 <= d.confidence < 0.95 for d in detections)  # no 0.99-style certainty claims


def test_threshold_semantics():
    fields = [('json_body.idfa', IDFA), ('json_body.advertising_id', GAID), ('json_body.age', '27'),
              ('json_body.gender', 'M'), ('json_body.user_id', '58201934')]
    assert len(found(fields)) == 5                      # default 0.8 keeps every category
    assert set(found(fields, threshold=0.86).values()) == {'APPLE_ADVERTISING_ID', 'ADVERTISING_ID'}
    assert found(fields, threshold=0.95) == {}
    with pytest.raises(ValueError):
        detect_fields(fields, threshold=1.5)


def test_dedup_order_and_duplicates():
    fields = [('json_body.age', '27'), ('json_body.idfa', IDFA), ('json_body.age', '27'), ('json_body.age', '28')]
    detections = [d for d in detect_fields(fields, include_values=True) if d.pii_type in IDENTITY_CATEGORIES]
    assert [(d.pii_type, d.value) for d in detections] == [('AGE', '27'), ('APPLE_ADVERTISING_ID', IDFA), ('AGE', '28')]
    assert detections == [d for d in detect_fields(fields, include_values=True) if d.pii_type in IDENTITY_CATEGORIES]


def test_existing_categories_unchanged_on_a_mixed_message():
    fields = [('json_body.email', 'ana@example.org'), ('json_body.phone', '+44 20 7946 0958'),
              ('json_body.card', '4111 1111 1111 1111'), ('json_body.password', 'hunter2'),
              ('json_body.username', 'ana_g'), ('json_body.full_name', 'Ana Garcia'), ('json_body.ip', '192.0.2.4'),
              ('json_body.age', '27'), ('json_body.idfa', IDFA)]
    kinds = [d.pii_type for d in detect_fields(fields)]
    assert set(kinds) - set(IDENTITY_CATEGORIES) == EXISTING
    assert sorted(set(kinds) & set(IDENTITY_CATEGORIES)) == ['AGE', 'APPLE_ADVERTISING_ID']


def test_unicode_and_long_inputs_are_safe_and_linear():
    assert one('json_body.用户.age', '27') is None                  # unknown non-person parent
    assert one('json_body.gender', 'fémale') is None
    long_key = 'json_body.' + '.'.join(['a'] * 50_000) + '.age'
    long_value = '9' * 100_000
    started = time.perf_counter()
    for loc, val in [(long_key, '27'), ('json_body.age', long_value), ('json_body.idfa', 'a-' * 50_000),
                     ('json_body.user_id', 'a' * 100_000), ('json_body.os', 'ios ' * 25_000),
                     ('json_body.' + '[' * 50_000 + 'age', '27 ' + 'y' * 50_000), ('json_body.gender', ' ' * 100_000)]:
        detect_fields([(loc, val), ('json_body.advertising_id', GAID)])
    assert time.perf_counter() - started < 2.0
    assert one(long_key, '27') is None                               # nearest parent ``a`` is not a person context


def test_committed_synthetic_validation_results_are_reproducible():
    import importlib.util
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('evaluate_identity_rules', root / 'scripts' / 'evaluate_identity_rules.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    cases = json.loads(module.DEFAULT_CASES.read_text(encoding='utf-8'))
    committed = json.loads(module.DEFAULT_OUT.read_text(encoding='utf-8'))
    assert module.evaluate(cases) == committed
    assert committed['label'].startswith('Synthetic rule-validation results')
    # Every error is a deliberately included hard case; the results file contains no field values.
    assert all(error['hard_case'] for error in committed['errors'])
    raw_values = {value for message in cases['messages'] for _, value in message['fields'] if len(value) >= 8}
    assert not any(value in json.dumps(committed) for value in raw_values)
