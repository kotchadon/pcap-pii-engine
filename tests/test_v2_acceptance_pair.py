"""Fail-closed receipt comparison tests, not model-quality evidence."""
import copy
import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1]/'scripts/validation/accept_v2_m3_pair.py'


def module():
    spec=importlib.util.spec_from_file_location('accept_pair',PATH)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m


def receipt():
    return {'capture_sha256':'a'*64,'capture_bytes':1024,'profile':'stress',
            'analysis_limits':{'max_memory_bytes':4*2**30},
            'ml_work_budget':{'max_fields':2500000},'ml_profile':'high_capacity',
            'threads':2,'torch':'test-version','checkpoint_sha256':{'model.pt':'b'*64},
            'model_version':'bilstm-v2-d1f9e9fb9a2b','min_score':.35,'cache_enabled':True,
            'runs':[{'status':'completed','seconds':10,'lifetime_peak_rss':100,
                     'report_digest_method':'ordered-json-events-v1','canonical_report_sha256':'c'*64,
                     'verified_capture_evidence':{'identity_status':'verified_read','capture_sha256':'a'*64},
                     'summary':{'analysis_incomplete':False,'ml_inference_complete':True,
                                'ml_fields_eligible':50,'ml_fields_evaluated':50,'ml_fields_skipped':0}}]}


def test_clock_changes_allowed_but_evidence_identity_required():
    a=receipt();b=copy.deepcopy(a);b['runs'][0]['seconds']=5
    assert module().validate_pair(a,b)==[]
    b['runs'][0]['canonical_report_sha256']='d'*64
    assert module().validate_pair(a,b)


@pytest.mark.parametrize('key,value', [('checkpoint_sha256',{}),('min_score',.4),
    ('analysis_limits',{'max_memory_bytes':8*2**30}),('capture_sha256','e'*64),
    ('ml_work_budget',{'max_fields':5000000}),('threads',4)])
def test_configuration_changes_disqualify_pair(key,value):
    a=receipt();b=copy.deepcopy(a);b[key]=value
    assert module().validate_pair(a,b)


@pytest.mark.parametrize('change', ['partial','skipped','failed','identity','empty','memory'])
def test_incomplete_or_invalid_receipts_never_pass(change):
    a=receipt();b=copy.deepcopy(a);run=b['runs'][0]
    if change=='partial':run['summary']['analysis_incomplete']=True
    elif change=='skipped':run['summary']['ml_fields_skipped']=1
    elif change=='failed':run['status']='failed'
    elif change=='identity':run['verified_capture_evidence']['identity_status']='unknown'
    elif change=='empty':run['summary']['ml_fields_eligible']=run['summary']['ml_fields_evaluated']=0
    else:run['lifetime_peak_rss']=5*2**30
    assert module().validate_pair(a,b)


def test_historical_capture_requires_its_known_counts_even_if_both_runs_agree():
    a=receipt()
    owner_sha='42e52f7ebb470d45e3d883ba6c800a11fce17357cf0edad417fefb8ca059c9ce'
    a['capture_sha256']=a['runs'][0]['verified_capture_evidence']['capture_sha256']=owner_sha
    a['runs'][0]['summary'].update(packets_captured=361389,http_messages=120462,
        fields_extracted=2349009,ml_fields_excluded_by_policy=421617,
        ml_fields_eligible=1927392,ml_fields_evaluated=1927392,
        rules_findings=244046,ml_findings=180694,potential_leaks=424740)
    assert module().validate_pair(a,copy.deepcopy(a))==[]
    # A matching digest and 100% of the wrong eligible count cannot pass.
    a['runs'][0]['summary']['ml_fields_eligible']=1927391
    a['runs'][0]['summary']['ml_fields_evaluated']=1927391
    assert module().validate_pair(a,copy.deepcopy(a))
