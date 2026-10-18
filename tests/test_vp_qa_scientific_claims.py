"""Task C - scientific-accuracy audit of what the product and its documents CLAIM (read-only on others' files).

Checks: (1) the headline offline numbers shown to the VP equal the committed evaluation results and are tied to the 1,058-field
synthetic challenge; (2) no text presents offline F1 as live-file accuracy; (3) raw scores are never called calibrated/probability;
(4) rules and model are distinguished; (5) nothing claims proof of theft/exfiltration/breach; (6) QA's own documents obey the same rules.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
UI = [ROOT / "src/packet_pii/dashboard_static/index.html", ROOT / "src/packet_pii/dashboard_static/app.js"]
GUIDES = [ROOT / "docs/showcase/VP_DEMO_GUIDE.md", ROOT / "docs/sunday-vp-dashboard.md", ROOT / "docs/sunday-hybrid-integration.md",
          ROOT / "docs/ml/V2_MODEL_CARD.md", ROOT / "docs/ml/V2_EVALUATION.md"]
QA_DOCS = [ROOT / "docs/vp-qa/SIMPLE_EXPLANATION.md", ROOT / "docs/vp-qa/TECHNICAL_VALIDATION.md"]
RESULTS = ROOT / "docs/ml/results"
NEGATION = re.compile(r"\b(not|no|never|cannot|can't|without|none|nothing|nor|neither|un(?:calibrated)|isn't|doesn't|does not|do not|is not|are not|don't|rather than)\b", re.I)


def _text(path: Path) -> str:
    return re.sub(r"<[^>]+>", " ", path.read_text(encoding="utf-8"))          # strip tags so HTML prose reads as prose


def _contexts(text: str, pattern: str, before=90, after=60):
    return [text[max(0, m.start() - before): m.end() + after] for m in re.finditer(pattern, text, re.I)]


def _existing(paths):
    return [p for p in paths if p.is_file()]


@pytest.fixture(scope="module")
def challenge():
    return json.loads((RESULTS / "v2_eval_challenge.json").read_text())["datasets"]["challenge"]


# ------------------------------------------------------------------ (1) numbers tie to the committed results
def test_ui_offline_numbers_equal_committed_challenge_results(challenge):
    v2, rules = challenge["systems"]["bilstm:v2"], challenge["systems"]["rules_strong"]
    from packet_pii.research import benchmark_metadata
    html = UI[0].read_text(encoding="utf-8")                          # raw markup: the element ids live inside tags
    bench = benchmark_metadata()                                      # the dashboard renders this payload via /api/benchmark
    pct = lambda x: f"{x * 100:.1f}"
    assert pct(v2["micro"]["precision"]) == "83.6" and pct(v2["micro"]["recall"]) == "80.1" and pct(v2["micro"]["f1"]) == "81.8"
    assert pct(rules["micro"]["f1"]) == "31.7"
    assert (pct(bench["precision"]), pct(bench["recall"]), pct(bench["f1"])) == ("83.6", "80.1", "81.8")
    assert bench["dataset"]["fields"] == 1058 and "not accuracy of an uploaded pcap" in bench["scope"].lower()
    for element in ("benchmark-precision", "benchmark-recall", "benchmark-f1", "benchmark-ci"):
        assert element in html, element                               # numbers are rendered from the API, never hard-coded
    lo, hi = v2["ci95_bootstrap"]["f1"]
    assert (f"{lo * 100:.1f}", f"{hi * 100:.1f}") == ("79.4", "84.0") and [round(x, 3) for x in bench["bootstrap_ci"]] == [0.794, 0.84]
    manifest = json.loads((RESULTS / "challenge_v1_manifest.json").read_text())
    assert manifest["examples"] == 1058 and "SYNTHETIC" in manifest["kind"].upper() and challenge["examples"] == 1058


def test_headline_f1_is_below_the_declared_target_and_says_so(challenge):
    f1 = challenge["systems"]["bilstm:v2"]["micro"]["f1"]
    assert f1 < 0.88                                                  # the engineering target was NOT reached on the independent set
    assert "No.** Frozen out-of-generator challenge benchmark" in (ROOT / "docs/ml/V2_EVALUATION.md").read_text(encoding="utf-8")


def test_every_benchmark_figure_is_tied_to_synthetic_offline_context():
    for path in _existing(UI + GUIDES + QA_DOCS):
        text = _text(path)
        for m in re.finditer(r"(?<![\d.])(?:81\.8\s*%?|0\.818)(?![\d])", text):
            headings = [ln for ln in text[:m.start()].splitlines() if ln.lstrip().startswith("#")]
            low = (text[max(0, m.start() - 700): m.end() + 700] + " " + (headings[-1] if headings else "")).lower()   # nearby prose + section title
            declared_up_front = "synthetic" in text[:900].lower()          # document-level disclosure at the top counts
            assert "synthetic" in low or declared_up_front, f"{path.name}: 81.8%/0.818 without 'synthetic' nearby"
            assert any(w in low for w in ("offline", "benchmark", "challenge", "published", "not computed from", "not live", "not this file")), path.name


# ------------------------------------------------------------------ (2) offline F1 is never live-file accuracy
def test_live_file_accuracy_is_declared_unmeasurable():
    js = _text(UI[1])
    html = _text(UI[0])
    assert "No live-file precision/recall/F1 is available" in js
    assert "Live-file precision, recall and F1 are NOT measured" in html
    assert "NOT LIVE FILE ACCURACY" in html.upper() or "not live file accuracy" in html.lower()
    guide = _text(ROOT / "docs/showcase/VP_DEMO_GUIDE.md")
    assert "not measurable" in guide and "are not computed from the uploaded PCAP" in guide


def test_no_text_presents_live_accuracy_or_f1_without_negation():
    for path in _existing(UI + GUIDES + QA_DOCS):
        for ctx in _contexts(_text(path), r"\blive(?:[- ]file)?\s+(?:accuracy|precision|recall|f1)\b"):
            assert NEGATION.search(ctx), f"{path.name}: {ctx!r}"


# ------------------------------------------------------------------ (3) uncalibrated
def test_raw_scores_are_never_called_calibrated_probabilities():
    for path in _existing(UI + GUIDES + QA_DOCS):
        text = _text(path)
        for ctx in _contexts(text, r"(?<!un)calibrated"):
            assert NEGATION.search(ctx), f"{path.name}: {ctx!r}"
        for ctx in _contexts(text, r"\b(?:confidence|score)s?\b[^.\n]{0,40}\bprobabilit(?:y|ies)\b|\bprobabilit(?:y|ies)\b[^.\n]{0,40}\b(?:of correctness|of being)"):
            assert NEGATION.search(ctx), f"{path.name}: {ctx!r}"


def test_report_and_findings_label_scores_as_uncalibrated(tmp_path):
    from packet_pii.engine import analyze
    from test_vp_qa_support import ml_findings, showcase_pcap, v2_detector
    r = analyze(showcase_pcap(tmp_path), ml_detector=v2_detector())
    assert r["metadata"]["confidence_type"] == "separate_rule_heuristic_and_uncalibrated_model_scores"
    assert {f["confidence_type"] for f in ml_findings(r)} == {"uncalibrated_model_score"}
    assert any("uncalibrated" in lim for lim in r["limitations"])
    calib = json.loads((RESULTS / "v2_eval_challenge.json").read_text())["datasets"]["challenge"]["raw_score_reliability"]["v2"]
    assert calib["ece_vs_span_precision"] > 0.05                      # measurably over-confident under shift: it IS uncalibrated


# ------------------------------------------------------------------ (4) rules vs model distinguished
def test_ui_distinguishes_rules_from_model_and_labels_provenance():
    js = UI[1].read_text(encoding="utf-8"); html = _text(UI[0])       # raw JS: '<' comparisons must not be treated as tags
    assert "BiLSTM · uncalibrated raw model score" in js and "Rules · heuristic score" in js
    assert "Rules: heuristic scores · BiLSTM: uncalibrated raw model scores" in html
    assert "Rules: heuristic" in html or "rule scores are heuristics" in js


def test_strong_rules_figure_is_a_research_baseline_not_the_live_rules_engine(challenge):
    s = challenge["systems"]
    assert s["host_detect_py"]["micro"]["f1"] < s["rules_strong"]["micro"]["f1"]     # live engine rules 0.134 vs research baseline 0.317
    assert round(s["host_detect_py"]["micro"]["f1"], 3) == 0.134 and round(s["rules_strong"]["micro"]["f1"], 3) == 0.317


def test_benchmark_comparators_are_labelled_research_baseline_vs_live_rule_engine():
    """F-07 fixed. The static 'strong rules' tile no longer exists: /api/benchmark now serves both comparators with explicit
    labels and the Model Laboratory renders each label and note next to its numbers."""
    from packet_pii.research import benchmark_metadata
    comparators = {c["key"]: c for c in benchmark_metadata()["comparators"]}
    assert comparators["rules_strong"]["label"].startswith("Research baseline") and "not the rule engine in this application" in comparators["rules_strong"]["note"]
    assert comparators["host_detect_py"]["label"].startswith("Live rule engine")
    assert round(comparators["host_detect_py"]["f1"], 3) == 0.134 and round(comparators["rules_strong"]["f1"], 3) == 0.317
    lab = (ROOT / "src/packet_pii/dashboard_static/lab.js").read_text(encoding="utf-8")
    assert "c.label" in lab and "c.note" in lab and "not met" in lab
    assert benchmark_metadata()["target"] == {"f1": 0.88, "met": False, "note": "Engineering target for an independent set; not met by the measured V2 result."}


# ------------------------------------------------------------------ (5) no claim of theft / exfiltration / breach
def test_nothing_claims_proof_of_theft_exfiltration_or_breach():
    for path in _existing(UI + GUIDES + QA_DOCS):
        text = _text(path)
        for ctx in _contexts(text, r"exfiltrat|\btheft\b|\bbreach(?:ed|es)?\b|\bstolen\b|\bproves?\b|\bproof\b|confirmed (?:leak|exposure)"):
            assert NEGATION.search(ctx), f"{path.name}: {ctx!r}"


def test_report_wording_is_potential_exposure_only(tmp_path):
    from packet_pii.engine import analyze
    from test_vp_qa_support import showcase_pcap
    r = analyze(showcase_pcap(tmp_path))
    assert any("not proof of exfiltration" in lim for lim in r["limitations"])
    assert "potential_leaks" in r["summary"] and "confirmed" not in json.dumps(r["summary"]).lower()


# ------------------------------------------------------------------ (6) QA documents obey the rules and tie to executed results
def test_qa_documents_exist_and_carry_required_disclosures():
    docs = {p.name: p.read_text(encoding="utf-8") for p in QA_DOCS if p.is_file()}
    if len(docs) < 2:
        pytest.skip("QA documents not written yet")
    for name, text in docs.items():
        low = text.lower()
        assert "synthetic" in low and "not proof" in low and "uncalibrated" in low, name
        assert "0.818" in text or "81.8" in text, name
        assert "live" in low and ("not measur" in low or "no live" in low), name


def test_technical_validation_measured_block_matches_a_fresh_run(tmp_path):
    """The machine-readable block in TECHNICAL_VALIDATION.md is recomputed here from the engine; the document cannot drift from the code."""
    doc = ROOT / "docs/vp-qa/TECHNICAL_VALIDATION.md"
    if not doc.is_file():
        pytest.skip("not written yet")
    m = re.search(r"<!-- vp-qa-measured:\s*(\{.*?\})\s*-->", doc.read_text(encoding="utf-8"), re.S)
    assert m, "measured block missing"
    claimed = json.loads(m.group(1))
    from packet_pii.engine import analyze
    from test_vp_qa_support import is_v2_checkpoint, showcase_pcap, v2_detector
    det = v2_detector()
    if not is_v2_checkpoint(det):
        pytest.skip("pinned to the V2 checkpoint")
    p = showcase_pcap(tmp_path)
    rules, hyb = analyze(p), analyze(p, ml_detector=det)
    fresh = {"model_version": det.model_version, "packets": hyb["summary"]["packets_captured"], "flows": hyb["summary"]["flows_processed"],
             "http_messages": hyb["summary"]["http_messages"], "rules_findings": hyb["summary"]["rules_findings"],
             "ml_findings": hyb["summary"]["ml_findings"], "ml_fields_evaluated": hyb["summary"]["ml_fields_evaluated"],
             "ml_fields_excluded_by_policy": hyb["summary"]["ml_fields_excluded_by_policy"], "potential_leaks_hybrid": hyb["summary"]["potential_leaks"],
             "potential_leaks_rules_only": rules["summary"]["potential_leaks"]}
    assert claimed == fresh


def test_every_test_named_in_the_technical_document_exists():
    """Verifiability: each `test_...` cited in TECHNICAL_VALIDATION.md (wildcards allowed) matches a real test function."""
    import fnmatch
    doc = ROOT / "docs/vp-qa/TECHNICAL_VALIDATION.md"
    if not doc.is_file():
        pytest.skip("not written yet")
    defined = set()
    for f in (ROOT / "tests").glob("test_vp_qa_*.py"):
        defined |= set(re.findall(r"^def (test_\w+)\(", f.read_text(encoding="utf-8"), re.M))
    cited = set(re.findall(r"`(test_[\w*]+)`", doc.read_text(encoding="utf-8")))
    assert cited, "no tests cited"
    missing = sorted(c for c in cited if not fnmatch.filter(defined, c))
    assert missing == []
