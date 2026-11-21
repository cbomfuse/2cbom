"""Benchmark results of the orchestrator (cbomfuse/orch) inside 2CBOM.

The fixture in ``tests/fixtures/benchmark`` is a synthetic orchestrator run directory (``scorecard.json``
with ledger and ``twocbom/tools.json``) produced with the orchestrator's own code by
``make_fixture.py``; ``golden-reconcile.json`` holds the orchestrator's answers to a set of queries.
"""
import hashlib
import itertools
import json
import os
import shutil

import pytest

from conftest import ROOT

from twocbom.benchmark import (Benchmark, BenchmarkError, Reliability, benchmark_family, language_of_location,
                               load_benchmark, purl_family)
from twocbom.canonical import jcs_dumps
from twocbom.cli import main
from twocbom.export import to_markdown
from twocbom.ingest import ingest_document
from twocbom.knowledge import load_kb
from twocbom.merge import MergeOptions, merge_ingested
from twocbom.validate import build_schema, validate_document

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "benchmark")
SCORECARD = os.path.join(FIXTURE, "scorecard.json")
TOOLS_JSON = os.path.join(FIXTURE, "twocbom", "tools.json")
TS = "2026-11-20T00:00:00Z"
JAVA = "src/main/java/com/example/Crypto.java"
PY = "app/hashing.py"
PRIORS_KEYS = ("schemaVersion", "scoringModelVersion", "orchestrator", "run", "baseline", "cases", "tools", "coverage",
               "scores", "pairwise", "summary")


def scorecard_doc() -> dict:
    with open(SCORECARD, encoding="utf-8") as fh:
        return json.load(fh)


def priors_doc() -> dict:
    """priors.json as orchestrator.export.build_priors writes it: the scorecard without the ledger."""
    doc = scorecard_doc()
    out = {k: doc[k] for k in PRIORS_KEYS if k in doc}
    out["ledgerIncluded"] = False
    return out


def cbom(tools, assets, component=None):
    """A minimal CycloneDX 1.6 CBOM. ``assets``: (name, primitive, location, line[, extra algorithm properties])."""
    comps = []
    for i, a in enumerate(assets):
        name, prim, loc, line = a[:4]
        props = {"primitive": prim} if prim else {}
        props.update(a[4] if len(a) > 4 else {})
        comps.append({"type": "cryptographic-asset", "bom-ref": f"asset-{i}", "name": name,
                      "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": props},
                      "evidence": {"occurrences": [{"location": loc, "line": line}]}})
    meta = {"tools": {"components": [{"type": "application", "name": n, "version": v} for n, v in tools]}}
    if component:
        meta["component"] = component
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": meta, "components": comps}


def ingest(doc, name):
    return ingest_document(doc, path=name)


def merge(docs, benchmark=None):
    # inputs are named by content: a source's path is part of the document
    inputs = [ingest(d, hashlib.sha256(jcs_dumps(d).encode()).hexdigest()[:12] + ".json") for d in docs]
    return merge_ingested(inputs, MergeOptions(timestamp=TS, trace=False, benchmark=benchmark)).document


def conflict(doc, cid, attribute):
    return next(c for c in doc["lineage"]["conflicts"] if c["subject"] == cid and c["attribute"] == attribute)


def resolved_tool_primitive(doc, cid):
    return conflict(doc, cid, "toolPrimitive")["chosen"]


K_AES = cbom([("CBOMkit", "2.3.0")], [("AES-128-GCM", "block-cipher", JAVA, 12)])
F_AES = cbom([("cryptobom-forge", "1.1.0")], [("AES-128-GCM", "ae", JAVA, 12)])
K_SHA = cbom([("CBOMkit", "2.3.0")], [("SHA-256", "hash", PY, 5)])
X_SHA = cbom([("cdxgen", "13.7.0")], [("SHA-256", "other", PY, 5)])


@pytest.fixture(scope="module")
def priors_only():
    return Benchmark(None, Reliability(scorecard_doc()))


@pytest.fixture(scope="module")
def full():
    return load_benchmark(FIXTURE)


# --------------------------------------------------------------------------- #
# the port of orchestrator.reconcile
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("source", ["scorecard", "priors"])
def test_reconcile_matches_the_orchestrator(source):
    with open(os.path.join(FIXTURE, "golden-reconcile.json"), encoding="utf-8") as fh:
        golden = json.load(fh)[source]
    rel = Reliability(scorecard_doc() if source == "scorecard" else priors_doc())
    assert rel.has_ledger is (source == "scorecard")
    for entry in golden:
        q = entry["query"]
        expected = dict(entry["answer"])
        expected.pop("valueEvidence", None)
        got = rel.reconcile(q["toolA"], q["toolB"], q["category"], q["attribute"], q.get("valueA"), q.get("valueB"))
        assert got.to_dict() == expected, q


def test_reconcile_matches_a_live_orchestrator_when_installed():
    reconcile = pytest.importorskip("orchestrator.reconcile")
    export = pytest.importorskip("orchestrator.export")
    doc = scorecard_doc()
    assert export.build_priors(doc) == priors_doc()
    import random
    rng = random.Random(3)
    tools = ["cbomkit", "cdxgen", "cryptobom-forge", "semgrep"]
    attrs = ["primitive", "oid", "parameterSet", "parameterSetIdentifier", "mode", "identity", "size", "type",
             "version", "purl", "executionEnvironment", None]
    facets = {"language": ["Java", "Python", "Go"], "assetType": ["algorithm", "related-crypto-material", "library"],
              "subtype": ["ae", "hash", "block-cipher", "secret-key", "library"], "family": ["aes", "sha2", "rsa", "x"]}
    for d in (doc, priors_doc()):
        theirs, ours = reconcile.Scorecard(d), Reliability(d)
        for _ in range(400):
            a, b = rng.sample(tools, 2)
            cat = {k: rng.choice(v) for k, v in facets.items() if rng.random() < 0.6}
            attr = rng.choice(attrs)
            expected = theirs.reconcile(a, b, cat, attr).to_dict()
            expected.pop("valueEvidence", None)
            assert ours.reconcile(a, b, cat, attr).to_dict() == expected


def test_reconcile_is_symmetric_and_cached(priors_only):
    rel = priors_only.reliability
    cat = {"language": "Java", "assetType": "algorithm", "subtype": "ae", "family": "aes"}
    ab = rel.answer("cryptobom-forge", "cbomkit", cat, "primitive")
    assert (ab.tool_a, ab.tool_b) == ("cbomkit", "cryptobom-forge")          # canonical order
    assert ab is rel.answer("cbomkit", "cryptobom-forge", cat, "primitive")
    assert ab.preferred == "cryptobom-forge" and ab.tier == "head-to-head"
    assert ab.category_used == {"assetType": "algorithm", "subtype": "ae", "family": "aes"}


def test_vocabulary_bridges():
    assert benchmark_family("tdea") == "3des" and benchmark_family("x25519") == "ecdh" and benchmark_family("aes") == "aes"
    assert language_of_location("src/main/java/A.java") == "Java" and language_of_location("x/y.cs") == "C#"
    assert language_of_location("lib/a.ts") == "TypeScript" and language_of_location("lib/a.js") == "JavaScript"
    assert language_of_location("host:443") is None and language_of_location("") is None
    assert language_of_location("/scan/pki/server.crt") == "Artifacts" and language_of_location("keystores/a.p12") == "Artifacts"
    assert language_of_location("secrets/app.env") == "Artifacts" and language_of_location("tls/openssl.cnf") == "Artifacts"
    assert language_of_location("keys/deploy_ed25519") is None
    assert purl_family("pkg:pypi/cryptography@43.0.1") == "pypi/cryptography"
    assert purl_family("pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78?type=jar") == "maven/org.bouncycastle/bcprov-jdk18on"


# --------------------------------------------------------------------------- #
# loading and validation
# --------------------------------------------------------------------------- #
def test_load_run_directory(full):
    assert full.tool_profiles["version"] == "orchestrator-fixture-synthetic"
    assert full.reliability.has_ledger and full.reliability.run_id == "fixture-synthetic"
    with open(SCORECARD, "rb") as fh:
        assert full.reliability.digest == "sha256:" + hashlib.sha256(fh.read()).hexdigest()
    assert full.scoring_model_version == "1.0"


def test_load_variants(tmp_path):
    # a run directory with only priors.json
    run = tmp_path / "run"
    (run / "twocbom").mkdir(parents=True)
    (run / "priors.json").write_text(json.dumps(priors_doc()))
    b = load_benchmark(run)
    assert b.tool_profiles is None and not b.reliability.has_ledger
    # the twocbom/ export directory: tools.json + priors.json
    shutil.copy(TOOLS_JSON, run / "twocbom" / "tools.json")
    (run / "twocbom" / "priors.json").write_text(json.dumps(priors_doc()))
    b = load_benchmark(run / "twocbom")
    assert b.tool_profiles is not None and b.reliability is not None
    # single files of either kind, and explicit paths
    assert load_benchmark(TOOLS_JSON).reliability is None
    assert load_benchmark(SCORECARD).tool_profiles is None
    b = load_benchmark(tool_profiles=TOOLS_JSON, priors=SCORECARD)
    assert b.tool_profiles is not None and b.reliability.has_ledger


def test_scoring_model_1_1_is_accepted():
    doc = scorecard_doc()
    doc["scoringModelVersion"] = "1.1"
    assert Reliability(doc).scoring_model_version == "1.1"


@pytest.mark.parametrize("mutate, message", [
    (lambda d: d.update(scoringModelVersion="2.0"), "scoring model"),
    (lambda d: d.pop("scoringModelVersion"), "scoring model"),
    (lambda d: d.update(ledger={"not": "a list"}), "ledger"),
])
def test_priors_are_refused_when_they_do_not_fit(mutate, message):
    doc = scorecard_doc()
    mutate(doc)
    with pytest.raises(BenchmarkError, match=message):
        Reliability(doc)


@pytest.mark.parametrize("mutate, message", [
    (lambda d: d.update(scoringModelVersion="0.9"), "scoring model"),
    (lambda d: d["tools"]["cbomkit"].update(trust=101), "trust"),
    (lambda d: d["tools"]["cbomkit"].update(trust="80"), "trust"),
    (lambda d: d["tools"]["cbomkit"].update(detectionMethod="guesswork"), "detection method"),
    (lambda d: d["tools"]["cbomkit"].update(strengths="oid"), "strengths"),
])
def test_tool_profiles_are_validated(mutate, message):
    with open(TOOLS_JSON, encoding="utf-8") as fh:
        doc = json.load(fh)
    mutate(doc)
    with pytest.raises(BenchmarkError, match=message):
        Benchmark(doc)


def test_missing_and_mismatched_inputs(tmp_path):
    with pytest.raises(BenchmarkError):
        load_benchmark(tmp_path / "nope")
    with pytest.raises(BenchmarkError, match="no twocbom/tools.json"):
        load_benchmark(tmp_path)
    with pytest.raises(BenchmarkError):
        Benchmark(None, None)
    with open(TOOLS_JSON, encoding="utf-8") as fh:
        tp = json.load(fh)
    tp["scoringModelVersion"] = "1.0"
    other = scorecard_doc()
    other["scoringModelVersion"] = "1.0"
    Benchmark(tp, Reliability(other))      # same model: fine
    (tmp_path / "x.json").write_text("{\"hello\": 1}")
    with pytest.raises(BenchmarkError, match="neither"):
        load_benchmark(tmp_path / "x.json")


# --------------------------------------------------------------------------- #
# tool profiles and attribution
# --------------------------------------------------------------------------- #
def test_longest_alias_wins():
    tp = load_kb().tool_profiles
    assert tp.profile("cbomkit-theia 1.3").name == "cbomkit-theia"     # not "cbomkit"
    assert tp.profile("CBOM-Lens").name == "cbom-lens"                 # not the generic "cbom" (ibm-cbom)
    assert tp.profile("IBM/CBOMkit").name == "cbomkit"
    assert tp.profile("CSNP CryptoScan").name == "cryptoscan"
    assert tp.profile("IBM Research cbom-scanner").name == "ibm-cbom"
    assert tp.profile("nothing-known").basis == "default"


def test_attribution_reads_every_listed_tool_and_the_cbom_lens_component():
    tp = load_kb().tool_profiles
    prof, name, version = tp.attribute([("dosai", "4.1.0"), ("@cdxgen/cdxgen", "13.2.0")])
    assert (prof.name, name, version) == ("cdxgen", "@cdxgen/cdxgen", "13.2.0")
    prof, name, version = tp.attribute([], ("CBOM-Lens", "0.4.0"))
    assert (prof.name, version) == ("cbom-lens", "0.4.0")
    prof, _, _ = tp.attribute([], ("payments-service", "1.0"))           # an ordinary subject is not a tool
    assert prof.name == "unknown"
    prof, name, _ = tp.attribute([("in-house-scanner", "1")], ("CBOM-Lens", "0.4.0"))
    assert prof.name == "in-house-scanner" and prof.basis == "default"   # metadata.tools takes precedence


def test_cbom_lens_cbom_is_attributed_end_to_end():
    doc = cbom([], [("AES-128-GCM", "ae", "/etc/app/conf.yaml", 3)],
               component={"type": "application", "bom-ref": "cbom-lens", "name": "CBOM-Lens", "version": "0.4.0"})
    doc["metadata"].pop("tools")
    src = merge([doc])["lineage"]["sources"][0]
    assert src["tool"] == {"name": "cbom-lens", "version": "0.4.0"} and src["detectionMethod"] == "static-binary"


def test_overlay_replaces_measured_tools_and_keeps_the_rest(full):
    base = load_kb().tool_profiles
    over = base.overlay(full.tool_profiles)
    k = over.profile("cbomkit")
    assert (k.trust, k.strengths, k.basis) == (80, ("oid",), "benchmark")
    assert over.profile("sonar-cryptography").name == "cbomkit"          # hand-set alias kept
    assert over.profile("cyclonedx-python-lib").name == "cryptobom-forge"  # self-reported name added
    assert over.profile("dosai").name == "cdxgen"
    assert over.profile("semgrep").trust == 60 and over.profile("semgrep").basis == "knowledge-base"
    assert base.profile("cyclonedx-python-lib").name != "cryptobom-forge"  # the packaged profile is untouched


def test_benchmark_profile_attributes_and_weights_sources(full):
    forge = cbom([("cyclonedx-python-lib", "4.2.2"), ("GitHub CodeQL", "2.27.4")], [("AES-128-GCM", "ae", JAVA, 12)])
    plain = merge([forge])["lineage"]["sources"][0]
    assert plain["tool"]["name"] == "codeql"                               # hand-set profile: misattributed
    src = merge([forge], full)["lineage"]["sources"][0]
    assert src["tool"] == {"name": "cryptobom-forge", "version": "4.2.2"} and src["trust"] == 79


# --------------------------------------------------------------------------- #
# settlement with the benchmark
# --------------------------------------------------------------------------- #
def test_benchmark_decides_a_conflict_the_scalar_order_gets_wrong(priors_only):
    cid = "2cbom:alg:aes-128-gcm"
    plain = merge([K_AES, F_AES])
    assert resolved_tool_primitive(plain, cid) == "block-cipher"       # cbomkit: hand-set strength on primitive
    assert conflict(plain, cid, "toolPrimitive")["rule"] == "settle.tool-precedence"
    doc = merge([K_AES, F_AES], priors_only)
    c = conflict(doc, cid, "toolPrimitive")
    assert c["chosen"] == "ae" and c["rule"] == "settle.benchmark-preference"
    [r] = c["reconciliation"]
    assert (r["toolA"], r["toolB"], r["preferred"], r["tier"]) == ("cbomkit", "cryptobom-forge", "cryptobom-forge", "head-to-head")
    assert r["attribute"] == "primitive" and r["confidence"] == 0.8804
    assert r["category"] == {"assetType": "algorithm", "subtype": "ae", "family": "aes", "language": "Java"}
    assert r["categoryUsed"] == {"assetType": "algorithm", "subtype": "ae", "family": "aes"} and r["backoffSteps"] == 1
    assert r["toolVersions"] == {"cbomkit": "2.3.0", "cryptobom-forge": "1.1.0"}
    assert {x["value"]: x["preference"] for x in c["candidates"]} == {"ae": 1, "block-cipher": -1}
    finding = next(f for f in doc["findings"] if f["code"] == "2CBOM-C14-SOURCE-CONFLICT" and f["subject"] == cid)
    assert "by benchmark preference" in finding["message"] and "benchmark prefers cryptobom-forge" in finding["message"]
    assert validate_document(doc) == []


def test_undecided_answers_fall_back_to_strength_and_trust(priors_only, full):
    cid = "2cbom:alg:sha2-256"
    doc = merge([K_SHA, X_SHA], priors_only)
    c = conflict(doc, cid, "toolPrimitive")
    assert c["rule"] == "settle.tool-precedence" and c["chosen"] == "hash"   # hand-set: cbomkit strength
    assert c["reconciliation"][0]["decision"] == "undecided" and c["reconciliation"][0]["tier"] == "attribute"
    assert "benchmark undecided" in next(f["message"] for f in doc["findings"]
                                         if f["code"] == "2CBOM-C14-SOURCE-CONFLICT" and f["subject"] == cid)
    # with the benchmark's own profile the scalar order is the measured one: cdxgen has the primitive strength
    c = conflict(merge([K_SHA, X_SHA], full), cid, "toolPrimitive")
    assert c["rule"] == "settle.tool-precedence" and c["chosen"] == "other"


def test_copeland_score_over_three_tools(priors_only):
    x_aes = cbom([("cdxgen", "13.7.0")], [("AES-128-GCM", "ae", JAVA, 12)])
    doc = merge([K_AES, F_AES, x_aes], priors_only)
    c = conflict(doc, "2cbom:alg:aes-128-gcm", "toolPrimitive")
    prefs = {(x["origin"], x["value"]): x["preference"] for x in c["candidates"]}
    assert sorted(prefs.values()) == [-2, 1, 1]
    assert c["chosen"] == "ae" and c["rule"] == "settle.benchmark-preference"
    assert {(r["toolA"], r["toolB"]) for r in c["reconciliation"]} == {("cbomkit", "cdxgen"), ("cbomkit", "cryptobom-forge")}


def test_tools_the_benchmark_did_not_measure_are_not_compared(priors_only):
    semgrep = cbom([("semgrep", "1.90")], [("AES-128-GCM", "ae", JAVA, 12)])
    c = conflict(merge([K_AES, semgrep], priors_only), "2cbom:alg:aes-128-gcm", "toolPrimitive")
    assert c["rule"] == "settle.tool-precedence" and "reconciliation" not in c and c["chosen"] == "block-cipher"
    k2 = cbom([("CBOMkit", "2.3.0")], [("AES-128-GCM", "ae", "src/Other.java", 3)])
    c = conflict(merge([K_AES, k2], priors_only), "2cbom:alg:aes-128-gcm", "toolPrimitive")
    assert "reconciliation" not in c                                          # one tool, two sources


def test_knowledge_base_values_are_never_put_to_the_benchmark(priors_only):
    k = cbom([("CBOMkit", "2.3.0")], [("AES-128-GCM", "ae", JAVA, 12)])
    f = cbom([("cryptobom-forge", "1.1.0")], [("AES-128-GCM", "ae", JAVA, 12)])
    k["components"][0]["cryptoProperties"]["oid"] = "1.2.3"
    f["components"][0]["cryptoProperties"]["oid"] = "2.16.840.1.101.3.4.1.6"
    c = conflict(merge([k, f], priors_only), "2cbom:alg:aes-128-gcm", "oid")
    assert c["rule"] == "settle.kb-authoritative" and "reconciliation" not in c


def test_merge_with_benchmark_is_order_independent(priors_only, full):
    x_aes = cbom([("cdxgen", "13.7.0")], [("AES-128-GCM", "ae", JAVA, 12)])
    docs = [K_AES, F_AES, x_aes, K_SHA, X_SHA]
    for bench in (priors_only, full):
        ref = merge(docs, bench)["integrity"]["digest"]
        for perm in itertools.permutations(docs):
            assert merge(list(perm), bench)["integrity"]["digest"] == ref
        assert merge(docs + [docs[1]], bench)["integrity"]["digest"] == ref


def test_without_a_benchmark_nothing_changes():
    doc = merge([K_AES, F_AES, K_SHA, X_SHA])
    assert "benchmark" not in doc["lineage"]
    assert all("reconciliation" not in c for c in doc["lineage"]["conflicts"])
    assert "check.I03-benchmark-version" not in doc["lineage"]["ruleset"]["firedRules"]


def test_lineage_records_the_benchmark(full):
    doc = merge([K_AES, F_AES], full)
    b = doc["lineage"]["benchmark"]
    assert b["scoringModelVersion"] == "1.0"
    assert b["toolProfiles"]["version"] == "orchestrator-fixture-synthetic"
    assert b["toolProfiles"]["tools"]["cdxgen"]["version"] == "13.7.0"
    assert b["toolProfiles"]["tools"]["cdxgen"]["reportedVersion"] == "4.1.0"
    assert b["priors"]["run"] == "fixture-synthetic" and b["priors"]["ledger"] is True
    assert b["priors"]["digest"] == full.reliability.digest
    assert b["settlement"]["rule"] == "reconcile, scalar fallback" and b["settlement"]["undecidedBelow"] == 0.6
    assert validate_document(doc) == []

    def numbers(x):
        if isinstance(x, dict):
            for v in x.values():
                yield from numbers(v)
        elif isinstance(x, list):
            for v in x:
                yield from numbers(v)
        elif isinstance(x, float):
            yield x
    for x in numbers(doc["lineage"]):                     # at most four decimal digits (canonical form)
        assert round(x, 4) == x


def test_version_mismatch_is_reported(full):
    old_k = cbom([("CBOMkit", "2.2.0")], [("AES-128-GCM", "block-cipher", JAVA, 12)])
    doc = merge([old_k, F_AES], full)
    [f] = [f for f in doc["findings"] if f["code"] == "2CBOM-I03-UNBENCHMARKED-VERSION"]
    assert f["severity"] == "info" and "cbomkit 2.2.0" in f["message"] and "2.3.0" in f["message"]
    assert not [f for f in merge([K_AES, F_AES], full)["findings"] if f["code"] == "2CBOM-I03-UNBENCHMARKED-VERSION"]
    v_prefixed = cbom([("CBOMkit", "v2.3.0")], [("AES-128-GCM", "block-cipher", JAVA, 12)])
    assert not [f for f in merge([v_prefixed], full)["findings"] if f["code"] == "2CBOM-I03-UNBENCHMARKED-VERSION"]


def test_report_shows_the_benchmark(full):
    md = to_markdown(merge([K_AES, F_AES], full))
    assert "## Benchmark" in md and "orchestrator-fixture-synthetic" in md
    assert "benchmark, cbomkit vs cryptobom-forge: prefers cryptobom-forge" in md


# --------------------------------------------------------------------------- #
# determinism of descriptor selection (order dependence found on real inputs)
# --------------------------------------------------------------------------- #
def test_descriptor_is_chosen_by_content_not_by_arrival():
    """Two tools report P-256 with different primitive hints, so the asset has two descriptor candidates."""
    a = cbom([("CBOMkit", "2.3.0")], [("EC", "pke", JAVA, 7, {"curve": "P-256"})])
    b = cbom([("cryptobom-forge", "1.1.0")], [("EC", "other", "src/main/java/com/example/Keys.java", 9, {"curve": "P-256"})])
    first = merge([a, b])
    second = merge([b, a])
    assert first["integrity"]["digest"] == second["integrity"]["digest"]
    descs = [x for x in first["assets"] if x["id"].startswith("2cbom:alg:ec")]
    assert descs and all(x.get("assessment") for x in descs)


# --------------------------------------------------------------------------- #
# command line and schema
# --------------------------------------------------------------------------- #
def test_cli_merge_benchmark_and_reconcile(tmp_path, capsys):
    k, f = tmp_path / "k.json", tmp_path / "f.json"
    k.write_text(json.dumps(K_AES))
    f.write_text(json.dumps(F_AES))
    out = tmp_path / "merged.json"
    assert main(["merge", str(k), str(f), "-o", str(out), "--benchmark", FIXTURE, "--timestamp", TS]) == 0
    doc = json.loads(out.read_text())
    assert conflict(doc, "2cbom:alg:aes-128-gcm", "toolPrimitive")["chosen"] == "ae"
    assert "consulted for 1 conflict(s), decided 1" in capsys.readouterr().err
    assert main(["merge", str(k), "-o", str(out), "--benchmark", str(tmp_path / "missing")]) == 2
    assert main(["benchmark", FIXTURE]) == 0
    assert "orchestrator-fixture-synthetic" in capsys.readouterr().out
    assert main(["reconcile", FIXTURE, "--tool-a", "cbomkit", "--tool-b", "cryptobom-forge",
                 "--category", "language=Java;assetType=algorithm;subtype=ae;family=aes", "--attribute", "toolPrimitive"]) == 0
    text = capsys.readouterr().out
    assert "prefer-b (cryptobom-forge" in text and "head-to-head" in text
    assert main(["reconcile", FIXTURE, "--tool-a", "cbomkit", "--tool-b", "cdxgen", "--attribute", "oid", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["attribute"] == "oid"


def test_shipped_schema_matches_the_generator():
    with open(os.path.join(ROOT, "twocbom", "schema", "twocbom-1.0.schema.json"), encoding="utf-8") as fh:
        assert json.load(fh) == build_schema()
