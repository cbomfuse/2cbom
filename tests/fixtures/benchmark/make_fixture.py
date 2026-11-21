"""Regenerate the synthetic benchmark fixture with the orchestrator's own code.

Not run by the test suite.  Needs a checkout of github.com/cbomfuse/orch (and PyYAML)::

    PYTHONPATH=/path/to/orch/orchestrator python tests/fixtures/benchmark/make_fixture.py

The ledger below is invented (two cases, three tools) but has the orchestrator's row format.  Scores,
head-to-head tables, ``twocbom/tools.json`` and the expected answers in ``golden-reconcile.json`` are
computed by the orchestrator, exactly as ``orchestrator run`` would.  ``priors.json`` is not stored:
it is the scorecard without the ledger, and the tests derive it the way ``build_priors`` does.
The scenarios the 2CBOM tests rely on:

* cbomkit states the primitive of authenticated-encryption algorithms as ``block-cipher`` where
  cryptobom-forge states ``ae``, and forge is right: forge wins head-to-head on ``primitive``;
* cbomkit and cdxgen both state hash primitives correctly: the attribute tier is undecided;
* cbomkit and cdxgen disagree on three OIDs and cbomkit is right: cbomkit wins head-to-head on ``oid``;
* cdxgen and forge never detect the same item; forge states parameter sets far more reliably
  (attribute tier).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from orchestrator.evaluate import PAIRWISE_COMBOS, _combo_of
from orchestrator.evaluate.pairwise import head_to_head, pair_key
from orchestrator.evaluate.scoring import FACET_COMBOS, parse_category, strengths
from orchestrator.export import build_priors, build_tools_json
from orchestrator.reconcile import Scorecard

HERE = Path(__file__).resolve().parent

K, X, F = "cbomkit", "cdxgen", "cryptobom-forge"
TOOLS = {
    K: {"name": "CBOMkit", "tag": "v2.3.0", "version": "2.3.0", "commit": "34a3d96" + "0" * 33,
        "image": "ghcr.io/cbomkit/cbomkit-action:2.3.0", "image_digest": "sha256:" + "8b" * 32,
        "reported": {"name": "CBOMkit", "version": None},
        "twocbom": {"aliases": ["cbomkit", "cbomkit-action", "sonar-cryptography"], "detection_method": "static-source"}},
    X: {"name": "cdxgen", "tag": "v13.7.0", "version": "13.7.0", "commit": "5951a06" + "0" * 33,
        "image": "ghcr.io/cyclonedx/cdxgen:latest", "image_digest": "sha256:" + "fe" * 32,
        "reported": {"name": "dosai", "version": "4.1.0"},
        "twocbom": {"aliases": ["cdxgen", "@cyclonedx/cdxgen", "@cdxgen/cdxgen"], "detection_method": "static-source"}},
    F: {"name": "cryptobom-forge", "tag": "1.1.0", "version": "1.1.0", "commit": "4197d51" + "0" * 33,
        "image": None, "image_digest": None,
        "reported": {"name": "cyclonedx-python-lib", "version": "4.2.2"},
        "twocbom": {"aliases": ["cryptobom-forge", "cryptobomforge"], "detection_method": "static-source"}},
}

# (case, assetId, name, assetType, subtype, family, expected attributes)
ITEMS = [
    ("Java", "aes-128-gcm", "AES-128-GCM", "algorithm", "ae", "aes", {"primitive": "ae", "parameterSetIdentifier": "128", "mode": "gcm", "oid": "2.16.840.1.101.3.4.1.6"}),
    ("Java", "aes-256-cbc", "AES-256-CBC", "algorithm", "block-cipher", "aes", {"primitive": "block-cipher", "parameterSetIdentifier": "256", "mode": "cbc", "padding": "pkcs5"}),
    ("Java", "sha-256", "SHA-256", "algorithm", "hash", "sha2", {"primitive": "hash", "parameterSetIdentifier": "256", "oid": "2.16.840.1.101.3.4.2.1"}),
    ("Java", "sha-512", "SHA-512", "algorithm", "hash", "sha2", {"primitive": "hash", "parameterSetIdentifier": "512", "oid": "2.16.840.1.101.3.4.2.3"}),
    ("Java", "sha3-256", "SHA3-256", "algorithm", "hash", "sha3", {"primitive": "hash", "parameterSetIdentifier": "256", "oid": "2.16.840.1.101.3.4.2.8"}),
    ("Java", "rsa-2048", "RSA-2048", "algorithm", "pke", "rsa", {"primitive": "pke", "parameterSetIdentifier": "2048", "padding": "oaep"}),
    ("Java", "key.aes", "AES key", "related-crypto-material", "secret-key", "aes", {"type": "secret-key", "size": 128}),
    ("Java", "lib.bc", "bcprov-jdk18on", "library", "library", "maven/org.bouncycastle/bcprov-jdk18on", {"purl": "pkg:maven/org.bouncycastle/bcprov-jdk18on", "version": "1.78"}),
    ("Python", "aes-128-gcm", "AES-128-GCM", "algorithm", "ae", "aes", {"primitive": "ae", "parameterSetIdentifier": "128", "mode": "gcm", "oid": "2.16.840.1.101.3.4.1.6"}),
    ("Python", "aes-256-gcm", "AES-256-GCM", "algorithm", "ae", "aes", {"primitive": "ae", "parameterSetIdentifier": "256", "mode": "gcm", "oid": "2.16.840.1.101.3.4.1.46"}),
    ("Python", "chacha20-poly1305", "ChaCha20-Poly1305", "algorithm", "ae", "chacha20", {"primitive": "ae", "parameterSetIdentifier": "256"}),
    ("Python", "sha-256", "SHA-256", "algorithm", "hash", "sha2", {"primitive": "hash", "parameterSetIdentifier": "256", "oid": "2.16.840.1.101.3.4.2.1"}),
    ("Python", "sha-512", "SHA-512", "algorithm", "hash", "sha2", {"primitive": "hash", "parameterSetIdentifier": "512", "oid": "2.16.840.1.101.3.4.2.3"}),
    ("Python", "sha3-256", "SHA3-256", "algorithm", "hash", "sha3", {"primitive": "hash", "parameterSetIdentifier": "256", "oid": "2.16.840.1.101.3.4.2.8"}),
    ("Python", "hmac-sha256", "HMAC-SHA256", "algorithm", "mac", "hmac", {"primitive": "mac", "parameterSetIdentifier": "256"}),
    ("Python", "rsa-3072", "RSA-3072", "algorithm", "signature", "rsa", {"primitive": "signature", "parameterSetIdentifier": "3072", "padding": "pss"}),
    ("Python", "key.aes", "AES key", "related-crypto-material", "secret-key", "aes", {"type": "secret-key", "size": 256}),
    ("Python", "lib.pyca", "cryptography", "library", "library", "pypi/cryptography", {"purl": "pkg:pypi/cryptography", "version": "43.0.1"}),
]

WRONG = "__wrong__"     # marker: the tool states a wrong value


def _wrong(attr, expected):
    return {"primitive": "block-cipher", "oid": "1.2.3.4", "parameterSetIdentifier": "64", "mode": "ecb",
            "padding": "none", "type": "public-key", "size": 64, "purl": "pkg:generic/x", "version": "0"}.get(attr, "x")


# tool -> {(case, assetId): {attribute: reported value | WRONG}}; a missing item was not detected
REPORTS = {
    K: {
        ("Java", "aes-128-gcm"): {"primitive": WRONG, "parameterSetIdentifier": "128", "oid": "2.16.840.1.101.3.4.1.6"},
        ("Java", "aes-256-cbc"): {"primitive": "block-cipher", "parameterSetIdentifier": WRONG, "mode": "cbc", "padding": "pkcs5"},
        ("Java", "sha-256"): {"primitive": "hash", "oid": "2.16.840.1.101.3.4.2.1"},
        ("Java", "sha-512"): {"primitive": "hash", "oid": "2.16.840.1.101.3.4.2.3"},
        ("Java", "sha3-256"): {"primitive": "hash", "oid": "2.16.840.1.101.3.4.2.8"},
        ("Java", "rsa-2048"): {"primitive": "pke", "parameterSetIdentifier": WRONG},
        ("Java", "key.aes"): {"type": "secret-key", "size": 128},
        ("Python", "aes-128-gcm"): {"primitive": WRONG, "parameterSetIdentifier": "128", "mode": "gcm"},
        ("Python", "aes-256-gcm"): {"primitive": WRONG, "parameterSetIdentifier": WRONG, "mode": "gcm"},
        ("Python", "chacha20-poly1305"): {"primitive": WRONG},
        ("Python", "sha-256"): {"primitive": "hash", "oid": "2.16.840.1.101.3.4.2.1"},
        ("Python", "sha-512"): {"primitive": "hash"},
        ("Python", "sha3-256"): {"primitive": "hash", "oid": "2.16.840.1.101.3.4.2.8"},
        ("Python", "rsa-3072"): {"primitive": "signature", "parameterSetIdentifier": WRONG},
    },
    X: {
        ("Java", "sha-256"): {"primitive": "hash", "oid": WRONG},
        ("Java", "sha-512"): {"primitive": "hash", "oid": WRONG},
        ("Java", "sha3-256"): {"primitive": "hash", "parameterSetIdentifier": WRONG, "oid": "2.16.840.1.101.3.4.2.8"},
        ("Python", "sha-256"): {"primitive": "hash", "parameterSetIdentifier": "256", "oid": WRONG},
        ("Python", "sha-512"): {"primitive": "hash", "parameterSetIdentifier": WRONG},
        ("Python", "hmac-sha256"): {"parameterSetIdentifier": WRONG},
        ("Java", "lib.bc"): {"purl": "pkg:maven/org.bouncycastle/bcprov-jdk18on", "version": "1.78"},
        ("Python", "lib.pyca"): {"purl": "pkg:pypi/cryptography", "version": "43.0.1"},
    },
    F: {
        ("Java", "aes-128-gcm"): {"primitive": "ae", "parameterSetIdentifier": "128", "mode": "gcm"},
        ("Java", "aes-256-cbc"): {"primitive": "block-cipher", "parameterSetIdentifier": "256", "mode": "cbc"},
        ("Java", "rsa-2048"): {"primitive": "pke", "parameterSetIdentifier": "2048", "padding": "oaep"},
        ("Java", "key.aes"): {"type": "secret-key", "size": 128},
        ("Python", "aes-128-gcm"): {"primitive": "ae", "parameterSetIdentifier": "128", "mode": "gcm"},
        ("Python", "aes-256-gcm"): {"primitive": "ae", "parameterSetIdentifier": "256", "mode": "gcm"},
        ("Python", "chacha20-poly1305"): {"primitive": "ae", "parameterSetIdentifier": "256"},
        ("Python", "rsa-3072"): {"primitive": "signature", "parameterSetIdentifier": "3072"},
        ("Python", "key.aes"): {"type": "secret-key", "size": WRONG},
    },
}
FALSE_POSITIVES = {K: [("Java", "algorithm", "block-cipher", "des")], X: [("Python", "algorithm", "hash", "md5")], F: []}


def ledger() -> list:
    rows = []
    for tool in sorted(REPORTS):
        for case, aid, name, atype, subtype, family, expected in ITEMS:
            rep = REPORTS[tool].get((case, aid))
            attrs = {}
            for attr, exp in expected.items():
                got = None if rep is None else rep.get(attr)
                if got == WRONG:
                    got = _wrong(attr, exp)
                attrs[attr] = {"expected": exp, "reported": got,
                               "correct": 1.0 if got is not None and got == exp else 0.0}
            reported = [a for a in attrs.values() if a["reported"] is not None]
            detected = rep is not None
            rows.append({
                "tool": tool, "toolVersion": TOOLS[tool]["version"], "case": case, "language": case, "kind": "gt",
                "assetId": aid, "name": name, "assetType": atype, "subtype": subtype, "family": family,
                "scenarios": ["S01"], "libraries": [], "implicit": False, "pqc": False, "scored": True,
                "detected": detected, "matchLevel": "exact" if detected else None,
                "identityScore": 1.0 if detected else 0.0, "detectionRefs": [f"{tool}:{case}:{aid}"] if detected else [],
                "attributes": attrs if detected else {k: {**v, "reported": None, "correct": 0.0} for k, v in attrs.items()},
                "completeness": round(len(reported) / len(attrs), 4) if detected else None,
                "correctness": round(sum(a["correct"] for a in reported) / len(reported), 4) if detected and reported else None,
                "locations": {"expected": 1, "matched": 1 if detected else 0},
                "bestDetection": {"ref": f"{tool}:{case}:{aid}", "name": name} if detected else None,
            })
        for i, (case, atype, subtype, family) in enumerate(FALSE_POSITIVES[tool]):
            rows.append({"tool": tool, "case": case, "language": case, "kind": "fp", "assetType": atype,
                         "subtype": subtype, "family": family, "lexical": False, "name": family.upper(), "ref": f"fp-{i}"})
    return rows


def scorecard() -> dict:
    scoring = {"weights": {"recall": 0.35, "precision": 0.15, "completeness": 0.15, "correctness": 0.25, "locality": 0.1},
               "line_tolerance": 1, "min_support": 5, "min_support_head_to_head": 3, "strength_threshold": 0.8,
               "strength_min_support": 5, "treat_failed_as_zero": False, "undecided_below": 0.6,
               "backoff_relevance_decay": 0.15, "shrinkage_prior_weight": 5, "attribute_weights": {}}
    tools = {t: {"tool": t, "repo": None, "strategy": "fixed", "source": "pinned", "launcher": "docker", **spec}
             for t, spec in TOOLS.items()}
    for spec in tools.values():
        spec["reported"] = {"name": spec["reported"]["name"], "version": spec["reported"]["version"],
                            "format": "cyclonedx", "specVersion": "1.6", "allTools": []}
    doc = {
        "schemaVersion": "1.0", "scoringModelVersion": "1.0", "orchestrator": {"version": "0.1.0"},
        "run": {"id": "fixture-synthetic", "startedAt": "2026-11-20T00:00:00Z", "finishedAt": "2026-11-20T00:05:00Z",
                "host": {"note": "synthetic fixture for the 2CBOM test suite"}, "config": {"scoring": scoring}},
        "baseline": {"repo": "https://github.com/cbomfuse/baseline", "ref": "main", "commit": "7cb9d9a" + "0" * 33,
                     "evaluatedCommit": "7cb9d9a" + "0" * 33},
        "cases": [{"id": "Java", "language": "Java"}, {"id": "Python", "language": "Python"}],
        "tools": tools, "runs": {}, "coverage": {t: {"Java": "ok", "Python": "ok"} for t in tools},
        "scores": {}, "pairwise": {}, "ledger": ledger(),
    }
    # exactly what orchestrator.evaluate.evaluate_run does after building the ledger
    sc = Scorecard(doc)
    for tool in sorted(tools):
        overall = sc.overall(tool) or {}
        doc["scores"][tool] = {
            "overall": overall, "byCategory": sc.all_category_scores(tool, FACET_COMBOS),
            "strengths": strengths(overall, 0.8, 5), "coverage": doc["coverage"][tool],
        }
    ids = sorted(tools)
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            key, _ = pair_key(a, b)
            table = {}
            cats = {"*"} | ({k for k in doc["scores"][a]["byCategory"] if _combo_of(k) in PAIRWISE_COMBOS}
                            & {k for k in doc["scores"][b]["byCategory"] if _combo_of(k) in PAIRWISE_COMBOS})
            for cat in sorted(cats):
                h2h = head_to_head(sc.gt_rows(a), sc.gt_rows(b), parse_category(cat))
                if h2h:
                    table[cat] = h2h
            doc["pairwise"][key] = table
    doc["summary"] = {t: {k: doc["scores"][t]["overall"].get(k) for k in ("support", "detected", "recall", "precision",
                                                                          "completeness", "correctness", "locality", "score")}
                      for t in ids}
    return doc


QUERIES = [
    (K, F, {"language": "Java", "assetType": "algorithm", "subtype": "ae", "family": "aes"}, "primitive"),
    (F, K, {"language": "Java", "assetType": "algorithm", "subtype": "ae", "family": "aes"}, "primitive"),
    (K, F, {"language": "Go", "assetType": "algorithm", "subtype": "ae", "family": "aes"}, "primitive"),
    (K, X, {"language": "Python", "assetType": "algorithm", "subtype": "hash", "family": "sha2"}, "primitive"),
    (K, X, {"language": "Java", "assetType": "algorithm", "subtype": "hash", "family": "sha2"}, "oid"),
    (X, F, {"language": "Python", "assetType": "algorithm", "subtype": "hash", "family": "sha2"}, "parameterSet"),
    (K, X, {"language": "Java", "assetType": "algorithm"}, "executionEnvironment"),
    (K, F, {"assetType": "related-crypto-material", "subtype": "secret-key", "family": "aes"}, "size"),
    (K, F, {}, None),
    (K, "semgrep", {"assetType": "algorithm"}, "primitive"),
    (K, X, "language=Java;subtype=hash", "family"),
    (K, F, {"assetType": "algorithm", "subtype": "ae"}, "mode"),
]
VALUE_QUERIES = [(K, F, {"assetType": "algorithm"}, "parameterSetIdentifier", "128", None)]


def golden(doc: dict) -> dict:
    out = {}
    for name, src in (("scorecard", Scorecard(doc)), ("priors", Scorecard(build_priors(doc)))):
        answers = []
        for a, b, cat, attr in QUERIES:
            answers.append({"query": {"toolA": a, "toolB": b, "category": cat, "attribute": attr},
                            "answer": src.reconcile(a, b, cat, attr).to_dict()})
        for a, b, cat, attr, va, vb in VALUE_QUERIES:
            answers.append({"query": {"toolA": a, "toolB": b, "category": cat, "attribute": attr, "valueA": va, "valueB": vb},
                            "answer": src.reconcile(a, b, cat, attr, va, vb).to_dict()})
        out[name] = answers
    return out


def main() -> int:
    doc = scorecard()
    (HERE / "twocbom").mkdir(exist_ok=True)
    compact = dict(separators=(",", ":"), sort_keys=True)
    (HERE / "scorecard.json").write_text(json.dumps(doc, **compact) + "\n", encoding="utf-8")
    (HERE / "twocbom" / "tools.json").write_text(json.dumps(build_tools_json(doc), indent=2) + "\n", encoding="utf-8")
    (HERE / "golden-reconcile.json").write_text(json.dumps(golden(doc), indent=1) + "\n", encoding="utf-8")
    print(f"wrote fixture to {HERE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
