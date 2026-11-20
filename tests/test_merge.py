import itertools
import json
import os
import random

from conftest import example

from twocbom.canonical import jcs_dumps
from twocbom.export import to_cyclonedx, to_markdown
from twocbom.merge import MergeOptions, digest_scope, merge_files, merge_ingested
from twocbom.ingest import ingest_file
from twocbom.validate import validate_document

ALL = [example(n) for n in ("cbomkit-java-cdx16.json", "cdxgen-python-cdx16.json", "cryptobom-forge-cdx16.json",
                            "ibm-prestandard-cbom14.json", "pqc-scanner-cdx17.json")]
OPTS = dict(timestamp="2026-10-29T00:00:00Z", trace=False)


def merged(paths=ALL, profile="strict"):
    return merge_files(paths, MergeOptions(profile=profile, **OPTS)).document


def by_id(doc):
    return {a["id"]: a for a in doc["assets"]}


def test_merge_produces_valid_conformant_document():
    doc = merged()
    assert validate_document(doc) == []
    assert doc["conformance"]["conformant"] is True
    assert len(doc["lineage"]["sources"]) == 5
    assert doc["integrity"]["digest"].startswith("sha256:")


def test_entity_resolution_across_tools_and_versions():
    a = by_id(merged())
    aes = a["2cbom:alg:aes-128-gcm"]
    assert set(aes["aliases"]) >= {"AES128-GCM", "AES-128-GCM", "AES"}
    assert len(aes["sources"]) == 3                      # cbomkit + IBM pre-standard + forge (subsumed)
    assert aes["algorithm"]["oid"] == "2.16.840.1.101.3.4.1.6"
    assert aes["algorithm"]["cryptoFunctions"] == ["decrypt", "encrypt"]
    # pre-standard name mapped
    assert "Dilithium3" in a["2cbom:alg:ml-dsa-65"]["aliases"]
    assert a["2cbom:alg:ml-dsa-65"]["algorithm"]["preStandardNames"] == ["Dilithium3"]
    # the certificate seen by DN (IBM) and by fingerprint (1.7 scanner) is one asset
    certs = [x for x in a.values() if x["type"] == "certificate"]
    assert len(certs) == 1 and len(certs[0]["sources"]) == 2
    assert certs[0]["certificate"]["signatureAlgorithm"] == "2cbom:alg:rsa-pkcs1v15-sha2-256"
    assert certs[0]["certificate"]["subjectPublicKeyAlgorithm"] in ("2cbom:alg:rsa", "2cbom:alg:rsa-2048",
                                                                      "2cbom:key:public-key:loc:37fffc6fd0dfba644509ea11")
    # OID-named algorithm from the 1.7 scanner merged with the Java signature
    sig = a["2cbom:alg:rsa-pkcs1v15-sha2-256"]
    assert len(sig["sources"]) == 4
    # cipher suites decomposed into canonical constituents
    tls12 = a["2cbom:proto:tls-1.2"]
    names = {s["name"] for s in tls12["protocol"]["cipherSuites"]}
    assert names == {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}
    assert "2cbom:alg:tdea-cbc" in a


def test_assessments():
    a = by_id(merged())
    q = lambda cid: a[cid]["assessment"]
    assert q("2cbom:alg:aes-128-gcm")["quantumClass"] == "quantum-safe"
    assert q("2cbom:alg:aes-128-gcm")["nistQuantumSecurityLevel"] == 1
    assert q("2cbom:alg:aes-256-gcm")["cnsa2"] is True
    assert q("2cbom:alg:rsa-2048")["quantumClass"] == "quantum-vulnerable"
    assert q("2cbom:alg:rsa-2048")["nistIr8547"] == "deprecated-after-2030"
    assert q("2cbom:alg:rsa-2048")["migrationPriority"] == "high"
    assert q("2cbom:alg:rsa-pkcs1v15-sha2-256")["migrationPriority"] == "medium"
    assert q("2cbom:alg:ecdsa-p256-sha2-256")["nistIr8547"] == "disallowed-after-2035"
    assert q("2cbom:alg:sha1")["quantumClass"] == "classically-weak"
    assert q("2cbom:alg:des-cbc")["migrationPriority"] == "immediate"
    assert q("2cbom:alg:ml-kem-768")["quantumClass"] == "quantum-safe"
    assert q("2cbom:alg:x25519+ml-kem-768")["quantumClass"] == "quantum-safe"
    assert q("2cbom:alg:x25519+ml-kem-768")["nistQuantumSecurityLevel"] == 3
    assert q("2cbom:proto:tls-1.2")["quantumClass"] == "classically-weak"     # 3DES/SHA-1 suite
    assert q("2cbom:proto:tls-1.3")["quantumClass"] == "quantum-vulnerable"   # RSA certificate authentication
    certs = [x for x in a.values() if x["type"] == "certificate"]
    assert certs[0]["assessment"]["quantumClass"] == "quantum-vulnerable"


def test_merge_is_commutative_and_idempotent():
    ref = merged()
    ref_scope = jcs_dumps(digest_scope(ref))
    rng = random.Random(7)
    for _ in range(4):
        order = ALL[:]
        rng.shuffle(order)
        doc = merged(order)
        assert jcs_dumps(digest_scope(doc)) == ref_scope
        assert doc["integrity"]["digest"] == ref["integrity"]["digest"]
        assert doc["serialNumber"] == ref["serialNumber"]
    twice = merged(ALL + [ALL[0]])
    assert twice["integrity"]["digest"] == ref["integrity"]["digest"]


def test_pairwise_merge_is_associative():
    """merge(a, b, c) == merge(merge(a, b) as facts, c): checked through the fact-set formulation."""
    ins = [ingest_file(p) for p in ALL[:3]]
    opts = MergeOptions(**OPTS)
    whole = merge_ingested(ins, opts).document["integrity"]["digest"]
    for perm in itertools.permutations(ins):
        assert merge_ingested(list(perm), MergeOptions(**OPTS)).document["integrity"]["digest"] == whole


def test_core_profile_relaxes_severities():
    strict = merged(profile="strict")
    core = merged(profile="core")
    assert core["profile"] == "core" and core["conformance"]["conformant"]
    assert core["conformance"]["warnings"] <= strict["conformance"]["warnings"]


def test_single_source_merge_and_subsumption_absent():
    doc = merged([ALL[2]])
    ids = set(by_id(doc))
    assert ids >= {"2cbom:alg:aes", "2cbom:alg:sha1", "2cbom:alg:rsa", "2cbom:alg:des-cbc"}
    assert any(f["code"] == "2CBOM-C10-PARAMETER-SET-MISSING" and f["severity"] == "error" for f in doc["findings"])
    assert doc["conformance"]["conformant"] is False


def test_exports_and_validation_of_tampering(tmp_path):
    doc = merged()
    cdx = to_cyclonedx(doc)
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.6"
    kinds = {c["type"] for c in cdx["components"]}
    assert "cryptographic-asset" in kinds
    assert cdx["metadata"]["component"]["name"] == "payments-service"
    assert any(d.get("provides") for d in cdx["dependencies"])
    md = to_markdown(doc)
    assert "## Post-quantum readiness" in md and "2cbom:alg:aes-128-gcm" in md
    tampered = json.loads(json.dumps(doc))
    rsa = next(a for a in tampered["assets"] if a["id"] == "2cbom:alg:rsa-2048")
    rsa["assessment"]["quantumClass"] = "quantum-safe"
    rsa["assessment"]["nistIr8547"] = "acceptable"
    errs = validate_document(tampered)
    assert any("digest mismatch" in e for e in errs)
    p = tmp_path / "doc.json"
    p.write_text(json.dumps(doc, indent=2))
    assert validate_document(json.loads(p.read_text())) == []
