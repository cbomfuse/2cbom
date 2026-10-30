from twocbom.merge import MergeOptions, merge_ingested
from twocbom.ingest import ingest_document

OPTS = dict(timestamp="2026-10-29T00:00:00Z", trace=False)


def cdx(components, deps=None, tool="cbomkit"):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6",
            "metadata": {"tools": {"components": [{"type": "application", "name": tool, "version": "1"}]},
                         "component": {"type": "application", "bom-ref": "app", "name": "app", "version": "1"}},
            "components": components, "dependencies": deps or []}


def merge(docs, profile="strict"):
    ins = [ingest_document(d, path=f"doc{i}.json") for i, d in enumerate(docs)]
    return merge_ingested(ins, MergeOptions(profile=profile, **OPTS)).document


def codes(doc, severity=None):
    return {f["code"] for f in doc["findings"] if severity is None or f["severity"] == severity}


def test_parameter_set_required_only_for_located_detections():
    doc = merge([cdx([{"type": "cryptographic-asset", "bom-ref": "a", "name": "AES",
                       "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "block-cipher"}},
                       "evidence": {"occurrences": [{"location": "x.java", "line": 1}]}}])])
    assert "2CBOM-C10-PARAMETER-SET-MISSING" in codes(doc, "error")
    assert not doc["conformance"]["conformant"]
    core = merge([cdx([{"type": "cryptographic-asset", "bom-ref": "a", "name": "AES",
                        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "block-cipher"}},
                        "evidence": {"occurrences": [{"location": "x.java", "line": 1}]}}])], profile="core")
    assert "2CBOM-C10-PARAMETER-SET-MISSING" in codes(core, "warning") and core["conformance"]["conformant"]


def test_unresolved_identity_and_unknown_assessment():
    doc = merge([cdx([{"type": "cryptographic-asset", "bom-ref": "a", "name": "FrobnicateCipher",
                       "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "block-cipher"}}}])])
    assert {"2CBOM-C01-IDENTITY-UNRESOLVED", "2CBOM-C03-ASSESSMENT-UNKNOWN"} <= codes(doc, "error")
    asset = doc["assets"][0]
    assert asset["unresolved"] and asset["id"].startswith("2cbom:alg:unresolved:")
    assert "2CBOM-C02-EVIDENCE-UNLOCATED" in codes(doc, "warning")   # declared without a location


def test_certificate_closure():
    doc = merge([cdx([{"type": "cryptographic-asset", "bom-ref": "c", "name": "cert",
                       "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
                           "subjectName": "CN=x", "issuerName": "CN=ca", "notValidBefore": "2027-01-01T00:00:00Z",
                           "notValidAfter": "2026-01-01T00:00:00Z"}},
                       "evidence": {"occurrences": [{"location": "x.crt"}]}}])])
    assert {"2CBOM-C05-CERT-SIGNATURE-UNLINKED", "2CBOM-C12-CERT-VALIDITY-INVALID", "2CBOM-C03-ASSESSMENT-UNKNOWN"} <= codes(doc, "error")
    assert "2CBOM-C06-CERT-KEY-UNLINKED" in codes(doc, "warning")


def test_secret_values_are_never_carried():
    doc = merge([cdx([{"type": "cryptographic-asset", "bom-ref": "k", "name": "k",
                       "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {
                           "type": "secret-key", "size": 256, "value": "deadbeef"}},
                       "evidence": {"occurrences": [{"location": "k.bin"}]}}])])
    assert "2CBOM-C18-SECRET-VALUE-DROPPED" in codes(doc, "warning")
    assert "deadbeef" not in __import__("json").dumps(doc)
    assert doc["assets"][0]["assessment"]["nistQuantumSecurityLevel"] == 5


def test_tool_disagreement_is_recorded_and_resolved_by_trust():
    a = cdx([{"type": "cryptographic-asset", "bom-ref": "a", "name": "AES-128-GCM",
              "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "ae", "executionEnvironment": "hardware"}},
              "evidence": {"occurrences": [{"location": "x.c", "line": 3}]}}], tool="cbomkit")
    b = cdx([{"type": "cryptographic-asset", "bom-ref": "b", "name": "aes-128-gcm",
              "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "ae", "executionEnvironment": "software-plain-ram",
                                                                                      "classicalSecurityLevel": 64}},
              "evidence": {"occurrences": [{"location": "x.c", "line": 9}]}}], tool="cryptobom-forge")
    doc = merge([a, b])
    asset = doc["assets"][0]
    assert asset["algorithm"]["executionEnvironment"] == "hardware"          # cbomkit trust 80 > forge 65
    assert asset["algorithm"]["classicalSecurityLevel"] == 128                 # catalogue overrides the wrong 64
    assert "2CBOM-C13-LEVEL-INCONSISTENT" in codes(doc, "warning")
    assert "2CBOM-C14-SOURCE-CONFLICT" in codes(doc, "info")
    assert len(doc["lineage"]["conflicts"]) == 2


def test_tls13_without_groups_is_unknown_and_with_hybrid_is_safe():
    proto = {"type": "cryptographic-asset", "bom-ref": "p", "name": "TLS 1.3",
             "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": "1.3",
                                                                                 "cipherSuites": [{"name": "TLS_AES_256_GCM_SHA384"}]}},
             "evidence": {"occurrences": [{"location": "cfg"}]}}
    doc = merge([cdx([proto])])
    assert doc["assets"][-1]["assessment"]["quantumClass"] == "unknown"
    assert "2CBOM-C19-PROTOCOL-KEX-UNKNOWN" in codes(doc, "warning")
    hybrid = {"type": "cryptographic-asset", "bom-ref": "h", "name": "X25519MLKEM768",
              "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "combiner"}},
              "evidence": {"occurrences": [{"location": "cfg"}]}}
    proto2 = __import__("copy").deepcopy(proto)
    proto2["cryptoProperties"]["protocolProperties"]["cryptoRefArray"] = ["h"]
    doc = merge([cdx([proto2, hybrid])])
    tls = [a for a in doc["assets"] if a["type"] == "protocol"][0]
    assert tls["assessment"]["quantumClass"] == "quantum-safe"
