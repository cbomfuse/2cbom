from conftest import example

from twocbom.ingest import detect_format, ingest_file, load_json


def test_format_detection():
    assert detect_format(load_json(example("cbomkit-java-cdx16.json"))[0]).family == "cyclonedx-json"
    assert detect_format(load_json(example("pqc-scanner-cdx17.json"))[0]).spec_version == "1.7"
    info = detect_format(load_json(example("ibm-prestandard-cbom14.json"))[0])
    assert info.family == "ibm-cbom-json" and info.spec_version == "1.4-cbom-1.0"
    assert detect_format({"foo": 1}).family == "unknown"
    assert detect_format({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [
        {"type": "crypto-asset", "cryptoProperties": {"assetType": "algorithm"}}]}).family == "ibm-cbom-json"


def test_ibm_adapter_lifts_vocabularies():
    res = ingest_file(example("ibm-prestandard-cbom14.json"))
    assert res.source.fmt == "ibm-cbom-json"
    assets = {a.ref: a for a in res.assets}
    assert assets["ibm-aes"].fields["executionEnvironment"] == "software-plain-ram"
    assert assets["ibm-key"].asset_type == "related-crypto-material"
    assert assets["ibm-key"].fields["type"] == "private-key"
    assert assets["ibm-cert"].fields["signatureAlgorithm"] == "sha256WithRSAEncryption"
    assert any(e.ref == "ibm-tls" and e.line == 28 for e in res.evidence)
    assert {(r.src, r.dst, r.kind) for r in res.relations} >= {("app", "ibm-aes", "uses"), ("ibm-tls", "ibm-cert", "uses")}
    assert any(code == "2CBOM-C17-SPEC-VERSION-NONSTANDARD" for code, _ in res.findings)


def test_cyclonedx_adapter():
    res = ingest_file(example("cbomkit-java-cdx16.json"))
    assert res.source.tool.lower().endswith("cbomkit") and res.source.tool_version == "2.1.0"
    assert len(res.assets) == 6 and len(res.components) == 2
    root = [c for c in res.components if c.root]
    assert root and root[0].name == "payments-service"
    assert any(r.kind == "provides" for r in res.relations)
    res17 = ingest_file(example("pqc-scanner-cdx17.json"))
    assert res17.source.spec_version == "1.7"
    cert = next(a for a in res17.assets if a.asset_type == "certificate")
    assert cert.fields["fingerprint"].startswith("sha256:")
