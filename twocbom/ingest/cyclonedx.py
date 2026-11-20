"""Adapter for CycloneDX 1.5 / 1.6 / 1.7 CBOM documents (JSON).

CycloneDX 1.6 standardised the cryptographic asset model that IBM contributed
(``cryptographic-asset`` components with ``cryptoProperties``); 1.7 keeps the
same structure and is read with the same code path.  1.5 documents that
nevertheless carry ``cryptoProperties`` (emitted by some early tools) are read
leniently and flagged.
"""
from __future__ import annotations

from typing import Optional

from ..canonical import kebab
from .base import (IRAsset, IRComponent, IREvidence, IRRelation, IngestResult, SourceInfo,
                   as_list, extract_tool, fingerprint_from_hashes, first, props_to_dict, to_float, to_int)

SUPPORTED_VERSIONS = ("1.5", "1.6", "1.7")

# CycloneDX cryptoProperties.assetType -> 2CBOM asset type (identity for 1.6)
_ASSET_TYPES = {
    "algorithm": "algorithm", "certificate": "certificate", "protocol": "protocol",
    "related-crypto-material": "related-crypto-material", "relatedcryptomaterial": "related-crypto-material",
}


def _flatten_components(components, out: list, parent: Optional[str] = None):
    for c in as_list(components):
        if not isinstance(c, dict):
            continue
        out.append((c, parent))
        if c.get("components"):
            _flatten_components(c["components"], out, c.get("bom-ref"))


def _norm_enum(v):
    if v is None:
        return None
    return kebab(str(v))


def _norm_list(v):
    return [kebab(str(x)) for x in as_list(v) if x is not None]


def ingest(doc: dict, source: SourceInfo) -> IngestResult:
    res = IngestResult(source=source)
    spec = str(doc.get("specVersion", ""))
    if spec not in SUPPORTED_VERSIONS:
        res.findings.append(("2CBOM-C17-SPEC-VERSION-NONSTANDARD",
                             f"CycloneDX specVersion {spec!r} read with the 1.6 adapter"))
    if spec == "1.5":
        res.findings.append(("2CBOM-C17-SPEC-VERSION-NONSTANDARD",
                             "CycloneDX 1.5 has no cryptographic-asset model; cryptoProperties read leniently"))
    metadata = doc.get("metadata") or {}
    tool, tool_version = extract_tool(metadata)
    source.tool, source.tool_version = tool, tool_version

    flat: list = []
    root = metadata.get("component")
    if isinstance(root, dict):
        root = dict(root)
        root.setdefault("bom-ref", "2cbom:root")
        root["_root"] = True
        flat.append((root, None))
    _flatten_components(doc.get("components"), flat)

    auto = 0
    for c, parent in flat:
        ref = c.get("bom-ref")
        if not ref:
            auto += 1
            ref = f"_auto-{auto}"
            c["bom-ref"] = ref
        ctype = kebab(str(c.get("type") or "unknown"))
        if ctype in ("cryptographic-asset", "crypto-asset"):
            _ingest_asset(c, res)
        else:
            res.components.append(IRComponent(
                ref=ref, ctype=ctype, name=str(c.get("name") or ref), version=c.get("version"),
                group=c.get("group"), purl=c.get("purl"), cpe=c.get("cpe"), root=bool(c.get("_root"))))
        if parent:
            res.relations.append(IRRelation(parent, ref, "depends-on"))

    for dep in as_list(doc.get("dependencies")):
        if not isinstance(dep, dict) or not dep.get("ref"):
            continue
        for d in as_list(dep.get("dependsOn")):
            res.relations.append(IRRelation(dep["ref"], d, "uses"))
        for d in as_list(dep.get("provides")):
            res.relations.append(IRRelation(dep["ref"], d, "provides"))
        dtype = dep.get("dependencyType")  # tolerated pre-standard extension
        if dtype:
            res.findings.append(("2CBOM-C17-SPEC-VERSION-NONSTANDARD", "dependencyType present in a CycloneDX dependency"))
    return res


def _ingest_asset(c: dict, res: IngestResult):
    ref = c["bom-ref"]
    cp = c.get("cryptoProperties") or {}
    atype = _ASSET_TYPES.get(kebab(str(cp.get("assetType") or "")).lower() if cp.get("assetType") else "", None)
    name = str(c.get("name") or "")
    props = props_to_dict(c.get("properties"))
    fields: dict = {}
    if atype is None:
        # best effort: infer from the properties block present
        for key, t in (("algorithmProperties", "algorithm"), ("certificateProperties", "certificate"),
                       ("protocolProperties", "protocol"), ("relatedCryptoMaterialProperties", "related-crypto-material")):
            if key in cp:
                atype = t
                break
    if atype is None:
        res.findings.append(("2CBOM-C11-VOCABULARY-VIOLATION", f"{ref}: cryptographic asset without a recognised assetType"))
        atype = "algorithm"

    if atype == "algorithm":
        ap = cp.get("algorithmProperties") or {}
        fields = {
            "primitive": _norm_enum(ap.get("primitive")),
            "parameterSetIdentifier": first(ap, "parameterSetIdentifier", "parameterSet"),
            "curve": ap.get("curve"),
            "mode": _norm_enum(ap.get("mode")),
            "padding": _norm_enum(ap.get("padding")),
            "executionEnvironment": _norm_enum(first(ap, "executionEnvironment", "implementationLevel")),
            "implementationPlatform": ap.get("implementationPlatform"),
            "certificationLevel": _norm_list(ap.get("certificationLevel")),
            "cryptoFunctions": _norm_list(ap.get("cryptoFunctions")),
            "classicalSecurityLevel": to_int(ap.get("classicalSecurityLevel")),
            "nistQuantumSecurityLevel": to_int(ap.get("nistQuantumSecurityLevel")),
        }
    elif atype == "certificate":
        cert = cp.get("certificateProperties") or {}
        fields = {
            "subjectName": cert.get("subjectName"),
            "issuerName": cert.get("issuerName"),
            "notValidBefore": cert.get("notValidBefore"),
            "notValidAfter": cert.get("notValidAfter"),
            "signatureAlgorithmRef": cert.get("signatureAlgorithmRef"),
            "signatureAlgorithm": cert.get("signatureAlgorithm"),
            "subjectPublicKeyRef": cert.get("subjectPublicKeyRef"),
            "subjectPublicKeyAlgorithm": cert.get("subjectPublicKeyAlgorithm"),
            "certificateFormat": cert.get("certificateFormat"),
            "certificateExtension": cert.get("certificateExtension"),
            "serialNumber": first(cert, "serialNumber") or props.get("serialNumber") or props.get("cbom:certificate:serialNumber"),
            "fingerprint": fingerprint_from_hashes(c.get("hashes")) or props.get("fingerprint") or props.get("cbom:certificate:fingerprint"),
        }
    elif atype == "related-crypto-material":
        rm = cp.get("relatedCryptoMaterialProperties") or {}
        secured = rm.get("securedBy") or {}
        fields = {
            "type": _norm_enum(first(rm, "type", "relatedCryptoMaterialType")),
            "id": rm.get("id"),
            "state": _norm_enum(rm.get("state")),
            "algorithmRef": rm.get("algorithmRef"),
            "algorithm": rm.get("algorithm"),
            "creationDate": rm.get("creationDate"),
            "activationDate": rm.get("activationDate"),
            "updateDate": rm.get("updateDate"),
            "expirationDate": rm.get("expirationDate"),
            "size": to_int(rm.get("size")),
            "format": rm.get("format"),
            "securedByMechanism": secured.get("mechanism") if isinstance(secured, dict) else None,
            "securedByAlgorithmRef": secured.get("algorithmRef") if isinstance(secured, dict) else None,
            "fingerprint": fingerprint_from_hashes(c.get("hashes")),
        }
        if rm.get("value") not in (None, ""):
            res.findings.append(("2CBOM-C18-SECRET-VALUE-DROPPED", f"{ref}: relatedCryptoMaterialProperties.value was discarded (2CBOM never carries key material)"))
    elif atype == "protocol":
        pp = cp.get("protocolProperties") or {}
        suites = []
        for s in as_list(first(pp, "cipherSuites", "cipherSuite")):
            if isinstance(s, dict):
                suites.append({"name": s.get("name"), "identifiers": [str(i) for i in as_list(s.get("identifiers"))],
                               "algorithms": [str(a) for a in as_list(s.get("algorithms"))]})
            elif isinstance(s, str):
                suites.append({"name": s, "identifiers": [], "algorithms": []})
        fields = {
            "type": _norm_enum(pp.get("type")),
            "version": pp.get("version"),
            "cipherSuites": suites,
            "cryptoRefs": [str(r) for r in as_list(pp.get("cryptoRefArray"))],
        }
    # tool properties worth keeping (namespaced)
    extra = {k: v for k, v in props.items() if isinstance(v, (str, int, float, bool))}
    if extra:
        fields["properties"] = extra
    res.assets.append(IRAsset(ref=ref, asset_type=atype, name=name,
                              fields={k: v for k, v in fields.items() if v not in (None, "", [], {})},
                              oid=cp.get("oid")))

    ev = c.get("evidence") or {}
    occ = as_list(ev.get("occurrences"))
    for o in occ:
        if not isinstance(o, dict):
            continue
        res.evidence.append(IREvidence(
            ref=ref, location=o.get("location"), line=to_int(o.get("line")), offset=to_int(o.get("offset")),
            symbol=o.get("symbol"), context=o.get("additionalContext"),
            confidence=to_float(o.get("confidence"))))
    for ident in as_list(ev.get("identity")):
        if isinstance(ident, dict) and not occ:
            res.evidence.append(IREvidence(ref=ref, method=None, confidence=to_float(ident.get("confidence")),
                                           context=f"identity:{ident.get('field')}"))
