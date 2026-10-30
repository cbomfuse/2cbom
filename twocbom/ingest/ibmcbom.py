"""Adapter for the pre-standard IBM CBOM format.

IBM Research published CBOM as an extension of CycloneDX 1.4 before it was
standardised in CycloneDX 1.6.  Documents of that generation identify
themselves with ``"bomFormat": "CBOM"`` and ``"specVersion": "1.4-cbom-1.0"``
(or ``1.4-cbom-1.1``), use the component type ``crypto-asset`` and camelCase
enumerations (``softwarePlainRam``, ``privateKey``, ``keyAgree``...), carry
detection locations in ``cryptoProperties.detectionContext`` and optionally
type dependencies with ``dependencyType`` (``uses`` / ``implements``).
"""
from __future__ import annotations

from ..canonical import kebab
from .base import (IRAsset, IRComponent, IREvidence, IRRelation, IngestResult, SourceInfo,
                   as_list, extract_tool, fingerprint_from_hashes, first, props_to_dict, to_float, to_int)

_ASSET_TYPES = {
    "algorithm": "algorithm", "certificate": "certificate", "protocol": "protocol",
    "relatedcryptomaterial": "related-crypto-material", "related-crypto-material": "related-crypto-material",
}

# camelCase vocabularies of the extension -> CycloneDX 1.6 kebab-case
_PRIMITIVES = {"blockcipher": "block-cipher", "streamcipher": "stream-cipher", "keyagree": "key-agree",
               "authenticated-encryption": "ae", "ae": "ae"}
_EXEC = {"softwareplainram": "software-plain-ram", "softwareencryptedram": "software-encrypted-ram",
         "softwaretee": "software-tee", "hardware": "hardware"}


def _enum(v, table=None):
    if v is None:
        return None
    k = kebab(str(v))
    if table:
        return table.get(k.replace("-", ""), k)
    return k


def ingest(doc: dict, source: SourceInfo) -> IngestResult:
    res = IngestResult(source=source)
    spec = str(doc.get("specVersion", ""))
    res.findings.append(("2CBOM-C17-SPEC-VERSION-NONSTANDARD",
                         f"pre-standard IBM CBOM (specVersion {spec}) lifted to the CycloneDX 1.6 model"))
    metadata = doc.get("metadata") or {}
    tool, tool_version = extract_tool(metadata)
    if tool == "unknown":
        tool = "ibm-cbom"
    source.tool, source.tool_version = tool, tool_version

    root = metadata.get("component")
    if isinstance(root, dict):
        rref = root.get("bom-ref") or "2cbom:root"
        res.components.append(IRComponent(ref=rref, ctype=kebab(str(root.get("type") or "application")),
                                          name=str(root.get("name") or rref), version=root.get("version"),
                                          group=root.get("group"), purl=root.get("purl"), cpe=root.get("cpe"), root=True))

    auto = 0
    for c in as_list(doc.get("components")):
        if not isinstance(c, dict):
            continue
        ref = c.get("bom-ref")
        if not ref:
            auto += 1
            ref = f"_auto-{auto}"
        ctype = kebab(str(c.get("type") or "unknown"))
        if ctype in ("crypto-asset", "cryptographic-asset"):
            _ingest_asset(c, ref, res)
        else:
            res.components.append(IRComponent(ref=ref, ctype=ctype, name=str(c.get("name") or ref),
                                              version=c.get("version"), group=c.get("group"),
                                              purl=c.get("purl"), cpe=c.get("cpe")))

    for dep in as_list(doc.get("dependencies")):
        if not isinstance(dep, dict) or not dep.get("ref"):
            continue
        kind = kebab(str(dep.get("dependencyType") or "uses"))
        if kind not in ("uses", "implements"):
            kind = "uses"
        for d in as_list(dep.get("dependsOn")):
            res.relations.append(IRRelation(dep["ref"], d, kind))
        for d in as_list(dep.get("provides")):
            res.relations.append(IRRelation(dep["ref"], d, "provides"))
    return res


def _ingest_asset(c: dict, ref: str, res: IngestResult):
    cp = c.get("cryptoProperties") or {}
    raw_type = str(cp.get("assetType") or "")
    atype = _ASSET_TYPES.get(raw_type.replace("-", "").lower())
    name = str(c.get("name") or "")
    props = props_to_dict(c.get("properties"))
    fields: dict = {}
    if atype is None:
        res.findings.append(("2CBOM-C11-VOCABULARY-VIOLATION", f"{ref}: crypto-asset with unknown assetType {raw_type!r}"))
        atype = "algorithm"

    if atype == "algorithm":
        ap = cp.get("algorithmProperties") or {}
        variant = ap.get("variant")
        if variant and not name:
            name = str(variant)
        fields = {
            "variant": variant,
            "primitive": _enum(ap.get("primitive"), _PRIMITIVES),
            "parameterSetIdentifier": first(ap, "parameterSetIdentifier", "parameterSet", "keyLength", "keySize"),
            "curve": ap.get("curve"),
            "mode": _enum(ap.get("mode")),
            "padding": _enum(ap.get("padding")),
            "executionEnvironment": _enum(first(ap, "implementationLevel", "executionEnvironment"), _EXEC),
            "implementationPlatform": ap.get("implementationPlatform"),
            "certificationLevel": [_enum(x) for x in as_list(ap.get("certificationLevel"))],
            "cryptoFunctions": [_enum(x) for x in as_list(ap.get("cryptoFunctions"))],
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
            "signatureAlgorithm": cert.get("signatureAlgorithm"),
            "signatureAlgorithmRef": cert.get("signatureAlgorithmRef"),
            "subjectPublicKeyAlgorithm": cert.get("subjectPublicKeyAlgorithm"),
            "subjectPublicKeyRef": cert.get("subjectPublicKeyRef"),
            "certificateFormat": cert.get("certificateFormat"),
            "certificateExtension": cert.get("certificateExtension"),
            "serialNumber": cert.get("serialNumber") or props.get("serialNumber"),
            "fingerprint": fingerprint_from_hashes(c.get("hashes")) or props.get("fingerprint"),
        }
    elif atype == "related-crypto-material":
        rm = cp.get("relatedCryptoMaterialProperties") or {}
        secured = rm.get("securedBy") or {}
        fields = {
            "type": _enum(first(rm, "relatedCryptoMaterialType", "type")),
            "id": rm.get("id"),
            "state": _enum(rm.get("state")),
            "algorithmRef": rm.get("algorithmRef"),
            "algorithm": rm.get("algorithm"),
            "size": to_int(rm.get("size")),
            "format": rm.get("format"),
            "creationDate": rm.get("creationDate"),
            "expirationDate": rm.get("expirationDate"),
            "securedByMechanism": secured.get("mechanism") if isinstance(secured, dict) else (
                "secured" if rm.get("secured") is True else None),
            "fingerprint": fingerprint_from_hashes(c.get("hashes")),
        }
        if rm.get("value") not in (None, ""):
            res.findings.append(("2CBOM-C18-SECRET-VALUE-DROPPED", f"{ref}: key material value discarded"))
    elif atype == "protocol":
        pp = cp.get("protocolProperties") or {}
        suites = []
        for s in as_list(first(pp, "cipherSuites", "cipherSuite")):
            if isinstance(s, dict):
                suites.append({"name": s.get("name"), "identifiers": [str(i) for i in as_list(s.get("identifiers"))],
                               "algorithms": [str(a) for a in as_list(s.get("algorithms"))]})
            elif isinstance(s, str):
                suites.append({"name": s, "identifiers": [], "algorithms": []})
        ptype = first(pp, "type", "protocolType", "tlsProtocolVariant")
        fields = {
            "type": _enum(ptype),
            "version": pp.get("version"),
            "cipherSuites": suites,
            "cryptoRefs": [str(r) for r in as_list(first(pp, "cryptoRefArray", "cryptoRefs"))],
        }
    extra = {k: v for k, v in props.items() if isinstance(v, (str, int, float, bool))}
    if extra:
        fields["properties"] = extra
    res.assets.append(IRAsset(ref=ref, asset_type=atype, name=name,
                              fields={k: v for k, v in fields.items() if v not in (None, "", [], {})},
                              oid=cp.get("oid")))

    conf = to_float(cp.get("confidenceLevel"))
    contexts = as_list(cp.get("detectionContext"))
    for ctx in contexts:
        if not isinstance(ctx, dict):
            continue
        lines = [to_int(x) for x in as_list(ctx.get("lineNumbers"))] or [None]
        offsets = [to_int(x) for x in as_list(ctx.get("offsets"))]
        keywords = [str(k) for k in as_list(ctx.get("keywords"))]
        for i, line in enumerate(lines):
            res.evidence.append(IREvidence(
                ref=ref, location=ctx.get("filePath"), line=line,
                offset=offsets[i] if i < len(offsets) else None,
                symbol=keywords[0] if keywords else None,
                context=ctx.get("additionalContext"), confidence=conf))
    if not contexts and conf is not None:
        res.evidence.append(IREvidence(ref=ref, confidence=conf, context="confidenceLevel only"))
