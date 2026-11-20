"""Projection of a 2CBOM document onto CycloneDX 1.6 (Section 11 of the specification).

The projection is *lossy but conformant*: everything CycloneDX can express is
mapped to its native field; 2CBOM-only information (assessment, typed
relations, canonical ids, lineage) is carried in ``properties`` under the
``2cbom:`` namespace so that no information is silently dropped.
"""
from __future__ import annotations

import json

from ..canonical import stable_uuid
from ..model import MODES, PADDINGS

_CDX_PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf",
                   "key-agree", "kem", "ae", "combiner", "other", "unknown"}
_CDX_MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"}
_CDX_PADDINGS = {"pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown"}
_CDX_EXEC = {"software-plain-ram", "software-encrypted-ram", "software-tee", "hardware", "other", "unknown"}
_CDX_MATERIAL = {"private-key", "public-key", "secret-key", "key", "ciphertext", "signature", "digest",
                 "initialization-vector", "nonce", "seed", "salt", "shared-secret", "tag", "additional-data",
                 "password", "credential", "token", "other", "unknown"}


def _prop(name, value):
    return {"name": name, "value": value if isinstance(value, str) else json.dumps(value, sort_keys=True)}


def _props_for(asset: dict) -> list:
    props = [_prop("2cbom:id", asset["id"])]
    a = asset.get("assessment") or {}
    for k in ("quantumClass", "nistIr8547", "migrationPriority"):
        if k in a:
            props.append(_prop(f"2cbom:assessment:{k}", a[k]))
    for k in ("cnsa2", "fipsApproved"):
        if a.get(k) is not None:
            props.append(_prop(f"2cbom:assessment:{k}", "true" if a[k] else "false"))
    if asset.get("aliases"):
        props.append(_prop("2cbom:aliases", ", ".join(asset["aliases"])))
    if asset.get("unresolved"):
        props.append(_prop("2cbom:unresolved", "true"))
    return props


def to_cyclonedx(doc: dict) -> dict:
    components = []
    for c in doc.get("components", []):
        comp = {"type": c["type"] if c["type"] != "unknown" else "library", "bom-ref": c["id"], "name": c["name"]}
        for k in ("version", "group", "purl", "cpe"):
            if c.get(k):
                comp[k] = c[k]
        comp["properties"] = [_prop("2cbom:id", c["id"])]
        components.append(comp)

    for asset in doc.get("assets", []):
        comp = {"type": "cryptographic-asset", "bom-ref": asset["id"], "name": asset["name"]}
        cp: dict = {}
        t = asset["type"]
        if t == "algorithm":
            alg = asset.get("algorithm", {})
            ap = {}
            prim = alg.get("primitive", "unknown")
            ap["primitive"] = prim if prim in _CDX_PRIMITIVES else "other"
            if alg.get("parameterSet"):
                ap["parameterSetIdentifier"] = alg["parameterSet"]
            if alg.get("curve"):
                ap["curve"] = alg["curve"]
            if alg.get("mode"):
                ap["mode"] = alg["mode"] if alg["mode"] in _CDX_MODES else "other"
            if alg.get("padding"):
                ap["padding"] = alg["padding"] if alg["padding"] in _CDX_PADDINGS else "other"
            if alg.get("executionEnvironment"):
                ap["executionEnvironment"] = alg["executionEnvironment"] if alg["executionEnvironment"] in _CDX_EXEC else "other"
            if alg.get("implementationPlatform"):
                ap["implementationPlatform"] = alg["implementationPlatform"]
            if alg.get("certificationLevel"):
                ap["certificationLevel"] = alg["certificationLevel"]
            if alg.get("cryptoFunctions"):
                ap["cryptoFunctions"] = alg["cryptoFunctions"]
            if alg.get("classicalSecurityLevel") is not None:
                ap["classicalSecurityLevel"] = alg["classicalSecurityLevel"]
            if alg.get("nistQuantumSecurityLevel") is not None:
                ap["nistQuantumSecurityLevel"] = alg["nistQuantumSecurityLevel"]
            cp = {"assetType": "algorithm", "algorithmProperties": ap}
            if alg.get("oid"):
                cp["oid"] = alg["oid"]
            extra = []
            if alg.get("hash"):
                extra.append(_prop("2cbom:algorithm:hash", alg["hash"]))
            if alg.get("family"):
                extra.append(_prop("2cbom:algorithm:family", alg["family"]))
            if alg.get("mode") and alg["mode"] not in _CDX_MODES:
                extra.append(_prop("2cbom:algorithm:mode", alg["mode"]))
            if alg.get("padding") and alg["padding"] not in _CDX_PADDINGS:
                extra.append(_prop("2cbom:algorithm:padding", alg["padding"]))
            if alg.get("standards"):
                extra.append(_prop("2cbom:algorithm:standards", "; ".join(alg["standards"])))
            if alg.get("components"):
                extra.append(_prop("2cbom:algorithm:components", ", ".join(alg["components"])))
            comp["properties"] = _props_for(asset) + extra
        elif t == "certificate":
            cert = asset.get("certificate", {})
            cpp = {}
            for src, dst in (("subject", "subjectName"), ("issuer", "issuerName"), ("notBefore", "notValidBefore"),
                             ("notAfter", "notValidAfter"), ("format", "certificateFormat"),
                             ("extension", "certificateExtension"), ("signatureAlgorithm", "signatureAlgorithmRef"),
                             ("subjectPublicKeyAlgorithm", "subjectPublicKeyRef")):
                if cert.get(src):
                    cpp[dst] = cert[src]
            cp = {"assetType": "certificate", "certificateProperties": cpp}
            if cert.get("fingerprint"):
                alg, _, content = cert["fingerprint"].partition(":")
                comp["hashes"] = [{"alg": {"sha256": "SHA-256", "sha1": "SHA-1", "sha512": "SHA-512"}.get(alg, "SHA-256"), "content": content}]
            comp["properties"] = _props_for(asset) + ([_prop("2cbom:certificate:serialNumber", cert["serialNumber"])] if cert.get("serialNumber") else [])
        elif t == "related-crypto-material":
            m = asset.get("material", {})
            rp = {"type": m.get("type", "unknown") if m.get("type") in _CDX_MATERIAL else "other"}
            for src, dst in (("identifier", "id"), ("state", "state"), ("size", "size"), ("format", "format"),
                             ("algorithm", "algorithmRef"), ("creationDate", "creationDate"),
                             ("activationDate", "activationDate"), ("updateDate", "updateDate"),
                             ("expirationDate", "expirationDate")):
                if m.get(src) is not None:
                    rp[dst] = m[src]
            if m.get("securedBy"):
                sb = {}
                if m["securedBy"].get("mechanism"):
                    sb["mechanism"] = m["securedBy"]["mechanism"]
                if m["securedBy"].get("algorithm"):
                    sb["algorithmRef"] = m["securedBy"]["algorithm"]
                if sb:
                    rp["securedBy"] = sb
            cp = {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": rp}
            comp["properties"] = _props_for(asset)
        else:
            p = asset.get("protocol", {})
            pp = {"type": p.get("type", "unknown") if p.get("type") in ("tls", "ssh", "ipsec", "ike", "sstp", "wpa") else "other"}
            if p.get("version"):
                pp["version"] = p["version"]
            suites = []
            for s in p.get("cipherSuites", []):
                entry = {}
                if s.get("name"):
                    entry["name"] = s["name"]
                if s.get("algorithms"):
                    entry["algorithms"] = s["algorithms"]
                if s.get("identifier"):
                    entry["identifiers"] = [s["identifier"]]
                suites.append(entry)
            if suites:
                pp["cipherSuites"] = suites
            if p.get("references"):
                pp["cryptoRefArray"] = p["references"]
            cp = {"assetType": "protocol", "protocolProperties": pp}
            comp["properties"] = _props_for(asset)
        comp["cryptoProperties"] = cp
        occ = []
        for e in asset.get("evidence", []):
            o = {}
            if e.get("location"):
                o["location"] = e["location"]
            if e.get("line") is not None:
                o["line"] = e["line"]
            if e.get("offset") is not None:
                o["offset"] = e["offset"]
            if e.get("symbol"):
                o["symbol"] = e["symbol"]
            ctx = f"[{e.get('tool')}/{e.get('method')}] " + (e.get("context") or "")
            o["additionalContext"] = ctx.strip()
            occ.append(o)
        if occ:
            comp["evidence"] = {"occurrences": occ}
        components.append(comp)

    deps: dict = {}
    for r in doc.get("relations", []):
        entry = deps.setdefault(r["from"], {"ref": r["from"], "dependsOn": [], "provides": []})
        if r["kind"] == "provides":
            entry["provides"].append(r["to"])
        else:
            entry["dependsOn"].append(r["to"])
    dependencies = []
    for ref in sorted(deps):
        e = deps[ref]
        d = {"ref": ref}
        if e["dependsOn"]:
            d["dependsOn"] = sorted(set(e["dependsOn"]))
        if e["provides"]:
            d["provides"] = sorted(set(e["provides"]))
        dependencies.append(d)

    typed = [_prop(f"2cbom:relation:{r['kind']}", f"{r['from']} -> {r['to']}" + (f" via {r['via']}" if r.get("via") else ""))
             for r in doc.get("relations", []) if r["kind"] not in ("uses", "provides", "depends-on")]

    root = next((c for c in doc.get("components", []) if c.get("root")), None)
    metadata = {
        "timestamp": doc.get("generated", {}).get("timestamp"),
        "tools": {"components": [{"type": "application", "name": "twocbom",
                                  "version": doc.get("generated", {}).get("generator", {}).get("version", "")}]},
        "properties": [
            _prop("2cbom:version", doc.get("2cbomVersion", "1.0")),
            _prop("2cbom:profile", doc.get("profile", "")),
            _prop("2cbom:digest", doc.get("integrity", {}).get("digest", "")),
            _prop("2cbom:conformant", "true" if doc.get("conformance", {}).get("conformant") else "false"),
        ] + [_prop(f"2cbom:source:{s['id']}", f"{s['tool'].get('name')} {s['tool'].get('version', '')} {s['format']} {s['specVersion']} {s['digest']}".strip())
             for s in doc.get("lineage", {}).get("sources", [])] + typed,
    }
    if metadata["timestamp"] is None:
        del metadata["timestamp"]
    if root:
        metadata["component"] = {"type": root["type"] if root["type"] != "unknown" else "application",
                                 "bom-ref": root["id"], "name": root["name"], **({"version": root["version"]} if root.get("version") else {})}
        components = [c for c in components if c.get("bom-ref") != root["id"]]
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + stable_uuid("cdx:" + doc.get("integrity", {}).get("digest", "")),
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
    }
