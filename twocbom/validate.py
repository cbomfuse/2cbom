"""Validation of 2CBOM documents (Section 7 and 8 of the specification).

Two layers:

1. structural validation against the JSON Schema that :func:`build_schema`
   derives from the closed vocabularies in :mod:`twocbom.model` (uses the
   optional ``jsonschema`` package when installed, otherwise a built-in subset);
2. semantic checks that a schema cannot express: canonical ordering of arrays,
   referential integrity of relations, digest and serial number verification.
"""
from __future__ import annotations

import json
import re
from typing import Optional

from . import model
from .canonical import digest as content_digest, stable_uuid
from .merge import digest_scope

ID_RE = r"^2cbom:(alg|cert|key|proto|comp):.+$"


def build_schema() -> dict:
    def enum(values):
        return {"type": "string", "enum": list(values)}

    id_schema = {"type": "string", "pattern": ID_RE}
    evidence = {
        "type": "object", "additionalProperties": False,
        "required": ["source", "tool", "method", "confidence"],
        "properties": {
            "source": {"type": "string", "pattern": "^src-[0-9a-f]{12}$"}, "tool": {"type": "string"},
            "method": enum(model.DETECTION_METHODS), "location": {"type": "string"},
            "line": {"type": "integer", "minimum": 0}, "offset": {"type": "integer", "minimum": 0},
            "symbol": {"type": "string"}, "context": {"type": "string"},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        },
    }
    assessment = {
        "type": "object", "additionalProperties": False,
        "required": ["quantumClass", "nistIr8547", "migrationPriority"],
        "properties": {
            "quantumClass": enum(model.QUANTUM_CLASSES),
            "nistQuantumSecurityLevel": {"type": "integer", "minimum": 0, "maximum": 5},
            "classicalSecurityLevel": {"type": "integer", "minimum": 0},
            "nistIr8547": enum(model.IR8547_STATUSES), "cnsa2": {"type": "boolean"},
            "fipsApproved": {"type": "boolean"}, "migrationPriority": enum(model.MIGRATION_PRIORITIES),
            "rationale": {"type": "array", "items": {"type": "string"}},
        },
    }
    algorithm = {
        "type": "object", "additionalProperties": False,
        "required": ["primitive"],
        "properties": {
            "family": {"type": "string"}, "primitive": enum(model.PRIMITIVES),
            "parameterSet": {"type": "string"}, "curve": {"type": "string"},
            "mode": enum(model.MODES), "padding": enum(model.PADDINGS), "hash": {"type": "string"},
            "components": {"type": "array", "items": id_schema},
            "cryptoFunctions": {"type": "array", "items": enum(model.CRYPTO_FUNCTIONS)},
            "classicalSecurityLevel": {"type": "integer", "minimum": 0},
            "nistQuantumSecurityLevel": {"type": "integer", "minimum": 0, "maximum": 5},
            "oid": {"type": "string", "pattern": r"^\d+(\.\d+)+$"},
            "standards": {"type": "array", "items": {"type": "string"}},
            "executionEnvironment": enum(model.EXECUTION_ENVIRONMENTS),
            "implementationPlatform": {"type": "string"},
            "certificationLevel": {"type": "array", "items": enum(model.CERTIFICATION_LEVELS)},
            "preStandardNames": {"type": "array", "items": {"type": "string"}},
            "stateful": {"type": "boolean"}, "toolPrimitive": {"type": "string"},
            "toolProperties": {"type": "object"}, "notes": {"type": "array", "items": {"type": "string"}},
        },
    }
    certificate = {
        "type": "object", "additionalProperties": False,
        "properties": {
            "subject": {"type": "string"}, "issuer": {"type": "string"}, "serialNumber": {"type": "string"},
            "notBefore": {"type": "string"}, "notAfter": {"type": "string"}, "format": {"type": "string"},
            "extension": {"type": "string"}, "fingerprint": {"type": "string"},
            "signatureAlgorithm": id_schema, "subjectPublicKeyAlgorithm": id_schema,
            "identityBasis": enum(("fingerprint", "distinguished-name", "location", "unresolved")),
            "toolProperties": {"type": "object"},
        },
    }
    material = {
        "type": "object", "additionalProperties": False,
        "required": ["type"],
        "properties": {
            "type": enum(model.MATERIAL_TYPES), "identifier": {"type": "string"}, "state": enum(model.MATERIAL_STATES),
            "size": {"type": "integer", "minimum": 0}, "format": {"type": "string"},
            "algorithm": id_schema, "algorithms": {"type": "array", "items": id_schema},
            "creationDate": {"type": "string"}, "activationDate": {"type": "string"},
            "updateDate": {"type": "string"}, "expirationDate": {"type": "string"},
            "securedBy": {"type": "object", "properties": {"mechanism": {"type": "string"}, "algorithm": id_schema}},
            "fingerprint": {"type": "string"},
            "identityBasis": enum(("fingerprint", "identifier", "location", "source-local")),
            "toolProperties": {"type": "object"},
        },
    }
    protocol = {
        "type": "object", "additionalProperties": False,
        "required": ["type"],
        "properties": {
            "type": enum(model.PROTOCOL_TYPES), "version": {"type": "string"},
            "cipherSuites": {"type": "array", "items": {
                "type": "object", "additionalProperties": False,
                "properties": {"name": {"type": "string"}, "identifier": {"type": "string"},
                               "algorithms": {"type": "array", "items": id_schema}, "keyExchangeKnown": {"type": "boolean"}}}},
            "references": {"type": "array", "items": id_schema},
            "toolProperties": {"type": "object"},
        },
    }
    asset = {
        "type": "object", "additionalProperties": False,
        "required": ["id", "type", "name", "evidence", "sources"],
        "properties": {
            "id": id_schema, "type": enum(model.ASSET_TYPES), "name": {"type": "string"},
            "aliases": {"type": "array", "items": {"type": "string"}},
            "algorithm": algorithm, "certificate": certificate, "material": material, "protocol": protocol,
            "assessment": assessment,
            "evidence": {"type": "array", "minItems": 1, "items": evidence},
            "sources": {"type": "array", "minItems": 1, "items": {"type": "string"}},
            "unresolved": {"type": "boolean"},
        },
        "allOf": [
            {"if": {"properties": {"type": {"const": "algorithm"}}}, "then": {"required": ["algorithm"]}},
            {"if": {"properties": {"type": {"const": "certificate"}}}, "then": {"required": ["certificate"]}},
            {"if": {"properties": {"type": {"const": "related-crypto-material"}}}, "then": {"required": ["material"]}},
            {"if": {"properties": {"type": {"const": "protocol"}}}, "then": {"required": ["protocol"]}},
        ],
    }
    component = {
        "type": "object", "additionalProperties": False,
        "required": ["id", "type", "name", "sources"],
        "properties": {
            "id": id_schema, "type": enum(model.COMPONENT_TYPES), "name": {"type": "string"},
            "version": {"type": "string"}, "group": {"type": "string"}, "purl": {"type": "string"},
            "cpe": {"type": "string"}, "aliases": {"type": "array", "items": {"type": "string"}},
            "sources": {"type": "array", "items": {"type": "string"}}, "root": {"type": "boolean"},
        },
    }
    relation = {
        "type": "object", "additionalProperties": False,
        "required": ["from", "to", "kind"],
        "properties": {"from": id_schema, "to": id_schema, "kind": enum(model.RELATION_KINDS),
                       "via": {"type": "string"}, "sources": {"type": "array", "items": {"type": "string"}}},
    }
    finding = {
        "type": "object", "additionalProperties": False,
        "required": ["code", "severity", "subject", "message", "rule"],
        "properties": {"code": {"type": "string", "pattern": "^2CBOM-[A-Z]\\d{2}[A-Za-z]?-[A-Z0-9-]+$"},
                       "severity": enum(model.SEVERITIES), "subject": {"type": "string"},
                       "message": {"type": "string"}, "rule": {"type": "string"}},
    }
    source = {
        "type": "object", "additionalProperties": False,
        "required": ["id", "digest", "format", "specVersion", "tool", "trust", "detectionMethod"],
        "properties": {
            "id": {"type": "string", "pattern": "^src-[0-9a-f]{12}$"},
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "format": enum(model.SOURCE_FORMATS), "specVersion": {"type": "string"},
            "tool": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}, "version": {"type": "string"}}},
            "trust": {"type": "integer", "minimum": 0, "maximum": 100},
            "detectionMethod": enum(model.DETECTION_METHODS), "path": {"type": "string"},
            "assetCount": {"type": "integer"}, "componentCount": {"type": "integer"},
            "notes": {"type": "array", "items": {"type": "string"}},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://2cbom.org/schema/2cbom-1.0.schema.json",
        "title": "Canonical Cryptography Bill of Materials (2CBOM) 1.0",
        "type": "object", "additionalProperties": False,
        "required": ["2cbomVersion", "profile", "serialNumber", "integrity", "lineage", "components", "assets",
                     "relations", "findings", "conformance", "summary"],
        "properties": {
            "2cbomVersion": {"const": model.TWOCBOM_VERSION},
            "profile": enum(model.PROFILES),
            "serialNumber": {"type": "string", "pattern": "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"},
            "generated": {"type": "object", "properties": {"timestamp": {"type": "string"}, "generator": {"type": "object"}}},
            "integrity": {"type": "object", "required": ["algorithm", "canonicalization", "digest"],
                          "properties": {"algorithm": {"const": "sha-256"}, "canonicalization": {"const": "RFC8785"},
                                         "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}, "scope": {"type": "string"}}},
            "lineage": {"type": "object", "required": ["sources", "ruleset", "knowledgeBase"],
                        "properties": {"sources": {"type": "array", "minItems": 1, "items": source},
                                       "ruleset": {"type": "object"}, "knowledgeBase": {"type": "object"},
                                       "conflicts": {"type": "array"}}},
            "components": {"type": "array", "items": component},
            "assets": {"type": "array", "items": asset},
            "relations": {"type": "array", "items": relation},
            "findings": {"type": "array", "items": finding},
            "conformance": {"type": "object", "required": ["profile", "conformant", "errors", "warnings", "infos"]},
            "summary": {"type": "object"},
        },
    }


# --------------------------------------------------------------------------- #
# built-in minimal validator (used when jsonschema is not installed)
# --------------------------------------------------------------------------- #
def _check(schema: dict, value, path: str, errors: list):
    t = schema.get("type")
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected {schema['const']!r}")
        return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not in {schema['enum'][:6]}...")
        return
    if t == "object":
        if not isinstance(value, dict):
            errors.append(f"{path}: expected object")
            return
        for req in schema.get("required", []):
            if req not in value:
                errors.append(f"{path}: missing required member {req!r}")
        props = schema.get("properties", {})
        for k, v in value.items():
            if k in props:
                _check(props[k], v, f"{path}.{k}", errors)
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected member {k!r}")
        for clause in schema.get("allOf", []):
            cond = clause.get("if", {}).get("properties", {})
            if all(value.get(k) == v.get("const") for k, v in cond.items()):
                for req in clause.get("then", {}).get("required", []):
                    if req not in value:
                        errors.append(f"{path}: missing required member {req!r} for this type")
    elif t == "array":
        if not isinstance(value, list):
            errors.append(f"{path}: expected array")
            return
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        for i, item in enumerate(value):
            _check(schema.get("items", {}), item, f"{path}[{i}]", errors)
    elif t == "string":
        if not isinstance(value, str):
            errors.append(f"{path}: expected string")
        elif "pattern" in schema and not re.match(schema["pattern"], value):
            errors.append(f"{path}: {value!r} does not match {schema['pattern']}")
    elif t == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            errors.append(f"{path}: expected integer")
        elif "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum")
        elif "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: above maximum")
    elif t == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            errors.append(f"{path}: expected number")
    elif t == "boolean":
        if not isinstance(value, bool):
            errors.append(f"{path}: expected boolean")


def validate_document(doc: dict, use_jsonschema: bool = True) -> list:
    """Return a list of validation errors (empty when the document is valid)."""
    errors: list = []
    schema = build_schema()
    if use_jsonschema:
        try:
            import jsonschema  # type: ignore
            validator = jsonschema.Draft202012Validator(schema)
            for e in sorted(validator.iter_errors(doc), key=lambda e: list(e.path)):
                errors.append("$." + ".".join(str(p) for p in e.path) + ": " + e.message)
        except ImportError:
            _check(schema, doc, "$", errors)
    else:
        _check(schema, doc, "$", errors)

    # semantic constraints
    ids = {a["id"] for a in doc.get("assets", [])} | {c["id"] for c in doc.get("components", [])}
    if len(ids) != len(doc.get("assets", [])) + len(doc.get("components", [])):
        errors.append("C1: duplicate identifiers")
    for r in doc.get("relations", []):
        if r["from"] not in ids or r["to"] not in ids:
            errors.append(f"C4: relation {r['from']} -> {r['to']} references an unknown entity")
    asset_ids = [a["id"] for a in doc.get("assets", [])]
    if asset_ids != sorted(asset_ids):
        errors.append("C9/canonical order: assets are not sorted by id")
    for a in doc.get("assets", []):
        if a["type"] == "certificate":
            cert = a.get("certificate", {})
            for k in ("signatureAlgorithm", "subjectPublicKeyAlgorithm"):
                if cert.get(k) and cert[k] not in ids:
                    errors.append(f"C5/C6: {a['id']} references unknown algorithm {cert[k]}")
        if a["type"] == "related-crypto-material":
            for c in a.get("material", {}).get("algorithms", []):
                if c not in ids:
                    errors.append(f"C9: {a['id']} references unknown algorithm {c}")
        if a["type"] == "protocol":
            for s in a.get("protocol", {}).get("cipherSuites", []):
                for c in s.get("algorithms", []):
                    if c not in ids:
                        errors.append(f"C8: {a['id']} suite references unknown algorithm {c}")
    if a_ := doc.get("integrity"):
        expected = content_digest(digest_scope(doc))
        if a_.get("digest") != expected:
            errors.append(f"C9/integrity: digest mismatch (expected {expected})")
        elif doc.get("serialNumber") != "urn:uuid:" + stable_uuid(expected):
            errors.append("C9/integrity: serialNumber is not derived from the digest")
    return errors


def schema_json() -> str:
    return json.dumps(build_schema(), indent=2)
