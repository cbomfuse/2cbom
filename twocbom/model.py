"""The 2CBOM data model: closed vocabularies and the document structure.

Everything that the expert system emits is an instance of the types below.
The vocabularies are *closed*: a 2CBOM document is non-conformant if any
enumerated attribute carries a value outside the corresponding tuple.  The
tuples are supersets of the CycloneDX 1.6 vocabularies so that a conformant
2CBOM can always be projected back onto CycloneDX.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

TWOCBOM_VERSION = "1.0"
ID_PREFIX = "2cbom:"

PROFILES = ("core", "strict")

# --------------------------------------------------------------------------- #
# Closed vocabularies (Section 5 of the specification)
# --------------------------------------------------------------------------- #
ASSET_TYPES = ("algorithm", "certificate", "related-crypto-material", "protocol")

COMPONENT_TYPES = (
    "application", "framework", "library", "container", "platform",
    "operating-system", "device", "device-driver", "firmware", "file",
    "machine-learning-model", "data", "service", "unknown",
)

PRIMITIVES = (
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke",
    "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown",
)

CRYPTO_FUNCTIONS = (
    "generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive",
    "sign", "verify", "encapsulate", "decapsulate", "other", "unknown",
)

# CycloneDX 1.6 modes plus the 2CBOM extensions (xts, siv, gcm-siv, ocb, eax, cts, kw, kwp)
MODES = ("cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "xts", "siv",
         "gcm-siv", "ocb", "eax", "cts", "kw", "kwp", "other", "unknown")

# CycloneDX 1.6 paddings plus the 2CBOM extensions (pss, none, zero, iso10126, iso7816, x923)
PADDINGS = ("pkcs5", "pkcs7", "pkcs1v15", "oaep", "pss", "raw", "none", "zero",
            "iso10126", "iso7816", "x923", "other", "unknown")

CURVES = ("p192", "p224", "p256", "p384", "p521", "secp256k1",
          "brainpoolp256r1", "brainpoolp384r1", "brainpoolp512r1",
          "curve25519", "curve448", "sm2p256v1", "other", "unknown")

EXECUTION_ENVIRONMENTS = ("software-plain-ram", "software-encrypted-ram",
                          "software-tee", "hardware", "other", "unknown")

CERTIFICATION_LEVELS = (
    "none",
    "fips140-1-l1", "fips140-1-l2", "fips140-1-l3", "fips140-1-l4",
    "fips140-2-l1", "fips140-2-l2", "fips140-2-l3", "fips140-2-l4",
    "fips140-3-l1", "fips140-3-l2", "fips140-3-l3", "fips140-3-l4",
    "cc-eal1", "cc-eal1+", "cc-eal2", "cc-eal2+", "cc-eal3", "cc-eal3+",
    "cc-eal4", "cc-eal4+", "cc-eal5", "cc-eal5+", "cc-eal6", "cc-eal6+",
    "cc-eal7", "cc-eal7+", "other", "unknown",
)

PROTOCOL_TYPES = ("tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown")

MATERIAL_TYPES = (
    "private-key", "public-key", "secret-key", "key", "ciphertext", "signature",
    "digest", "initialization-vector", "nonce", "seed", "salt", "shared-secret",
    "tag", "additional-data", "password", "credential", "token", "other", "unknown",
)

MATERIAL_STATES = ("pre-activation", "active", "suspended", "deactivated",
                   "compromised", "destroyed")

RELATION_KINDS = (
    "uses",                   # component/asset -> asset it invokes
    "implements",             # component -> asset it implements
    "provides",               # library/provider -> asset it makes available
    "negotiates",             # protocol -> algorithm (through a cipher suite)
    "signed-by",              # certificate -> signature algorithm
    "subject-key-algorithm",  # certificate -> subject public key algorithm
    "instantiates",           # key material -> algorithm it is a key for
    "secured-by",             # key material -> mechanism protecting it
    "depends-on",             # generic software dependency
    "component-of",           # hybrid/cipher-suite -> constituent algorithm
)

QUANTUM_CLASSES = ("quantum-safe", "quantum-vulnerable", "classically-weak", "unknown")
# Total order used for worst-of aggregation (index 0 is the worst).
QUANTUM_CLASS_ORDER = ("classically-weak", "quantum-vulnerable", "unknown", "quantum-safe")

IR8547_STATUSES = ("acceptable", "deprecated-after-2030", "disallowed-after-2035",
                   "disallowed", "unknown")

MIGRATION_PRIORITIES = ("immediate", "high", "medium", "low", "none", "unknown")

DETECTION_METHODS = ("static-source", "static-binary", "dynamic", "network",
                     "configuration", "manual", "declared", "derived", "unknown")

SEVERITIES = ("error", "warning", "info")

SOURCE_FORMATS = ("cyclonedx-json", "ibm-cbom-json", "cyclonedx-prestandard-json", "unknown")


def worst_quantum_class(classes) -> str:
    """Return the worst class of an iterable (classically-weak < quantum-vulnerable < unknown < quantum-safe)."""
    best_index = len(QUANTUM_CLASS_ORDER)
    for c in classes:
        if c is None:
            c = "unknown"
        idx = QUANTUM_CLASS_ORDER.index(c) if c in QUANTUM_CLASS_ORDER else QUANTUM_CLASS_ORDER.index("unknown")
        best_index = min(best_index, idx)
    return QUANTUM_CLASS_ORDER[best_index] if best_index < len(QUANTUM_CLASS_ORDER) else "unknown"


def worst_priority(priorities) -> str:
    order = MIGRATION_PRIORITIES
    best = len(order)
    for p in priorities:
        if p in order:
            best = min(best, order.index(p))
    return order[best] if best < len(order) else "none"


# --------------------------------------------------------------------------- #
# Document structure
# --------------------------------------------------------------------------- #
def _clean(d: dict) -> dict:
    """Drop None values and empty containers so the canonical form is minimal."""
    out = {}
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, (list, dict, tuple)) and len(v) == 0:
            continue
        out[k] = v
    return out


@dataclass
class ToolRecord:
    name: str
    version: Optional[str] = None

    def to_dict(self):
        return _clean({"name": self.name, "version": self.version})


@dataclass
class SourceRecord:
    id: str
    digest: str
    format: str
    specVersion: str
    tool: ToolRecord
    trust: int
    detectionMethod: str
    path: Optional[str] = None
    assetCount: int = 0
    componentCount: int = 0
    notes: list = field(default_factory=list)

    def to_dict(self):
        return _clean({
            "id": self.id, "digest": self.digest, "format": self.format,
            "specVersion": self.specVersion, "tool": self.tool.to_dict(),
            "trust": self.trust, "detectionMethod": self.detectionMethod,
            "path": self.path, "assetCount": self.assetCount,
            "componentCount": self.componentCount, "notes": sorted(set(self.notes)),
        })


@dataclass
class EvidenceRecord:
    source: str
    tool: str
    method: str
    location: Optional[str] = None
    line: Optional[int] = None
    offset: Optional[int] = None
    symbol: Optional[str] = None
    context: Optional[str] = None
    confidence: float = 1.0

    def key(self):
        return (self.source, self.location or "", self.line if self.line is not None else -1,
                self.offset if self.offset is not None else -1, self.symbol or "", self.method)

    def to_dict(self):
        return _clean({
            "source": self.source, "tool": self.tool, "method": self.method,
            "location": self.location, "line": self.line, "offset": self.offset,
            "symbol": self.symbol, "context": self.context,
            "confidence": self.confidence,
        })


@dataclass
class Assessment:
    quantumClass: str = "unknown"
    nistQuantumSecurityLevel: Optional[int] = None
    classicalSecurityLevel: Optional[int] = None
    nistIr8547: str = "unknown"
    cnsa2: Optional[bool] = None
    fipsApproved: Optional[bool] = None
    migrationPriority: str = "unknown"
    rationale: list = field(default_factory=list)

    def to_dict(self):
        return _clean({
            "quantumClass": self.quantumClass,
            "nistQuantumSecurityLevel": self.nistQuantumSecurityLevel,
            "classicalSecurityLevel": self.classicalSecurityLevel,
            "nistIr8547": self.nistIr8547, "cnsa2": self.cnsa2,
            "fipsApproved": self.fipsApproved,
            "migrationPriority": self.migrationPriority,
            "rationale": sorted(set(self.rationale)),
        })


@dataclass
class Asset:
    id: str
    type: str
    name: str
    aliases: list = field(default_factory=list)
    properties: dict = field(default_factory=dict)   # type-specific block (algorithm/certificate/material/protocol)
    assessment: Optional[Assessment] = None
    evidence: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    unresolved: bool = False

    def to_dict(self):
        block_name = {"algorithm": "algorithm", "certificate": "certificate",
                      "related-crypto-material": "material", "protocol": "protocol"}[self.type]
        d = {
            "id": self.id, "type": self.type, "name": self.name,
            "aliases": sorted(set(self.aliases)),
            block_name: _clean(self.properties),
            "assessment": self.assessment.to_dict() if self.assessment else None,
            "evidence": [e.to_dict() for e in sorted(self.evidence, key=lambda e: e.key())],
            "sources": sorted(set(self.sources)),
            "unresolved": self.unresolved,
        }
        return _clean(d)


@dataclass
class Component:
    id: str
    type: str
    name: str
    version: Optional[str] = None
    group: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    aliases: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    root: bool = False

    def to_dict(self):
        return _clean({
            "id": self.id, "type": self.type, "name": self.name, "version": self.version,
            "group": self.group, "purl": self.purl, "cpe": self.cpe,
            "aliases": sorted(set(self.aliases)), "sources": sorted(set(self.sources)),
            "root": self.root or None,
        })


@dataclass
class Relation:
    source: str
    target: str
    kind: str
    via: Optional[str] = None
    sources: list = field(default_factory=list)

    def key(self):
        return (self.source, self.target, self.kind, self.via or "")

    def to_dict(self):
        return _clean({"from": self.source, "to": self.target, "kind": self.kind,
                       "via": self.via, "sources": sorted(set(self.sources))})


@dataclass
class Finding:
    code: str
    severity: str
    subject: str
    message: str
    rule: str

    def key(self):
        sev_rank = SEVERITIES.index(self.severity) if self.severity in SEVERITIES else 99
        return (sev_rank, self.code, self.subject, self.message)

    def to_dict(self):
        return {"code": self.code, "severity": self.severity, "subject": self.subject,
                "message": self.message, "rule": self.rule}


@dataclass
class ConflictRecord:
    subject: str
    attribute: str
    chosen: Any
    candidates: list
    rule: str

    def to_dict(self):
        return {"subject": self.subject, "attribute": self.attribute, "chosen": self.chosen,
                "candidates": self.candidates, "rule": self.rule}


@dataclass
class Document:
    profile: str
    sources: list
    components: list
    assets: list
    relations: list
    findings: list
    conflicts: list
    generator: dict
    knowledgeBaseVersion: str
    rulesetVersion: str
    firedRules: dict
    timestamp: Optional[str] = None

    def to_dict(self) -> dict:
        """Return the document without integrity information (digest/serialNumber are added by the serializer)."""
        errors = sum(1 for f in self.findings if f.severity == "error")
        warnings = sum(1 for f in self.findings if f.severity == "warning")
        infos = sum(1 for f in self.findings if f.severity == "info")
        by_class: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        for a in self.assets:
            if a.assessment:
                by_class[a.assessment.quantumClass] = by_class.get(a.assessment.quantumClass, 0) + 1
                by_priority[a.assessment.migrationPriority] = by_priority.get(a.assessment.migrationPriority, 0) + 1
        return {
            "2cbomVersion": TWOCBOM_VERSION,
            "profile": self.profile,
            "generated": _clean({"timestamp": self.timestamp, "generator": self.generator}),
            "lineage": {
                "sources": [s.to_dict() for s in sorted(self.sources, key=lambda s: s.id)],
                "ruleset": {"version": self.rulesetVersion, "firedRules": dict(sorted(self.firedRules.items()))},
                "knowledgeBase": {"version": self.knowledgeBaseVersion},
                "conflicts": [c.to_dict() for c in sorted(self.conflicts, key=lambda c: (c.subject, c.attribute))],
            },
            "components": [c.to_dict() for c in sorted(self.components, key=lambda c: c.id)],
            "assets": [a.to_dict() for a in sorted(self.assets, key=lambda a: a.id)],
            "relations": [r.to_dict() for r in sorted(self.relations, key=lambda r: r.key())],
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda f: f.key())],
            "conformance": {
                "profile": self.profile,
                "conformant": errors == 0,
                "errors": errors, "warnings": warnings, "infos": infos,
            },
            "summary": {
                "componentCount": len(self.components),
                "assetCount": len(self.assets),
                "relationCount": len(self.relations),
                "assetsByQuantumClass": dict(sorted(by_class.items())),
                "assetsByMigrationPriority": dict(sorted(by_priority.items())),
            },
        }
