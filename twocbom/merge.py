"""The merge pipeline: ingest -> working memory -> inference -> 2CBOM document.

    merge_files([...]) == assemble(fixpoint(rules, facts(ingest(f1)) U facts(ingest(f2)) U ...))

Because the fact set is a union and the fixpoint and assembly are order-free,
the output is byte-identical for any permutation of the inputs (see
``tests/test_merge.py::test_merge_is_commutative``).
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from . import RULESET_VERSION, __version__
from .canonical import digest as content_digest, jcs_dumps, normalize_location, stable_uuid
from .engine import Engine, RunResult, WorkingMemory
from .engine.facts import (Alias, Assessment as AssessmentFact, Asset as AssetFact, Attr, Component as ComponentFact,
                           Config, Conflict as ConflictFact, Evidence as EvidenceFact, Finding as FindingFact, Member,
                           RawAsset, RawComponent, RawEvidence, RawRelation, Relation as RelationFact, Resolved,
                           Source as SourceFact, Suite, J, U)
from .ingest import IngestResult, ingest_file
from .knowledge import load_kb
from .model import (Assessment, Asset, Component, ConflictRecord, Document, EvidenceRecord, Finding, ID_PREFIX, Relation,
                    SourceRecord, ToolRecord)
from . import rules as _rules  # noqa: F401  (registers the rule base)

KB = load_kb()

_INGEST_SEVERITY = {
    "2CBOM-C17-SPEC-VERSION-NONSTANDARD": "info",
    "2CBOM-C18-SECRET-VALUE-DROPPED": "warning",
    "2CBOM-C11-VOCABULARY-VIOLATION": "error",
}


@dataclass
class MergeOptions:
    profile: str = "strict"
    strip_prefixes: tuple = ()
    tool_overrides: dict = field(default_factory=dict)   # path -> tool name
    trace: bool = True
    timestamp: Optional[str] = None                      # ISO 8601; None = now


@dataclass
class MergeResult:
    document: dict
    run: RunResult
    wm: WorkingMemory

    @property
    def canonical_json(self) -> str:
        return jcs_dumps(self.document)


def source_id(digest: str) -> str:
    return "src-" + digest.split(":")[-1][:12]


# --------------------------------------------------------------------------- #
# facts from IR
# --------------------------------------------------------------------------- #
def assert_ingest(wm: WorkingMemory, res: IngestResult, options: MergeOptions) -> str:
    src = res.source
    sid = source_id(src.digest)
    prof = KB.tool_profile(src.tool)
    tool_name = prof.name if prof.name != "unknown" else (src.tool or "unknown")
    wm.add(SourceFact(sid, src.digest, src.fmt, src.spec_version, tool_name, src.tool_version or "",
                      prof.trust, prof.detection_method, src.path))
    for c in res.components:
        wm.add(RawComponent(sid, c.ref, c.ctype or "unknown", c.name or "", c.version or "", c.group or "",
                            c.purl or "", c.cpe or "", bool(c.root)))
    evidenced = set()
    for e in res.evidence:
        evidenced.add(e.ref)
        wm.add(RawEvidence(sid, e.ref, normalize_location(e.location, options.strip_prefixes) or "",
                           e.line if e.line is not None else -1, e.offset if e.offset is not None else -1,
                           e.symbol or "", e.context or "", e.method or prof.detection_method,
                           e.confidence if e.confidence is not None else 1.0))
    for a in res.assets:
        wm.add(RawAsset(sid, a.ref, a.asset_type, a.name or "", J(a.fields), a.oid or ""))
        if a.ref not in evidenced:
            wm.add(RawEvidence(sid, a.ref, "", -1, -1, "", "declared by the generating tool without a location",
                               "declared", 1.0))
    for r in res.relations:
        wm.add(RawRelation(sid, r.src, r.dst, r.kind))
    for code, msg in res.findings:
        wm.add(FindingFact(code, _INGEST_SEVERITY.get(code, "info"), sid, msg, "ingest"))
    return sid


# --------------------------------------------------------------------------- #
# document assembly
# --------------------------------------------------------------------------- #
def _resolved_map(wm: WorkingMemory, cid: str) -> dict:
    out = {}
    for r in wm.find(Resolved, cid=cid):
        out[r.name] = U(r.value_json)     # later facts (if any) override: assembly is set-based
    return out


def _evidence(wm, cid):
    out = []
    for e in wm.find(EvidenceFact, cid=cid):
        out.append(EvidenceRecord(source=e.sid, tool=e.tool, method=e.method or "unknown",
                                  location=e.location or None, line=None if e.line < 0 else e.line,
                                  offset=None if e.offset < 0 else e.offset, symbol=e.symbol or None,
                                  context=e.context or None, confidence=e.confidence))
    # deduplicate by key
    seen = {}
    for e in out:
        seen.setdefault(e.key(), e)
    return list(seen.values())


def _assessment(wm, cid) -> Optional[Assessment]:
    facts = wm.find(AssessmentFact, cid=cid)
    if not facts:
        return None
    f = facts[0]
    return Assessment(quantumClass=f.quantum_class,
                      nistQuantumSecurityLevel=None if f.nist_level < 0 else f.nist_level,
                      classicalSecurityLevel=None if f.classical_level < 0 else f.classical_level,
                      nistIr8547=f.ir8547, cnsa2=f.cnsa2,
                      fipsApproved={"true": True, "false": False}.get(f.fips),
                      migrationPriority=f.priority, rationale=U(f.rationale_json))


def _relations_from(wm, cid, kind):
    return sorted({r.dst for r in wm.find(RelationFact, src=cid) if r.kind == kind})


def assemble(wm: WorkingMemory, run: RunResult, options: MergeOptions) -> Document:
    sources = []
    for s in wm.get(SourceFact):
        members = wm.find(Member, sid=s.sid)
        n_assets = sum(1 for m in members if wm.exists(RawAsset, sid=s.sid, ref=m.ref))
        n_comps = sum(1 for m in members if wm.exists(RawComponent, sid=s.sid, ref=m.ref))
        sources.append(SourceRecord(id=s.sid, digest=s.digest, format=s.fmt, specVersion=s.spec_version,
                                    tool=ToolRecord(s.tool, s.tool_version or None), trust=s.trust,
                                    detectionMethod=s.method, path=s.path or None, assetCount=n_assets,
                                    componentCount=n_comps))

    components = []
    for c in wm.get(ComponentFact):
        res = _resolved_map(wm, c.cid)
        members = wm.find(Member, cid=c.cid)
        components.append(Component(id=c.cid, type=res.get("ctype", c.ctype), name=res.get("name", c.cid),
                                    version=res.get("version"), group=res.get("group"), purl=res.get("purl"),
                                    cpe=res.get("cpe"), aliases=[a.name for a in wm.find(Alias, cid=c.cid)],
                                    sources=[m.sid for m in members], root=bool(res.get("root"))))

    assets = []
    for a in wm.get(AssetFact):
        res = _resolved_map(wm, a.cid)
        aliases = sorted({al.name for al in wm.find(Alias, cid=a.cid)})
        evidence = _evidence(wm, a.cid)
        src_ids = sorted({m.sid for m in wm.find(Member, cid=a.cid)} | {e.source for e in evidence})
        props: dict = {}
        unresolved = bool(res.get("unresolved"))
        if a.asset_type == "algorithm":
            name = a.cid[len(ID_PREFIX) + 4:]
            props = {
                "family": res.get("family"), "primitive": res.get("primitive", "unknown"),
                "parameterSet": res.get("parameterSet"), "curve": res.get("curve"), "mode": res.get("mode"),
                "padding": res.get("padding"), "hash": res.get("hash"),
                "components": [f"{ID_PREFIX}alg:{c}" for c in res.get("components", [])],
                "cryptoFunctions": res.get("cryptoFunctions", []),
                "classicalSecurityLevel": res.get("classicalSecurityLevel"),
                "nistQuantumSecurityLevel": res.get("nistQuantumSecurityLevel"),
                "oid": res.get("oid"), "standards": res.get("standards", []),
                "executionEnvironment": res.get("executionEnvironment"),
                "implementationPlatform": res.get("implementationPlatform"),
                "certificationLevel": res.get("certificationLevel", []),
                "preStandardNames": res.get("preStandardNames", []),
                "stateful": res.get("stateful"), "toolPrimitive": res.get("toolPrimitive"),
                "toolProperties": res.get("properties"), "notes": res.get("parseNotes", []),
            }
        elif a.asset_type == "certificate":
            subject = res.get("subjectName")
            name = subject or (aliases[0] if aliases else a.cid)
            props = {
                "subject": subject, "issuer": res.get("issuerName"), "serialNumber": res.get("serialNumber"),
                "notBefore": res.get("notValidBefore"), "notAfter": res.get("notValidAfter"),
                "format": res.get("certificateFormat"), "extension": res.get("certificateExtension"),
                "fingerprint": res.get("fingerprint"),
                "signatureAlgorithm": (_relations_from(wm, a.cid, "signed-by") or [None])[0],
                "subjectPublicKeyAlgorithm": (_relations_from(wm, a.cid, "subject-key-algorithm") or [None])[0],
                "identityBasis": res.get("identityBasis"), "toolProperties": res.get("properties"),
            }
        elif a.asset_type == "related-crypto-material":
            inst = _relations_from(wm, a.cid, "instantiates")
            # the most specific instantiation (longest canonical string) is the primary one
            primary = sorted(inst, key=lambda c: (-len(c), c))[0] if inst else None
            name = f"{res.get('type', 'unknown')}" + (f" ({aliases[0]})" if aliases else "")
            props = {
                "type": res.get("type", "unknown"), "identifier": res.get("id"), "state": res.get("state"),
                "size": res.get("size"), "format": res.get("format"), "algorithm": primary,
                "algorithms": inst, "creationDate": res.get("creationDate"),
                "activationDate": res.get("activationDate"), "updateDate": res.get("updateDate"),
                "expirationDate": res.get("expirationDate"),
                "securedBy": {k: v for k, v in {"mechanism": res.get("securedByMechanism"),
                                                "algorithm": (_relations_from(wm, a.cid, "secured-by") or [None])[0]}.items() if v},
                "fingerprint": res.get("fingerprint"), "identityBasis": res.get("identityBasis"),
                "toolProperties": res.get("properties"),
            }
        else:  # protocol
            ptype = res.get("type", "unknown")
            version = res.get("version")
            name = f"{ptype} {version}".strip()
            suites = []
            for s in sorted(wm.find(Suite, cid=a.cid), key=lambda s: (s.name, s.identifier)):
                entry = {"name": s.name or None, "identifier": s.identifier or None, "algorithms": U(s.algorithms_json),
                         "keyExchangeKnown": s.kex_known}
                suites.append({k: v for k, v in entry.items() if v is not None})
            # merge duplicates of the same suite reported by several sources
            merged: dict = {}
            for s in suites:
                key = s.get("name") or s.get("identifier")
                if key in merged:
                    merged[key]["algorithms"] = sorted(set(merged[key]["algorithms"]) | set(s["algorithms"]))
                else:
                    merged[key] = s
            props = {"type": ptype, "version": version, "cipherSuites": list(merged.values()),
                     "references": _relations_from(wm, a.cid, "uses"), "toolProperties": res.get("properties")}
        assets.append(Asset(id=a.cid, type=a.asset_type, name=name, aliases=aliases, properties=props,
                            assessment=_assessment(wm, a.cid), evidence=evidence, sources=src_ids,
                            unresolved=unresolved))

    relations: dict = {}
    for r in wm.get(RelationFact):
        key = (r.src, r.dst, r.kind, r.via or "")
        rel = relations.setdefault(key, Relation(source=r.src, target=r.dst, kind=r.kind, via=r.via or None))
        rel.sources.append(r.sid)

    findings = [Finding(f.code, f.severity, f.subject, f.message, f.rule) for f in wm.get(FindingFact)]
    conflicts = [ConflictRecord(c.cid, c.name, U(c.chosen_json), U(c.candidates_json), c.rule) for c in wm.get(ConflictFact)]

    return Document(profile=options.profile, sources=sources, components=components, assets=assets,
                    relations=list(relations.values()), findings=findings, conflicts=conflicts,
                    generator={"name": "twocbom", "version": __version__},
                    knowledgeBaseVersion=KB.version, rulesetVersion=RULESET_VERSION,
                    firedRules=dict(run.fired), timestamp=options.timestamp)


# --------------------------------------------------------------------------- #
# integrity
# --------------------------------------------------------------------------- #
def digest_scope(doc: dict) -> dict:
    """The part of the document covered by the digest: everything but integrity and the timestamp."""
    scoped = copy.deepcopy(doc)
    scoped.pop("integrity", None)
    scoped.pop("serialNumber", None)
    if "generated" in scoped:
        scoped["generated"].pop("timestamp", None)
    return scoped


def seal(doc: dict) -> dict:
    """Add serialNumber and integrity to a document (idempotent)."""
    d = content_digest(digest_scope(doc))
    doc["serialNumber"] = "urn:uuid:" + stable_uuid(d)
    doc["integrity"] = {"algorithm": "sha-256", "canonicalization": "RFC8785", "digest": d,
                        "scope": "all members except integrity, serialNumber and generated.timestamp"}
    return doc


# --------------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------------- #
def merge_ingested(inputs: list, options: Optional[MergeOptions] = None) -> MergeResult:
    options = options or MergeOptions()
    wm = WorkingMemory()
    wm.add(Config(options.profile, tuple(options.strip_prefixes)))
    for res in inputs:
        assert_ingest(wm, res, options)
    engine = Engine(trace=options.trace)
    run = engine.run(wm)
    if options.timestamp is None:
        options.timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    doc = assemble(wm, run, options).to_dict()
    seal(doc)
    return MergeResult(doc, run, wm)


def merge_files(paths: list, options: Optional[MergeOptions] = None) -> MergeResult:
    options = options or MergeOptions()
    inputs = [ingest_file(p, tool_override=options.tool_overrides.get(p)) for p in paths]
    return merge_ingested(inputs, options)
