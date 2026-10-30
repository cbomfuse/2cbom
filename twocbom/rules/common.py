"""Helpers shared by the rule modules."""
from __future__ import annotations

from typing import Optional

from ..canonical import AlgorithmDescriptor, parse_algorithm, short_hash
from ..engine.facts import (Alias, Asset, Attr, Config, Evidence, Finding, Resolved, Source, J, U, WorkingMemory)
from ..knowledge import KnowledgeBase, load_kb
from ..model import ID_PREFIX

KB: KnowledgeBase = load_kb()

DERIVED_STRENGTH = 5
KB_STRENGTH = 9
KB_TRUST = 100


def profile(wm: WorkingMemory) -> str:
    cfg = wm.one(Config)
    return cfg.profile if cfg else "strict"


def severity(wm: WorkingMemory, strict: str, core: str) -> str:
    """Severity of a finding under the active profile."""
    return strict if profile(wm) == "strict" else core


def source_of(wm: WorkingMemory, sid: str) -> Optional[Source]:
    return wm.one(Source, sid=sid)


def tool_of(wm: WorkingMemory, sid: str) -> str:
    s = source_of(wm, sid)
    return s.tool if s else "unknown"


def trust_of(wm: WorkingMemory, sid: str) -> int:
    s = source_of(wm, sid)
    return s.trust if s else 50


def strength_of(wm: WorkingMemory, sid: str, attr: str) -> int:
    s = source_of(wm, sid)
    if not s:
        return 0
    prof = KB.tool_profile(s.tool)
    return 1 if attr in prof.strengths else 0


def descriptor_of(wm: WorkingMemory, cid: str) -> Optional[AlgorithmDescriptor]:
    a = wm.one(Attr, cid=cid, name="descriptor")
    if a is None:
        return None
    return AlgorithmDescriptor.from_dict(U(a.value_json))


def resolved(wm: WorkingMemory, cid: str, name: str, default=None):
    r = wm.find(Resolved, cid=cid, name=name)
    if not r:
        return default
    return U(r[-1].value_json)


def derived_attrs(cid: str, desc: AlgorithmDescriptor, confidence: float, origin: str = "derived") -> list:
    """Attributes implied by the canonical identity itself."""
    facts = [Attr(cid, "descriptor", J(desc.to_dict()), origin, DERIVED_STRENGTH, KB_TRUST, confidence)]
    for name, value in (("family", desc.family), ("parameterSet", desc.parameter_set), ("curve", desc.curve),
                        ("mode", desc.mode), ("padding", desc.padding), ("hash", desc.hash),
                        ("primitive", desc.primitive)):
        if value is not None:
            facts.append(Attr(cid, name, J(value), origin, DERIVED_STRENGTH, KB_TRUST, confidence))
    if desc.components:
        facts.append(Attr(cid, "components", J(list(desc.components)), origin, DERIVED_STRENGTH, KB_TRUST, confidence))
    return facts


def unresolved_cid(name: str) -> str:
    return f"{ID_PREFIX}alg:unresolved:{short_hash((name or '').strip().lower(), 20)}"


def synth_algorithm(wm: WorkingMemory, name: str, hints: Optional[dict], sid: str, parent_cid: str,
                    rule_name: str, confidence: float = 1.0) -> tuple[str, list]:
    """Create (if needed) the canonical algorithm asset named by a string found inside another asset.

    Returns (cid, facts).  The synthesized asset gets *derived* evidence that
    names the parent so that constraint C2 (evidence totality) stays traceable.
    """
    pr = parse_algorithm(name, hints, KB)
    facts: list = []
    if pr.ok:
        cid = pr.descriptor.cid()
        facts.append(Asset(cid, "algorithm"))
        facts.extend(derived_attrs(cid, pr.descriptor, min(confidence, pr.confidence)))
        if pr.pre_standard:
            facts.append(Attr(cid, "preStandardNames", J([name]), "derived", DERIVED_STRENGTH, KB_TRUST, 1.0))
        for n in pr.notes:
            facts.append(Attr(cid, "parseNotes", J([n]), "derived", 0, KB_TRUST, 1.0))
    else:
        cid = unresolved_cid(name)
        facts.append(Asset(cid, "algorithm"))
        facts.append(Attr(cid, "unresolved", J(True), "derived", DERIVED_STRENGTH, KB_TRUST, 1.0))
        facts.append(Attr(cid, "primitive", J("unknown"), "derived", DERIVED_STRENGTH, KB_TRUST, 1.0))
    facts.append(Alias(cid, name))
    facts.append(Evidence(cid, sid, tool_of(wm, sid), "derived", "", -1, -1, "",
                          f"derived from {parent_cid} by rule {rule_name}", confidence))
    return cid, facts


def finding(code: str, sev: str, subject: str, message: str, rule: str) -> Finding:
    return Finding(code, sev, subject, message, rule)
