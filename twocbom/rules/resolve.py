"""Phase 2 -- entity resolution.

* subsumption: a less specific detection ("AES") is absorbed by a more
  specific one ("aes-128-gcm") reported at the same source location;
* materialisation: canonical Asset/Component facts, raw->canonical membership,
  aliases, attribute candidates with provenance, evidence and typed relations.
"""
from __future__ import annotations

from ..canonical import AlgorithmDescriptor
from ..engine.facts import (Alias, Asset, Attr, Candidate, Component, Evidence, Member, RawAsset, RawComponent,
                            RawEvidence, RawRelation, Relation, Subsumed, J, U)
from ..engine.rules import rule
from .common import DERIVED_STRENGTH, KB_TRUST, derived_attrs, finding, severity, strength_of, tool_of, trust_of

ALGORITHM_TOOL_ATTRS = ("cryptoFunctions", "executionEnvironment", "implementationPlatform", "certificationLevel",
                        "classicalSecurityLevel", "nistQuantumSecurityLevel", "oid", "properties")
CERT_ATTRS = ("subjectName", "issuerName", "notValidBefore", "notValidAfter", "certificateFormat",
              "certificateExtension", "serialNumber", "fingerprint", "signatureAlgorithm", "signatureAlgorithmRef",
              "subjectPublicKeyAlgorithm", "subjectPublicKeyRef", "properties")
MATERIAL_ATTRS = ("type", "id", "state", "size", "format", "creationDate", "activationDate", "updateDate",
                  "expirationDate", "securedByMechanism", "securedByAlgorithmRef", "algorithm", "algorithmRef",
                  "fingerprint", "properties")
PROTOCOL_ATTRS = ("type", "version", "cipherSuites", "cryptoRefs", "properties")
COMPONENT_ATTRS = ("name", "version", "group", "purl", "cpe", "ctype")


def _extends(generic: AlgorithmDescriptor, specific: AlgorithmDescriptor) -> bool:
    """True when ``specific`` agrees with every slot ``generic`` sets and sets strictly more."""
    if generic.family != specific.family:
        return False
    more = False
    for slot in ("parameter_set", "curve", "mode", "padding", "hash"):
        g, s = getattr(generic, slot), getattr(specific, slot)
        if g is not None and g != s:
            return False
        if g is None and s is not None:
            more = True
    return more


@rule("resolve.subsume-by-location", 850, "resolve",
      "Absorb a generic algorithm detection into a more specific one at the same file and line.")
def r_subsume(wm):
    for cand in wm.get(Candidate):
        if cand.asset_type != "algorithm" or cand.basis != "grammar":
            continue
        generic = AlgorithmDescriptor.from_dict(U(cand.canonical_json))
        for ev in wm.find(RawEvidence, sid=cand.sid, ref=cand.ref):
            if not ev.location or ev.line < 0:
                continue
            for other_ev in wm.find(RawEvidence, location=ev.location):
                if other_ev.line != ev.line or (other_ev.sid, other_ev.ref) == (cand.sid, cand.ref):
                    continue
                for oc in wm.find(Candidate, sid=other_ev.sid, ref=other_ev.ref):
                    if oc.asset_type != "algorithm" or oc.basis != "grammar":
                        continue
                    specific = AlgorithmDescriptor.from_dict(U(oc.canonical_json))
                    if _extends(generic, specific):
                        yield (cand, oc)


@r_subsume.then
def _(wm, cand, oc):
    # the most specific candidate wins; if several, the lexicographically smallest cid keeps determinism
    return [Subsumed(cand.sid, cand.ref, oc.cid, oc.sid, oc.ref)]


@rule("resolve.subsume-certificate-by-dn", 850, "resolve",
      "A certificate identified only by its distinguished names is absorbed by the fingerprint-identified copy with the same names and validity.")
def r_subsume_cert(wm):
    for cand in wm.get(Candidate):
        if cand.asset_type != "certificate" or cand.basis != "distinguished-name":
            continue
        key = U(cand.canonical_json).get("dnKey")
        if not key:
            continue
        for oc in wm.get(Candidate):
            if oc.asset_type == "certificate" and oc.basis == "fingerprint" and U(oc.canonical_json).get("dnKey") == key:
                yield (cand, oc)


@r_subsume_cert.then
def _(wm, cand, oc):
    return [Subsumed(cand.sid, cand.ref, oc.cid, oc.sid, oc.ref)]


@rule("resolve.materialize", 800, "resolve",
      "Create the canonical asset/component for a candidate (unless subsumed) and record membership and aliases.")
def r_materialize(wm):
    for cand in wm.get(Candidate):
        yield (cand,)


@r_materialize.then
def _(wm, cand):
    facts = []
    subs = wm.find(Subsumed, sid=cand.sid, ref=cand.ref)
    if subs:
        def specificity(s):
            oc = wm.one(Candidate, sid=s.by_sid, ref=s.by_ref)
            n = 0
            if oc and oc.asset_type == "algorithm" and oc.basis == "grammar":
                d = AlgorithmDescriptor.from_dict(U(oc.canonical_json))
                n = sum(1 for slot in ("parameter_set", "curve", "mode", "padding", "hash") if getattr(d, slot))
            return (-n, s.cid)
        target = min(subs, key=specificity).cid
        facts.append(Member(cand.sid, cand.ref, target))
        ra = wm.one(RawAsset, sid=cand.sid, ref=cand.ref)
        if ra and ra.name:
            facts.append(Alias(target, ra.name))
        facts.append(finding("2CBOM-I01-SUBSUMED", "info", target,
                             f"detection {cand.ref!r} ({ra.name if ra else ''}) from {cand.sid} absorbed into {target} (same location)",
                             "resolve.subsume-by-location"))
        return facts
    if cand.asset_type == "component":
        rc = wm.one(RawComponent, sid=cand.sid, ref=cand.ref)
        facts.append(Component(cand.cid, rc.ctype if rc else "unknown"))
        facts.append(Member(cand.sid, cand.ref, cand.cid))
        if rc and rc.name:
            facts.append(Alias(cand.cid, rc.name))
        return facts
    facts.append(Asset(cand.cid, cand.asset_type))
    facts.append(Member(cand.sid, cand.ref, cand.cid))
    ra = wm.one(RawAsset, sid=cand.sid, ref=cand.ref)
    if ra and ra.name:
        facts.append(Alias(cand.cid, ra.name))
    if cand.asset_type == "algorithm":
        canon = U(cand.canonical_json)
        if canon.get("unresolved"):
            facts.append(Attr(cand.cid, "unresolved", J(True), "derived", DERIVED_STRENGTH, KB_TRUST, 1.0))
            facts.append(Attr(cand.cid, "primitive", J("unknown"), "derived", DERIVED_STRENGTH, KB_TRUST, 1.0))
        else:
            facts.extend(derived_attrs(cand.cid, AlgorithmDescriptor.from_dict(canon), cand.confidence))
        for note in U(cand.notes_json):
            if note.startswith("pre-standard:"):
                facts.append(Attr(cand.cid, "preStandardNames", J([ra.name if ra else note]), "derived", DERIVED_STRENGTH, KB_TRUST, 1.0))
            else:
                facts.append(Attr(cand.cid, "parseNotes", J([note]), cand.sid, 0, KB_TRUST, 1.0))
    elif cand.asset_type == "protocol":
        canon = U(cand.canonical_json)
        facts.append(Attr(cand.cid, "type", J(canon.get("type")), "derived", DERIVED_STRENGTH, KB_TRUST, 1.0))
        if canon.get("version"):
            facts.append(Attr(cand.cid, "version", J(canon.get("version")), "derived", DERIVED_STRENGTH, KB_TRUST, 1.0))
    elif cand.asset_type == "related-crypto-material":
        canon = U(cand.canonical_json)
        facts.append(Attr(cand.cid, "identityBasis", J(canon.get("basis")), "derived", DERIVED_STRENGTH, KB_TRUST, 1.0))
    elif cand.asset_type == "certificate":
        canon = U(cand.canonical_json)
        facts.append(Attr(cand.cid, "identityBasis", J(canon.get("basis")), "derived", DERIVED_STRENGTH, KB_TRUST, 1.0))
    return facts


@rule("resolve.attributes", 790, "resolve",
      "Assert tool-reported attributes of a raw asset as provenance-tagged candidates of its canonical asset.")
def r_attributes(wm):
    for m in wm.get(Member):
        ra = wm.one(RawAsset, sid=m.sid, ref=m.ref)
        if ra is not None:
            yield (m, ra)


@r_attributes.then
def _(wm, m, ra):
    f = U(ra.fields_json)
    trust = trust_of(wm, m.sid)
    attrs = {"algorithm": ALGORITHM_TOOL_ATTRS, "certificate": CERT_ATTRS,
             "related-crypto-material": MATERIAL_ATTRS, "protocol": PROTOCOL_ATTRS}[ra.asset_type]
    facts = []
    own_candidate = wm.one(Candidate, sid=m.sid, ref=m.ref)
    subsumed = own_candidate is not None and own_candidate.cid != m.cid
    if ra.oid and ra.asset_type == "algorithm" and not subsumed:   # the OID of a generic detection is not the OID of the specific asset
        facts.append(Attr(m.cid, "oid", J(ra.oid), m.sid, strength_of(wm, m.sid, "oid"), trust, 1.0))
    for name in attrs:
        if name == "oid":
            continue
        v = f.get(name)
        if v in (None, "", [], {}):
            continue
        if name == "primitive":
            continue
        facts.append(Attr(m.cid, name, J(v), m.sid, strength_of(wm, m.sid, name), trust, 1.0))
    if ra.asset_type == "algorithm" and f.get("primitive"):
        facts.append(Attr(m.cid, "toolPrimitive", J(f["primitive"]), m.sid, strength_of(wm, m.sid, "primitive"), trust, 1.0))
    return facts


@rule("resolve.component-attributes", 790, "resolve", "Assert component attributes with provenance.")
def r_component_attributes(wm):
    for m in wm.get(Member):
        rc = wm.one(RawComponent, sid=m.sid, ref=m.ref)
        if rc is not None:
            yield (m, rc)


@r_component_attributes.then
def _(wm, m, rc):
    trust = trust_of(wm, m.sid)
    facts = []
    for name in COMPONENT_ATTRS:
        v = getattr(rc, name)
        if v in (None, ""):
            continue
        facts.append(Attr(m.cid, name, J(v), m.sid, strength_of(wm, m.sid, name), trust, 1.0))
    if rc.root:
        facts.append(Attr(m.cid, "root", J(True), m.sid, 0, trust, 1.0))
    return facts


@rule("resolve.evidence", 785, "resolve", "Attach every raw occurrence to the canonical asset it now belongs to.")
def r_evidence(wm):
    for m in wm.get(Member):
        for ev in wm.find(RawEvidence, sid=m.sid, ref=m.ref):
            yield (m, ev)


@r_evidence.then
def _(wm, m, ev):
    return [Evidence(m.cid, m.sid, tool_of(wm, m.sid), ev.method, ev.location, ev.line, ev.offset,
                     ev.symbol, ev.context, ev.confidence)]


@rule("resolve.relations", 780, "resolve", "Lift raw dependencies into typed relations between canonical entities.")
def r_relations(wm):
    for rr in wm.get(RawRelation):
        src = wm.find(Member, sid=rr.sid, ref=rr.src)
        dst = wm.find(Member, sid=rr.sid, ref=rr.dst)
        if src and dst:
            yield (rr, src[0], dst[0])


@r_relations.then
def _(wm, rr, src, dst):
    kind = rr.kind
    src_is_comp = wm.exists(Component, cid=src.cid)
    dst_is_comp = wm.exists(Component, cid=dst.cid)
    if kind == "uses" and src_is_comp and dst_is_comp:
        kind = "depends-on"
    if kind == "depends-on" and not dst_is_comp:
        kind = "uses"
    if src.cid == dst.cid:
        return []
    return [Relation(src.cid, dst.cid, kind, rr.sid)]


@rule("resolve.dangling-relation", 775, "resolve", "Report dependency references that point to nothing in their source.")
def r_dangling(wm):
    for rr in wm.get(RawRelation):
        if not wm.find(Member, sid=rr.sid, ref=rr.dst) or not wm.find(Member, sid=rr.sid, ref=rr.src):
            yield (rr,)


@r_dangling.then
def _(wm, rr):
    return [finding("2CBOM-C04-DANGLING-RELATION", "warning", f"{rr.sid}:{rr.src}",
                    f"dependency {rr.src!r} -> {rr.dst!r} ({rr.kind}) references an unknown bom-ref", "resolve.dangling-relation")]
