"""Phase 3 -- structural closure.

The 2CBOM closure constraints (C5-C7) require that every algorithm a
certificate, key, protocol or hybrid refers to exists as a canonical asset
of its own.  Pre-standard and tool outputs frequently carry such references as
free-text strings ("sha256WithRSAEncryption", "TLS_AES_128_GCM_SHA256"); these
rules materialise the referenced assets and the typed relations.
"""
from __future__ import annotations

from ..canonical import AlgorithmDescriptor, parse_algorithm, parse_cipher_suite
from ..engine.facts import Asset, Attr, Evidence, Member, Relation, Suite, J, U
from ..engine.rules import rule
from .common import KB, DERIVED_STRENGTH, KB_TRUST, derived_attrs, descriptor_of, finding, synth_algorithm, tool_of


def _ref_to_cid(wm, sid, ref):
    m = wm.find(Member, sid=sid, ref=ref)
    return m[0].cid if m else None


def _source_for(wm, cid):
    """A deterministic source id to attribute derived facts about ``cid`` to."""
    sids = sorted({m.sid for m in wm.find(Member, cid=cid)} | {e.sid for e in wm.find(Evidence, cid=cid)})
    return sids[0] if sids else "unknown"


# ---- certificates --------------------------------------------------------- #
@rule("closure.certificate-signature", 700, "closure",
      "Link a certificate to its signature algorithm (by bom-ref or by canonicalising the algorithm string).")
def r_cert_sig(wm):
    for a in wm.get(Attr):
        if a.name in ("signatureAlgorithm", "signatureAlgorithmRef") and wm.exists(Asset, cid=a.cid, asset_type="certificate"):
            yield (a,)


@r_cert_sig.then
def _(wm, a):
    value = U(a.value_json)
    if a.name == "signatureAlgorithmRef":
        cid = _ref_to_cid(wm, a.origin, str(value))
        if cid:
            return [Relation(a.cid, cid, "signed-by", a.origin)]
        return [finding("2CBOM-C04-DANGLING-RELATION", "warning", a.cid, f"signatureAlgorithmRef {value!r} not found in {a.origin}", "closure.certificate-signature")]
    cid, facts = synth_algorithm(wm, str(value), None, a.origin, a.cid, "closure.certificate-signature")
    facts.append(Relation(a.cid, cid, "signed-by", a.origin))
    return facts


@rule("closure.certificate-subject-key", 700, "closure",
      "Link a certificate to the algorithm of its subject public key.")
def r_cert_key(wm):
    for a in wm.get(Attr):
        if a.name in ("subjectPublicKeyAlgorithm", "subjectPublicKeyRef") and wm.exists(Asset, cid=a.cid, asset_type="certificate"):
            yield (a,)


@r_cert_key.then
def _(wm, a):
    value = U(a.value_json)
    if a.name == "subjectPublicKeyRef":
        cid = _ref_to_cid(wm, a.origin, str(value))
        if cid:
            # the ref may point at key material; follow its algorithm when it has one
            return [Relation(a.cid, cid, "subject-key-algorithm", a.origin)]
        return [finding("2CBOM-C04-DANGLING-RELATION", "warning", a.cid, f"subjectPublicKeyRef {value!r} not found in {a.origin}", "closure.certificate-subject-key")]
    cid, facts = synth_algorithm(wm, str(value), None, a.origin, a.cid, "closure.certificate-subject-key")
    facts.append(Relation(a.cid, cid, "subject-key-algorithm", a.origin))
    return facts


# ---- key material ---------------------------------------------------------- #
@rule("closure.material-algorithm", 700, "closure",
      "Link key material to the algorithm it instantiates; the key size refines the parameter set.")
def r_material_alg(wm):
    for a in wm.get(Attr):
        if a.name in ("algorithm", "algorithmRef") and wm.exists(Asset, cid=a.cid, asset_type="related-crypto-material"):
            yield (a,)


@r_material_alg.then
def _(wm, a):
    value = U(a.value_json)
    if a.name == "algorithmRef":
        cid = _ref_to_cid(wm, a.origin, str(value))
        if cid:
            return [Relation(a.cid, cid, "instantiates", a.origin)]
        return [finding("2CBOM-C04-DANGLING-RELATION", "warning", a.cid, f"algorithmRef {value!r} not found in {a.origin}", "closure.material-algorithm")]
    size = wm.find(Attr, cid=a.cid, name="size")
    hints = {"parameterSetIdentifier": U(size[0].value_json)} if size else None
    cid, facts = synth_algorithm(wm, str(value), hints, a.origin, a.cid, "closure.material-algorithm")
    facts.append(Relation(a.cid, cid, "instantiates", a.origin))
    return facts


@rule("closure.material-secured-by", 700, "closure", "Link key material to the mechanism that protects it.")
def r_material_secured(wm):
    for a in wm.get(Attr):
        if a.name == "securedByAlgorithmRef" and wm.exists(Asset, cid=a.cid, asset_type="related-crypto-material"):
            yield (a,)


@r_material_secured.then
def _(wm, a):
    cid = _ref_to_cid(wm, a.origin, str(U(a.value_json)))
    if cid:
        return [Relation(a.cid, cid, "secured-by", a.origin)]
    return []


# ---- protocols -------------------------------------------------------------- #
@rule("closure.protocol-suites", 700, "closure",
      "Decompose each cipher suite of a protocol into canonical algorithm assets and 'negotiates' relations.")
def r_protocol_suites(wm):
    for a in wm.get(Attr):
        if a.name == "cipherSuites" and wm.exists(Asset, cid=a.cid, asset_type="protocol"):
            yield (a,)


@r_protocol_suites.then
def _(wm, a):
    facts = []
    for suite in U(a.value_json):
        name = suite.get("name")
        idents = [str(i).lower() for i in suite.get("identifiers", [])]
        if not name:
            for i in idents:
                if i in KB.cipher_suite_ids:
                    name = KB.cipher_suite_ids[i]
                    break
        parsed = parse_cipher_suite(name, KB) if name else None
        alg_cids = []
        kex_known = True
        if parsed:
            kex_known = parsed["kex_known"]
            for role, desc in parsed["components"]:
                cid, extra = synth_algorithm(wm, desc.canonical(), None, a.origin, a.cid, "closure.protocol-suites")
                alg_cids.append(cid)
                facts.extend(extra)
                facts.append(Relation(a.cid, cid, "negotiates", a.origin, parsed["name"]))
        for ref in suite.get("algorithms", []):
            cid = _ref_to_cid(wm, a.origin, ref)
            if cid:
                alg_cids.append(cid)
                facts.append(Relation(a.cid, cid, "negotiates", a.origin, (parsed or {}).get("name") or name or ""))
            else:
                facts.append(finding("2CBOM-C04-DANGLING-RELATION", "warning", a.cid, f"cipher suite algorithm ref {ref!r} not found in {a.origin}", "closure.protocol-suites"))
        if not parsed and not alg_cids:
            facts.append(finding("2CBOM-C08-SUITE-UNRESOLVED", "warning", a.cid, f"cipher suite {name or idents} could not be decomposed", "closure.protocol-suites"))
        facts.append(Suite(a.cid, (parsed or {}).get("name") or (name or ""), idents[0] if idents else "",
                           J(sorted(set(alg_cids))), a.origin, kex_known))
    return facts


@rule("closure.protocol-crypto-refs", 700, "closure", "Link a protocol to the assets listed in cryptoRefArray.")
def r_protocol_refs(wm):
    for a in wm.get(Attr):
        if a.name == "cryptoRefs" and wm.exists(Asset, cid=a.cid, asset_type="protocol"):
            yield (a,)


@r_protocol_refs.then
def _(wm, a):
    facts = []
    for ref in U(a.value_json):
        cid = _ref_to_cid(wm, a.origin, ref)
        if cid:
            facts.append(Relation(a.cid, cid, "uses", a.origin))
    return facts


# ---- hybrids and suite-shaped algorithms ------------------------------------ #
@rule("closure.constituents", 700, "closure",
      "Materialise the constituents of a hybrid combiner or cipher-suite-shaped algorithm asset.")
def r_constituents(wm):
    for a in wm.get(Attr):
        if a.name == "components" and a.origin == "derived":
            yield (a,)


@r_constituents.then
def _(wm, a):
    facts = []
    sid = _source_for(wm, a.cid)
    for canon in U(a.value_json):
        cid, extra = synth_algorithm(wm, canon, None, sid, a.cid, "closure.constituents")
        facts.extend(extra)
        facts.append(Relation(a.cid, cid, "component-of", sid))
    return facts


# ---- generic refinement by key size ----------------------------------------- #
@rule("closure.refine-generic-by-material", 690, "closure",
      "When key material of size n instantiates a generic family (e.g. 'rsa'), also assert the sized asset.")
def r_refine(wm):
    for rel in wm.get(Relation):
        if rel.kind != "instantiates":
            continue
        desc = descriptor_of(wm, rel.dst)
        if desc is None or desc.parameter_set is not None:
            continue
        spec = KB.family(desc.family) or {}
        if "parameterSet" not in spec.get("slots", []):
            continue
        for s in wm.find(Attr, cid=rel.src, name="size"):
            yield (rel, s)


@r_refine.then
def _(wm, rel, s):
    desc = descriptor_of(wm, rel.dst)
    size = U(s.value_json)
    pr = parse_algorithm(desc.family, {"parameterSetIdentifier": str(size)}, KB)
    if not pr.ok or pr.descriptor.cid() == rel.dst:
        return []
    cid, facts = synth_algorithm(wm, pr.descriptor.canonical(), None, s.origin, rel.src, "closure.refine-generic-by-material")
    facts.append(Relation(rel.src, cid, "instantiates", s.origin))
    facts.append(finding("2CBOM-I02-REFINED", "info", rel.src,
                         f"key size {size} refines {rel.dst} to {cid}", "closure.refine-generic-by-material"))
    return facts
