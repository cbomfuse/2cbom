"""Phase 4 -- enrichment from the knowledge base.

For every canonical algorithm the catalogue is authoritative for the intrinsic
properties that compliance decisions rest on: classical security strength,
NIST PQC security category, OID, governing standards, FIPS approval and the
family-level quantum class.  Tool-reported values for the same attributes are
kept as candidates and surface as conflicts (finding C13) when they disagree.
"""
from __future__ import annotations

from ..engine.facts import Asset, Attr, J, U
from ..engine.rules import rule
from .common import KB, KB_STRENGTH, KB_TRUST, descriptor_of


@rule("enrich.catalogue", 600, "enrich",
      "Assert catalogue knowledge (security levels, OID, standards, FIPS status, quantum class) for an algorithm.")
def r_catalogue(wm):
    for asset in wm.get(Asset):
        if asset.asset_type == "algorithm" and wm.exists(Attr, cid=asset.cid, name="descriptor"):
            yield (asset,)


@r_catalogue.then
def _(wm, asset):
    desc = descriptor_of(wm, asset.cid)
    cid = asset.cid
    facts = []

    def kb(name, value):
        if value is not None:
            facts.append(Attr(cid, name, J(value), "kb", KB_STRENGTH, KB_TRUST, 1.0))

    if desc.is_hybrid():
        kb("quantumClassKb", "unknown")   # decided by the assessment of the constituents
        kb("standards", ["draft-ietf-tls-ecdhe-mlkem"] if "ml-kem" in desc.family else [])
        kb("hybrid", True)
        return facts
    if desc.family == "suite":
        kb("quantumClassKb", "unknown")
        return facts

    spec = KB.family(desc.family)
    if spec is None:
        kb("quantumClassKb", "unknown")
        kb("catalogueMiss", True)
        return facts

    classical, nist = KB.level(desc.family, desc.parameter_set, desc.curve, desc.hash)
    if desc.curve and desc.curve not in KB.curves:
        classical, nist = None, None
    kb("classicalSecurityLevel", classical)
    kb("nistQuantumSecurityLevel", nist)
    kb("oid", KB.oid(desc.family, desc.parameter_set, desc.curve, desc.mode, desc.padding, desc.hash))
    kb("standards", list(spec.get("standards") or []))
    fips = spec.get("fipsApproved")
    if fips is True and desc.curve:
        fips = bool(KB.curves.get(desc.curve, {}).get("fipsApproved", False))
    if fips is True and desc.hash and desc.hash.split("-")[0] in ("sha1", "md5", "md4", "md2"):
        fips = False
    kb("fipsApproved", fips)
    kb("quantumClassKb", spec.get("quantumClass", "unknown"))
    kb("cnsa2", KB.cnsa2(desc.family, desc.parameter_set or spec.get("defaultParameterSet")))
    if spec.get("stateful"):
        kb("stateful", True)
    if spec.get("note"):
        kb("catalogueNote", spec["note"])
    if desc.parameter_set is None and spec.get("defaultParameterSet") and "parameterSet" not in spec.get("slots", []):
        kb("effectiveParameterSet", spec["defaultParameterSet"])
    return facts


@rule("enrich.hybrid-levels", 590, "enrich",
      "A hybrid combiner inherits the minimum security level of its constituents.")
def r_hybrid_levels(wm):
    for a in wm.get(Attr):
        if a.name == "hybrid" and a.origin == "kb":
            comps = wm.find(Attr, cid=a.cid, name="components")
            if not comps:
                continue
            cids = []
            for c in U(comps[0].value_json):
                cids.append(f"2cbom:alg:{c}")
            levels = [wm.find(Attr, cid=c, name="classicalSecurityLevel", origin="kb") for c in cids]
            if all(levels):
                yield (a, tuple(cids))


@r_hybrid_levels.then
def _(wm, a, cids):
    cl = [U(wm.find(Attr, cid=c, name="classicalSecurityLevel", origin="kb")[0].value_json) for c in cids]
    nl = [U(wm.find(Attr, cid=c, name="nistQuantumSecurityLevel", origin="kb")[0].value_json) for c in cids]
    cl = [x for x in cl if x is not None]
    # the PQ constituent decides the quantum level; the classical constituent is only a hedge
    pq = [U(x[0].value_json) for c in cids for x in [wm.find(Attr, cid=c, name="nistQuantumSecurityLevel", origin="kb")]
          if x and descriptor_of(wm, c) and descriptor_of(wm, c).family in KB.pq_families]
    pq = [x for x in pq if x is not None]
    facts = []
    if cl:
        facts.append(Attr(a.cid, "classicalSecurityLevel", J(min(cl)), "kb", KB_STRENGTH, KB_TRUST, 1.0))
    if pq:
        facts.append(Attr(a.cid, "nistQuantumSecurityLevel", J(min(pq)), "kb", KB_STRENGTH, KB_TRUST, 1.0))
    elif nl:
        facts.append(Attr(a.cid, "nistQuantumSecurityLevel", J(min(x for x in nl if x is not None) if any(x is not None for x in nl) else 0), "kb", KB_STRENGTH, KB_TRUST, 1.0))
    return facts
