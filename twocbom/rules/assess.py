"""Phase 6 -- post-quantum assessment.

Every asset receives exactly one :class:`Assessment`.  Composite assets
(hybrids, cipher suites, protocols, certificates, key material) are assessed
as the *worst* of what they depend on, so a single quantum-vulnerable
constituent taints the whole; an *unknown* constituent is never silently
treated as safe.
"""
from __future__ import annotations

from ..engine.facts import Assessment, Asset, Attr, Relation, Resolved, Suite, J, U
from ..engine.rules import rule
from ..model import worst_priority, worst_quantum_class
from .common import KB, descriptor_of, resolved

POL = KB.policies


def ir8547_status(qclass: str, classical) -> str:
    p = POL["nistIr8547"]
    if qclass == "quantum-safe":
        return "acceptable"
    if qclass == "classically-weak":
        return "disallowed"
    if qclass == "quantum-vulnerable":
        if classical is None:
            return "disallowed-after-2035"
        if classical < p["floorBits"]:
            return "disallowed"
        if classical == p["deprecationThresholdBits"]:
            return "deprecated-after-2030"
        return "disallowed-after-2035"
    return "unknown"


def _priority(qclass: str, primitive, functions, cnsa2) -> str:
    mp = POL["migrationPriority"]
    if qclass == "classically-weak":
        return "immediate"
    if qclass == "quantum-vulnerable":
        if primitive in mp["confidentialityPrimitives"] or set(functions or []) & set(mp["confidentialityFunctions"]):
            return "high"
        return "medium"
    if qclass == "quantum-safe":
        return "none" if cnsa2 else "low"
    return "unknown"


def _assessment_of(wm, cid):
    a = wm.find(Assessment, cid=cid)
    return a[0] if a else None


def _assessed(wm, cids) -> bool:
    return all(wm.exists(Assessment, cid=c) for c in cids)


def _component_cids(wm, cid):
    comps = resolved(wm, cid, "components", []) or []
    return [f"2cbom:alg:{c}" for c in comps]


def _none_if_neg(v):
    return None if v is None or v < 0 else v


def _agg(wm, cid, cids, kind: str, extra_rationale):
    parts = [_assessment_of(wm, c) for c in cids]
    parts = [p for p in parts if p]
    qclass = worst_quantum_class([p.quantum_class for p in parts]) if parts else "unknown"
    nist = [p.nist_level for p in parts if p.nist_level >= 0]
    classical = [p.classical_level for p in parts if p.classical_level >= 0]
    cnsa2 = bool(parts) and all(p.cnsa2 for p in parts)
    prio = worst_priority([p.priority for p in parts]) if parts else "unknown"
    if qclass == "unknown":
        prio = "unknown"
    elif kind == "certificate" and qclass == "quantum-vulnerable":
        prio = "medium"   # certificate keys authenticate; they are not exposed to harvest-now-decrypt-later
    rationale = list(extra_rationale) + [f"{kind} constituent {p.cid}: {p.quantum_class}" for p in parts]
    return Assessment(cid, qclass, min(nist) if nist else -1, min(classical) if classical else -1,
                      ir8547_status(qclass, min(classical) if classical else None), cnsa2,
                      "unknown", prio, J(rationale))


# ---- algorithms --------------------------------------------------------------- #
@rule("assess.algorithm", 400, "assess",
      "Classify an algorithm (quantum class, NIST IR 8547 status, CNSA 2.0, FIPS, migration priority).")
def r_algorithm(wm):
    for asset in wm.get(Asset):
        if asset.asset_type != "algorithm" or wm.exists(Assessment, cid=asset.cid):
            continue
        if not wm.exists(Resolved, cid=asset.cid, name="primitive"):
            continue   # settlement not finished for this asset
        desc = descriptor_of(wm, asset.cid)
        if desc is not None and (desc.is_hybrid() or desc.family == "suite"):
            if not _assessed(wm, _component_cids(wm, asset.cid)):
                continue
        yield (asset,)


@r_algorithm.then
def _(wm, asset):
    cid = asset.cid
    desc = descriptor_of(wm, cid)
    if desc is None or resolved(wm, cid, "unresolved"):
        return [Assessment(cid, "unknown", -1, -1, "unknown", False, "unknown", "unknown",
                           J(["identity could not be resolved by the canonical naming grammar"]))]
    if desc.is_hybrid():
        comps = _component_cids(wm, cid)
        parts = [_assessment_of(wm, c) for c in comps]
        pq_parts = [p for p, c in zip(parts, comps) if p and (descriptor_of(wm, c) or desc).family in KB.pq_families]
        classical_parts = [p for p in parts if p and p not in pq_parts]
        rationale = ["hybrid combiner: secure if at least one constituent is quantum-safe and none is classically weak"]
        if any(p.quantum_class == "classically-weak" for p in parts if p):
            qclass = "classically-weak"
        elif pq_parts and all(p.quantum_class == "quantum-safe" for p in pq_parts):
            qclass = "quantum-safe"
        else:
            qclass = "unknown"
        nist = [p.nist_level for p in pq_parts if p.nist_level >= 0]
        classical = resolved(wm, cid, "classicalSecurityLevel")
        cnsa2 = bool(pq_parts) and all(p.cnsa2 for p in pq_parts)
        prio = "none" if (qclass == "quantum-safe" and cnsa2) else ("low" if qclass == "quantum-safe" else ("immediate" if qclass == "classically-weak" else "unknown"))
        rationale += [f"constituent {p.cid}: {p.quantum_class}" for p in parts if p]
        return [Assessment(cid, qclass, min(nist) if nist else -1, classical if classical is not None else -1,
                           ir8547_status(qclass, classical), cnsa2, "unknown", prio, J(rationale))]
    if desc.family == "suite":
        return [_agg(wm, cid, _component_cids(wm, cid), "cipher-suite", ["cipher suite assessed as the worst of its constituents"])]

    qclass = resolved(wm, cid, "quantumClassKb", "unknown") or "unknown"
    classical = resolved(wm, cid, "classicalSecurityLevel")
    nist = resolved(wm, cid, "nistQuantumSecurityLevel")
    functions = resolved(wm, cid, "cryptoFunctions", []) or []
    cnsa2 = bool(resolved(wm, cid, "cnsa2", False))
    fips = resolved(wm, cid, "fipsApproved")
    rationale = [f"catalogue family {desc.family!r}: {qclass}"]
    if classical is not None and classical < POL["nistIr8547"]["floorBits"] and qclass != "unknown":
        rationale.append(f"classical strength {classical} bits is below the 112-bit floor")
        qclass = "classically-weak"
    if desc.hash and desc.hash.split("-")[0] in ("sha1", "md5", "md4", "md2") and qclass != "classically-weak":
        rationale.append(f"uses broken hash {desc.hash}")
        qclass = "classically-weak"
    if resolved(wm, cid, "catalogueMiss"):
        rationale.append("family not in catalogue")
    if qclass == "quantum-vulnerable":
        rationale.append("public-key algorithm broken by Shor's algorithm")
    if desc.family in KB.pq_families:
        rationale.append("NIST post-quantum family")
    note = resolved(wm, cid, "catalogueNote")
    if note:
        rationale.append(note)
    if classical is None and qclass != "unknown":
        rationale.append("security level unknown for this parameter set")
    fips_s = "true" if fips is True else ("false" if fips is False else "unknown")
    return [Assessment(cid, qclass, nist if nist is not None else -1, classical if classical is not None else -1,
                       ir8547_status(qclass, classical), cnsa2, fips_s,
                       _priority(qclass, desc.primitive, functions, cnsa2), J(rationale))]


# ---- certificates --------------------------------------------------------------- #
@rule("assess.certificate", 390, "assess", "A certificate is as weak as its signature and subject-key algorithms.")
def r_certificate(wm):
    for asset in wm.get(Asset):
        if asset.asset_type != "certificate" or wm.exists(Assessment, cid=asset.cid):
            continue
        deps = [r.dst for r in wm.find(Relation, src=asset.cid) if r.kind in ("signed-by", "subject-key-algorithm")]
        if _assessed(wm, [d for d in deps if wm.exists(Asset, cid=d, asset_type="algorithm")]):
            yield (asset,)


@r_certificate.then
def _(wm, asset):
    deps = []
    for r in wm.find(Relation, src=asset.cid):
        if r.kind in ("signed-by", "subject-key-algorithm"):
            if wm.exists(Asset, cid=r.dst, asset_type="algorithm"):
                deps.append(r.dst)
            else:
                for r2 in wm.find(Relation, src=r.dst):   # ref pointed at key material
                    if r2.kind == "instantiates":
                        deps.append(r2.dst)
    return [_agg(wm, asset.cid, sorted(set(deps)), "certificate", ["certificate assessed as the worst of signature and subject-key algorithms"])]


# ---- key material --------------------------------------------------------------- #
_SIZE_CLASSES = ((256, 5), (192, 3), (128, 1))


@rule("assess.material", 390, "assess", "Key material inherits the assessment of the algorithm it instantiates; symmetric keys by size.")
def r_material(wm):
    for asset in wm.get(Asset):
        if asset.asset_type != "related-crypto-material" or wm.exists(Assessment, cid=asset.cid):
            continue
        deps = [r.dst for r in wm.find(Relation, src=asset.cid) if r.kind == "instantiates"]
        if _assessed(wm, deps):
            yield (asset,)


@r_material.then
def _(wm, asset):
    deps = sorted({r.dst for r in wm.find(Relation, src=asset.cid) if r.kind == "instantiates"})
    if deps:
        # prefer the most specific (sized) instantiation when both generic and refined exist
        return [_agg(wm, asset.cid, deps, "key material", ["key material inherits the assessment of its algorithm"])]
    mtype = resolved(wm, asset.cid, "type", "unknown")
    size = resolved(wm, asset.cid, "size")
    if mtype in ("secret-key", "key", "shared-secret", "seed", "password", "credential", "token") and isinstance(size, int):
        if size < POL["nistIr8547"]["floorBits"]:
            return [Assessment(asset.cid, "classically-weak", 0, size, "disallowed", False, "unknown", "immediate",
                               J([f"symmetric material of {size} bits is below the 112-bit floor"]))]
        nist = next((n for bits, n in _SIZE_CLASSES if size >= bits), 1)
        return [Assessment(asset.cid, "quantum-safe", nist, size, "acceptable", size >= 256, "unknown",
                           "none" if size >= 256 else "low", J([f"symmetric material of {size} bits"]))]
    return [Assessment(asset.cid, "unknown", -1, -1, "unknown", False, "unknown", "unknown",
                       J(["no algorithm linked to this key material"]))]


# ---- protocols ------------------------------------------------------------------- #
@rule("assess.protocol", 380, "assess",
      "A protocol is assessed from its version policy and the worst of its negotiated cipher suites.")
def r_protocol(wm):
    for asset in wm.get(Asset):
        if asset.asset_type != "protocol" or wm.exists(Assessment, cid=asset.cid):
            continue
        cids = set()
        for s in wm.find(Suite, cid=asset.cid):
            cids.update(U(s.algorithms_json))
        for r in wm.find(Relation, src=asset.cid):
            if r.kind in ("uses", "negotiates") and wm.exists(Asset, cid=r.dst):
                cids.add(r.dst)
        if _assessed(wm, cids):
            yield (asset,)


@r_protocol.then
def _(wm, asset):
    cid = asset.cid
    ptype = resolved(wm, cid, "type", "unknown")
    version = resolved(wm, cid, "version")
    pspec = KB.catalogue.get("protocols", {}).get(ptype, {})
    policy = pspec.get("versions", {}).get(str(version)) if version else None
    rationale = []
    if policy == "classically-weak":
        note = pspec.get("notes", {}).get(str(version), "protocol version deprecated")
        return [Assessment(cid, "classically-weak", 0, -1, "disallowed", False, "unknown", "immediate",
                           J([f"{ptype} {version}: {note}"]))]
    suites = wm.find(Suite, cid=cid)
    suite_classes = []
    all_cids = set()
    kex_unknown = False
    for s in suites:
        cids = U(s.algorithms_json)
        all_cids.update(cids)
        parts = [_assessment_of(wm, c) for c in cids]
        parts = [p for p in parts if p]
        sc = worst_quantum_class([p.quantum_class for p in parts]) if parts else "unknown"
        if not s.kex_known:
            kex_unknown = True
        suite_classes.append(sc)
        rationale.append(f"suite {s.name or s.identifier}: {sc}")
    extra = [r.dst for r in wm.find(Relation, src=cid) if r.kind == "uses" and wm.exists(Asset, cid=r.dst)]
    kex_assets = []
    for c in extra:
        d = descriptor_of(wm, c)
        if d and d.primitive in ("kem", "key-agree", "combiner", "pke"):
            kex_assets.append(c)
        all_cids.add(c)
    if kex_unknown:
        if kex_assets:
            rationale.append("TLS 1.3 key exchange taken from the referenced groups: " + ", ".join(sorted(kex_assets)))
        else:
            rationale.append("TLS 1.3 cipher suites do not fix the key exchange; no group recorded, key exchange unknown")
            suite_classes.append("unknown")
    if not suites and not extra:
        return [Assessment(cid, "unknown", -1, -1, "unknown", False, "unknown", "unknown",
                           J([f"{ptype} {version or ''}: no cipher suites or algorithm references recorded"]))]
    agg = _agg(wm, cid, sorted(all_cids), "protocol", rationale)
    qclass = worst_quantum_class([agg.quantum_class] + suite_classes)
    prio = agg.priority if qclass != "unknown" else "unknown"
    classical = _none_if_neg(agg.classical_level)
    return [Assessment(cid, qclass, agg.nist_level, agg.classical_level, ir8547_status(qclass, classical),
                       agg.cnsa2 and qclass == "quantum-safe", "unknown", prio, agg.rationale_json)]
