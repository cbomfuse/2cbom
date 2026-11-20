"""Phase 7 -- conformance checking (Section 7 of the specification).

Each rule evaluates one constraint and emits a :class:`Finding`.  Severity
depends on the active profile: the *strict* (PQC-compliance) profile turns
every incompleteness that blocks a sound quantum assessment into an error.
A document is conformant to a profile when it has no error findings.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..engine.facts import Alias, Assessment, Asset, Conflict, Evidence, Relation, Resolved, Suite, U
from ..engine.rules import rule
from ..model import (CERTIFICATION_LEVELS, CRYPTO_FUNCTIONS, CURVES, EXECUTION_ENVIRONMENTS, MATERIAL_STATES,
                     MATERIAL_TYPES, MODES, PADDINGS, PRIMITIVES, PROTOCOL_TYPES)
from .common import KB, descriptor_of, finding, resolved, severity

_VOCAB = {
    "primitive": PRIMITIVES, "mode": MODES, "padding": PADDINGS, "curve": CURVES,
    "executionEnvironment": EXECUTION_ENVIRONMENTS, "cryptoFunctions": CRYPTO_FUNCTIONS,
    "certificationLevel": CERTIFICATION_LEVELS, "type": None, "state": MATERIAL_STATES,
}


def _parse_date(s):
    if not s:
        return None
    try:
        t = str(s).strip().replace("Z", "+00:00")
        d = datetime.fromisoformat(t)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d
    except ValueError:
        return None


@rule("check.C01-identity", 300, "check", "C1: every algorithm asset must have a resolved canonical identity.")
def r_c01(wm):
    for a in wm.get(Asset):
        if a.asset_type == "algorithm" and resolved(wm, a.cid, "unresolved"):
            yield (a,)


@r_c01.then
def _(wm, a):
    aliases = sorted({x.name for x in wm.find(Alias, cid=a.cid)})
    return [finding("2CBOM-C01-IDENTITY-UNRESOLVED", severity(wm, "error", "warning"), a.cid,
                    f"algorithm name(s) {aliases} could not be canonicalised", "check.C01-identity")]


@rule("check.C02-evidence", 300, "check", "C2: every asset must carry at least one evidence record.")
def r_c02(wm):
    for a in wm.get(Asset):
        if not wm.exists(Evidence, cid=a.cid):
            yield (a,)


@r_c02.then
def _(wm, a):
    return [finding("2CBOM-C02-EVIDENCE-MISSING", "error", a.cid, "asset has no evidence of occurrence", "check.C02-evidence")]


@rule("check.C02b-unlocated", 300, "check", "C2b: evidence should locate the asset (file/line, binary offset, network endpoint).")
def r_c02b(wm):
    for a in wm.get(Asset):
        evs = wm.find(Evidence, cid=a.cid)
        if evs and all(not e.location for e in evs):
            yield (a,)


@r_c02b.then
def _(wm, a):
    methods = sorted({e.method for e in wm.find(Evidence, cid=a.cid)})
    return [finding("2CBOM-C02-EVIDENCE-UNLOCATED", severity(wm, "warning", "info"), a.cid,
                    f"asset is only {', '.join(methods)}; no occurrence location recorded", "check.C02b-unlocated")]


@rule("check.C03-assessment", 290, "check", "C3: the quantum class of every asset must be determined.")
def r_c03(wm):
    for s in wm.get(Assessment):
        if s.quantum_class == "unknown":
            yield (s,)


@r_c03.then
def _(wm, s):
    return [finding("2CBOM-C03-ASSESSMENT-UNKNOWN", severity(wm, "error", "warning"), s.cid,
                    "quantum security class could not be determined: " + "; ".join(U(s.rationale_json)), "check.C03-assessment")]


@rule("check.C05-certificate-signature", 300, "check", "C5: a certificate must be linked to its signature algorithm.")
def r_c05(wm):
    for a in wm.get(Asset):
        if a.asset_type == "certificate" and not any(r.kind == "signed-by" for r in wm.find(Relation, src=a.cid)):
            yield (a,)


@r_c05.then
def _(wm, a):
    return [finding("2CBOM-C05-CERT-SIGNATURE-UNLINKED", severity(wm, "error", "warning"), a.cid,
                    "certificate has no signature algorithm", "check.C05-certificate-signature")]


@rule("check.C06-certificate-key", 300, "check", "C6: a certificate must be linked to its subject public-key algorithm.")
def r_c06(wm):
    for a in wm.get(Asset):
        if a.asset_type == "certificate" and not any(r.kind == "subject-key-algorithm" for r in wm.find(Relation, src=a.cid)):
            yield (a,)


@r_c06.then
def _(wm, a):
    return [finding("2CBOM-C06-CERT-KEY-UNLINKED", "warning", a.cid, "certificate has no subject public-key algorithm", "check.C06-certificate-key")]


@rule("check.C07-protocol-suites", 300, "check", "C7: a protocol must record its cipher suites or algorithm references.")
def r_c07(wm):
    for a in wm.get(Asset):
        if a.asset_type != "protocol":
            continue
        if not wm.find(Suite, cid=a.cid) and not any(r.kind in ("uses", "negotiates") for r in wm.find(Relation, src=a.cid)):
            yield (a,)


@r_c07.then
def _(wm, a):
    return [finding("2CBOM-C07-PROTOCOL-SUITES-MISSING", "warning", a.cid, "protocol has no cipher suites or algorithm references", "check.C07-protocol-suites")]


@rule("check.C09-key-algorithm", 300, "check", "C9: key material must be linked to the algorithm it instantiates.")
def r_c09(wm):
    for a in wm.get(Asset):
        if a.asset_type == "related-crypto-material" and not any(r.kind == "instantiates" for r in wm.find(Relation, src=a.cid)):
            yield (a,)


@r_c09.then
def _(wm, a):
    mtype = resolved(wm, a.cid, "type", "unknown")
    if mtype in ("private-key", "public-key"):
        sev = severity(wm, "error", "warning")
    elif mtype in ("secret-key", "key", "shared-secret"):
        sev = "warning"
    else:
        return []
    return [finding("2CBOM-C09-KEY-ALGORITHM-UNLINKED", sev, a.cid, f"{mtype} is not linked to an algorithm", "check.C09-key-algorithm")]


@rule("check.C10-parameter-set", 300, "check", "C10: parameterised families must state their parameter set or curve.")
def r_c10(wm):
    for a in wm.get(Asset):
        if a.asset_type != "algorithm":
            continue
        desc = descriptor_of(wm, a.cid)
        if desc is None or desc.is_hybrid():
            continue
        spec = KB.family(desc.family)
        if not spec:
            continue
        req = spec.get("requires", [])
        unless = spec.get("requiresUnless", [])
        if any(getattr(desc, {"parameterSet": "parameter_set", "curve": "curve", "hash": "hash"}[u]) for u in unless):
            continue
        missing = [r for r in req if getattr(desc, {"parameterSet": "parameter_set", "curve": "curve", "hash": "hash"}[r]) is None]
        if missing:
            yield (a, tuple(missing))


@r_c10.then
def _(wm, a, missing):
    located = any(e.location for e in wm.find(Evidence, cid=a.cid))
    sev = severity(wm, "error", "warning") if located else "warning"
    return [finding("2CBOM-C10-PARAMETER-SET-MISSING", sev, a.cid,
                    f"missing {', '.join(missing)} for family {descriptor_of(wm, a.cid).family!r}; security level cannot be derived",
                    "check.C10-parameter-set")]


@rule("check.C11-vocabulary", 300, "check", "C11: enumerated attributes must use the closed vocabularies.")
def r_c11(wm):
    for r in wm.get(Resolved):
        if r.name not in _VOCAB:
            continue
        asset = wm.one(Asset, cid=r.cid)
        if asset is None:
            continue
        vocab = _VOCAB[r.name]
        if r.name == "type":
            vocab = MATERIAL_TYPES if asset.asset_type == "related-crypto-material" else (PROTOCOL_TYPES if asset.asset_type == "protocol" else None)
        if vocab is None:
            continue
        values = U(r.value_json)
        values = values if isinstance(values, list) else [values]
        bad = [v for v in values if v not in vocab]
        if bad:
            yield (r, tuple(bad))


@r_c11.then
def _(wm, r, bad):
    return [finding("2CBOM-C11-VOCABULARY-VIOLATION", "error", r.cid, f"{r.name} value(s) {list(bad)} not in the closed vocabulary", "check.C11-vocabulary")]


@rule("check.C12-certificate-validity", 300, "check", "C12: certificate validity dates must be ISO 8601 and ordered.")
def r_c12(wm):
    for a in wm.get(Asset):
        if a.asset_type == "certificate":
            nb, na = resolved(wm, a.cid, "notValidBefore"), resolved(wm, a.cid, "notValidAfter")
            if nb or na:
                yield (a, nb, na)


@r_c12.then
def _(wm, a, nb, na):
    d1, d2 = _parse_date(nb), _parse_date(na)
    if (nb and d1 is None) or (na and d2 is None):
        return [finding("2CBOM-C12-CERT-VALIDITY-INVALID", "error", a.cid, f"unparsable validity dates {nb!r} / {na!r}", "check.C12-certificate-validity")]
    if d1 and d2 and d1 > d2:
        return [finding("2CBOM-C12-CERT-VALIDITY-INVALID", "error", a.cid, "notValidBefore is after notValidAfter", "check.C12-certificate-validity")]
    return []


@rule("check.C13-C14-conflicts", 300, "check", "C13/C14: report knowledge-base overrides and tool disagreements.")
def r_c13(wm):
    for c in wm.get(Conflict):
        yield (c,)


@r_c13.then
def _(wm, c):
    cands = U(c.candidates_json)
    chosen = U(c.chosen_json)
    desc = "; ".join(f"{x['origin']}={x['value']!r}" for x in cands if x["origin"] not in ("kb", "derived") and x["value"] != chosen) or "(none)"
    if c.rule == "settle.kb-authoritative":
        return [finding("2CBOM-C13-LEVEL-INCONSISTENT" if c.name in ("classicalSecurityLevel", "nistQuantumSecurityLevel") else "2CBOM-C14-SOURCE-CONFLICT",
                        "warning", c.cid, f"{c.name}: catalogue value {U(c.chosen_json)!r} overrides {desc}", "check.C13-C14-conflicts")]
    return [finding("2CBOM-C14-SOURCE-CONFLICT", "info", c.cid, f"{c.name}: sources disagree ({desc}); chose {U(c.chosen_json)!r} by precedence", "check.C13-C14-conflicts")]


@rule("check.C15-weak-identity", 300, "check", "C15: certificates and key material should be identified by fingerprint or stable identifier.")
def r_c15(wm):
    for a in wm.get(Asset):
        if a.asset_type in ("certificate", "related-crypto-material"):
            basis = resolved(wm, a.cid, "identityBasis")
            if basis in ("location", "source-local", "unresolved"):
                yield (a, basis)


@r_c15.then
def _(wm, a, basis):
    return [finding("2CBOM-C15-WEAK-IDENTITY", "warning", a.cid, f"identity derived from {basis}; occurrences from other sources may not merge", "check.C15-weak-identity")]


@rule("check.C16-prestandard", 300, "check", "C16: record pre-standard algorithm names that were mapped to standardised ones.")
def r_c16(wm):
    for r in wm.get(Resolved):
        if r.name == "preStandardNames" and U(r.value_json):
            yield (r,)


@r_c16.then
def _(wm, r):
    return [finding("2CBOM-C16-PRESTANDARD-NAME", "info", r.cid, f"pre-standard names {U(r.value_json)} mapped to {r.cid}", "check.C16-prestandard")]


@rule("check.C19-protocol-kex", 300, "check", "C19: TLS 1.3 protocols should record the negotiated key-exchange groups.")
def r_c19(wm):
    for s in wm.get(Suite):
        if not s.kex_known:
            has_kex = False
            for r in wm.find(Relation, src=s.cid):
                d = descriptor_of(wm, r.dst) if r.kind == "uses" else None
                if d and d.primitive in ("kem", "key-agree", "combiner"):
                    has_kex = True
            if not has_kex:
                yield (s.cid,)


@r_c19.then
def _(wm, cid):
    return [finding("2CBOM-C19-PROTOCOL-KEX-UNKNOWN", "warning", cid, "TLS 1.3 suites recorded without key-exchange groups (cryptoRefArray)", "check.C19-protocol-kex")]


@rule("check.C20-hint-mismatch", 300, "check", "C20: structured fields must agree with the algorithm name.")
def r_c20(wm):
    for r in wm.get(Resolved):
        if r.name == "parseNotes":
            bad = [n for n in U(r.value_json) if str(n).startswith("hint-conflict")]
            if bad:
                yield (r, tuple(bad))


@r_c20.then
def _(wm, r, bad):
    return [finding("2CBOM-C20-HINT-MISMATCH", "warning", r.cid, f"name/field disagreement: {list(bad)}", "check.C20-hint-mismatch")]


@rule("check.P01-P02-readiness", 280, "check", "P1/P2: surface assets that require migration.")
def r_p01(wm):
    for s in wm.get(Assessment):
        if s.quantum_class in ("classically-weak", "quantum-vulnerable"):
            yield (s,)


@r_p01.then
def _(wm, s):
    if s.quantum_class == "classically-weak":
        return [finding("2CBOM-P01-CLASSICALLY-WEAK", "warning", s.cid, "classically weak: replace now (" + "; ".join(U(s.rationale_json)[:2]) + ")", "check.P01-P02-readiness")]
    return [finding("2CBOM-P02-QUANTUM-VULNERABLE", "info", s.cid, f"quantum-vulnerable; NIST IR 8547: {s.ir8547}; migration priority {s.priority}", "check.P01-P02-readiness")]
