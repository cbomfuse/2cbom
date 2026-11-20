"""Phase 1 -- normalisation: propose a canonical identity for every raw asset/component.

Each rule reads the raw facts of one source, applies the canonical naming
grammar (algorithms), the identity functions (certificates, key material,
protocols, components) and asserts a :class:`Candidate` fact.
"""
from __future__ import annotations

from ..canonical import (certificate_id, component_id, material_id, normalize_dn, normalize_protocol_version,
                         parse_algorithm, protocol_id, short_hash)
from ..engine.facts import Candidate, RawAsset, RawComponent, RawEvidence, J, U
from ..engine.rules import rule
from .common import KB, unresolved_cid


@rule("normalize.algorithm", 900, "normalize",
      "Apply the canonical naming grammar to a raw algorithm asset (name + structured hints).")
def r_norm_algorithm(wm):
    for ra in wm.get(RawAsset):
        if ra.asset_type == "algorithm":
            yield (ra,)


@r_norm_algorithm.then
def _(wm, ra):
    fields = U(ra.fields_json)
    hints = {k: fields.get(k) for k in ("primitive", "parameterSetIdentifier", "curve", "mode", "padding")}
    if ra.oid:
        hints["oid"] = ra.oid
    name = ra.name or fields.get("variant") or ""
    pr = parse_algorithm(name, hints, KB)
    if not pr.ok and fields.get("variant") and fields["variant"] != name:
        pr = parse_algorithm(str(fields["variant"]), hints, KB)
        name = str(fields["variant"])
    if pr.ok:
        desc = pr.descriptor
        notes = list(pr.notes)
        if pr.pre_standard:
            notes.append(f"pre-standard:{pr.pre_standard}")
        return [Candidate(ra.sid, ra.ref, desc.cid(), "algorithm", J(desc.to_dict()), pr.confidence, J(notes), "grammar")]
    return [Candidate(ra.sid, ra.ref, unresolved_cid(name or ra.ref), "algorithm", J({"unresolved": True, "name": name}),
                      0.0, J(pr.notes + pr.residue), "unresolved")]


@rule("normalize.certificate", 900, "normalize",
      "Identify a certificate by fingerprint, else by (subject, issuer, serial, validity), else by location.")
def r_norm_certificate(wm):
    for ra in wm.get(RawAsset):
        if ra.asset_type == "certificate":
            yield (ra,)


@r_norm_certificate.then
def _(wm, ra):
    f = U(ra.fields_json)
    loc = None
    ev = wm.find(RawEvidence, sid=ra.sid, ref=ra.ref)
    if ev:
        loc = ev[0].location or None
    cid, basis = certificate_id(f.get("fingerprint"), f.get("subjectName"), f.get("issuerName"), f.get("serialNumber"),
                                f.get("notValidBefore"), f.get("notValidAfter"), loc)
    conf = {"fingerprint": 1.0, "distinguished-name": 0.9, "location": 0.6, "unresolved": 0.0}[basis]
    dn_key = None
    if f.get("subjectName") or f.get("issuerName") or f.get("serialNumber"):
        _, dn_key = certificate_id(None, f.get("subjectName"), f.get("issuerName"), f.get("serialNumber"),
                                   f.get("notValidBefore"), f.get("notValidAfter"), None)
        dn_key = _.split(":")[-1]
    return [Candidate(ra.sid, ra.ref, cid, "certificate", J({"basis": basis, "dnKey": dn_key}), conf, J([]), basis)]


@rule("normalize.material", 900, "normalize",
      "Identify key material by fingerprint, identifier or (algorithm, location, size).")
def r_norm_material(wm):
    for ra in wm.get(RawAsset):
        if ra.asset_type == "related-crypto-material":
            yield (ra,)


@r_norm_material.then
def _(wm, ra):
    f = U(ra.fields_json)
    mtype = f.get("type") or "unknown"
    loc = None
    ev = wm.find(RawEvidence, sid=ra.sid, ref=ra.ref)
    if ev:
        loc = ev[0].location or None
    alg_cid = None
    alg_name = f.get("algorithm")
    if alg_name:
        hints = {"parameterSetIdentifier": f.get("size")} if f.get("size") else None
        pr = parse_algorithm(str(alg_name), hints, KB)
        if pr.ok:
            alg_cid = pr.descriptor.cid()
    cid, basis = material_id(mtype, f.get("fingerprint"), alg_cid, f.get("id"), loc, f.get("size"), f"{ra.sid}:{ra.ref}")
    conf = {"fingerprint": 1.0, "identifier": 0.9, "location": 0.7, "source-local": 0.3}[basis]
    return [Candidate(ra.sid, ra.ref, cid, "related-crypto-material", J({"basis": basis, "algorithm": alg_cid}), conf, J([]), basis)]


@rule("normalize.protocol", 900, "normalize", "Identify a protocol by (type, normalised version).")
def r_norm_protocol(wm):
    for ra in wm.get(RawAsset):
        if ra.asset_type == "protocol":
            yield (ra,)


@r_norm_protocol.then
def _(wm, ra):
    f = U(ra.fields_json)
    ptype = (f.get("type") or "").lower()
    version = f.get("version")
    low = (ra.name or "").lower()
    if not ptype:
        for t in ("tls", "ssh", "ipsec", "ike", "sstp", "wpa"):
            if t in low or t in (version or "").lower():
                ptype = t
                break
        if not ptype and "ssl" in low:
            ptype = "tls"
    if ptype == "ssl":
        ptype = "tls"
    if version is None and low:
        version = ra.name
    v = normalize_protocol_version(ptype or "unknown", version)
    cid = protocol_id(ptype or "unknown", v)
    notes = [] if ptype else ["protocol-type-unknown"]
    return [Candidate(ra.sid, ra.ref, cid, "protocol", J({"type": ptype or "unknown", "version": v}), 1.0 if ptype else 0.5, J(notes), "type-version")]


@rule("normalize.component", 900, "normalize", "Identify a software component by purl, else cpe, else (group, name, version).")
def r_norm_component(wm):
    for rc in wm.get(RawComponent):
        yield (rc,)


@r_norm_component.then
def _(wm, rc):
    cid, basis = component_id(rc.purl or None, rc.cpe or None, rc.group or None, rc.name or None, rc.version or None)
    conf = {"purl": 1.0, "cpe": 0.9, "name-version": 0.7}[basis]
    return [Candidate(rc.sid, rc.ref, cid, "component", J({"basis": basis}), conf, J([]), basis)]
