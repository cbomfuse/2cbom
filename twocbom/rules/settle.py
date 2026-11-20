"""Phase 5 -- settlement: one value per (asset, attribute).

The resolution order is a total order on candidates, so the chosen value is
a function of the candidate *set* and not of the order in which sources were
read (Theorem 1 of the specification):

    origin rank (kb > derived > tool)  >  specificity (tool strength)
    >  tool trust  >  evidence confidence  >  value (lexicographic)  >  origin id

Multi-valued attributes are merged by set union.  Every disagreement between
tool-asserted values is recorded as a :class:`Conflict`.
"""
from __future__ import annotations

from ..engine.facts import Attr, Conflict, Resolved, J, U
from ..engine.rules import rule

UNION_ATTRS = {"cryptoFunctions", "certificationLevel", "standards", "preStandardNames", "parseNotes",
               "components", "aliases", "cipherSuites", "cryptoRefs"}
DICT_ATTRS = {"properties"}
IDENTITY_ATTRS = {"descriptor", "family", "parameterSet", "curve", "mode", "padding", "hash", "primitive",
                  "unresolved", "identityBasis"}


def _origin_rank(origin: str) -> int:
    return {"kb": 3, "derived": 2}.get(origin, 1)


def _norm_value(v):
    if isinstance(v, str):
        return v.strip().lower()
    return v


def _sort_key(a: Attr):
    return (-_origin_rank(a.origin), -a.strength, -a.trust, -a.confidence, a.value_json, a.origin)


@rule("settle.resolve-attribute", 500, "settle",
      "Pick the value of an attribute from its provenance-tagged candidates by the resolution order; record conflicts.")
def r_resolve(wm):
    groups: dict = {}
    for a in wm.get(Attr):
        groups.setdefault((a.cid, a.name), []).append(a)
    for (cid, name), cands in sorted(groups.items()):
        yield (cid, name, frozenset(cands))


@r_resolve.then
def _(wm, cid, name, cands):
    cands = sorted(cands, key=_sort_key)
    facts = []
    if name in UNION_ATTRS:
        merged = set()
        for a in cands:
            v = U(a.value_json)
            for x in (v if isinstance(v, list) else [v]):
                if x not in (None, ""):
                    merged.add(x if not isinstance(x, (dict, list)) else J(x))
        facts.append(Resolved(cid, name, J(sorted(merged, key=lambda x: str(x))), False))
        return facts
    if name in DICT_ATTRS:
        merged = {}
        conflict = False
        for a in reversed(cands):          # highest precedence written last
            v = U(a.value_json)
            if isinstance(v, dict):
                for k, x in v.items():
                    if k in merged and merged[k] != x:
                        conflict = True
                    merged[k] = x
        facts.append(Resolved(cid, name, J(merged), conflict))
        return facts

    chosen = cands[0]
    tool_cands = [a for a in cands if _origin_rank(a.origin) == 1]
    distinct_tool = {}
    for a in tool_cands:
        distinct_tool.setdefault(J(_norm_value(U(a.value_json))), a)
    conflict = len(distinct_tool) > 1
    override = (_origin_rank(chosen.origin) > 1 and tool_cands and
                any(_norm_value(U(a.value_json)) != _norm_value(U(chosen.value_json)) for a in tool_cands))
    facts.append(Resolved(cid, name, chosen.value_json, bool(conflict or override)))
    if conflict or override:
        facts.append(Conflict(cid, name, chosen.value_json,
                              J([{"value": U(a.value_json), "origin": a.origin, "strength": a.strength,
                                  "trust": a.trust, "confidence": a.confidence} for a in cands]),
                              "settle.kb-authoritative" if override else "settle.tool-precedence"))
    return facts
