"""Phase 5 -- settlement: one value per (asset, attribute).

The resolution order is a total order on candidates, so the chosen value is
a function of the candidate *set* and not of the order in which sources were
read (Theorem 1 of the specification):

    origin rank (kb > derived > tool)  >  benchmark preference  >  specificity (tool strength)
    >  tool trust  >  evidence confidence  >  value (lexicographic)  >  origin id

The benchmark preference is 0 unless an orchestrator benchmark with reliability
priors is in use (``MergeOptions.benchmark``).  Then every pair of tool candidates
with different values from two *benchmarked* tools is posed to the benchmark's
``reconcile()`` with the asset's category (language, asset type, subtype,
family); a decided answer adds 1 to the preferred candidate and takes 1 from the
other (a Copeland score), an undecided one changes nothing, so strength and trust
still break the tie -- the "reconcile, scalar fallback" rule evaluated by the
orchestrator.  The score depends only on the candidate set and the benchmark, so
the order stays total and the merge order-independent.  Candidates from the
knowledge base or derived from the canonical identity outrank every tool and are
never put to the benchmark.

Multi-valued attributes are merged by set union.  Every disagreement between
tool-asserted values is recorded as a :class:`Conflict`, together with the
benchmark answers it rested on.
"""
from __future__ import annotations

from itertools import combinations

from ..benchmark import (benchmark_attribute_name, benchmark_family, document_number, language_of_location,
                         purl_family)
from ..engine.facts import Asset, Attr, Component, Conflict, Evidence, Relation, Resolved, J, U
from ..engine.rules import rule
from .common import benchmark_of, origin_rank, scalar_key, scalar_value, tool_of

UNION_ATTRS = {"cryptoFunctions", "certificationLevel", "standards", "preStandardNames", "parseNotes",
               "components", "aliases", "cipherSuites", "cryptoRefs"}
DICT_ATTRS = {"properties"}
IDENTITY_ATTRS = {"descriptor", "family", "parameterSet", "curve", "mode", "padding", "hash", "primitive",
                  "unresolved", "identityBasis"}

RECORD_KEYS = ("toolA", "toolB", "attribute", "category", "categoryUsed", "backoffSteps", "tier", "decision",
               "preferred", "confidence", "weights", "support", "toolVersions", "explanation")


def _norm_value(v):
    if isinstance(v, str):
        return v.strip().lower()
    return v


def _norm_key(a: Attr) -> str:
    return J(_norm_value(U(a.value_json)))


def _sort_key(a: Attr, preference: int = 0):
    return (-origin_rank(a.origin), -preference, -a.strength, -a.trust, -a.confidence, a.value_json, a.origin)


# --------------------------------------------------------------------------- #
# benchmark categories
# --------------------------------------------------------------------------- #
def category_of(wm, cid: str, name: str) -> dict:
    """The benchmark category of an asset or component (language, assetType, subtype, family).

    Facets are read from the benchmark-independent resolution of the other attributes, so they do not
    depend on the answers they help to produce; a facet that the disputed attribute itself defines is
    left out, and the language is set only when all located evidence agrees on one.
    """
    facets: dict = {}
    asset = wm.one(Asset, cid=cid)
    if asset is not None:
        atype = asset.asset_type
        facets["assetType"] = atype
        if atype == "algorithm":
            prim = scalar_value(wm, cid, "primitive")
            if prim and prim != "unknown" and name != "primitive":
                facets["subtype"] = prim
            fam = benchmark_family(scalar_value(wm, cid, "family"))
            if fam and name not in ("family", "descriptor"):
                facets["family"] = fam
        elif atype == "related-crypto-material":
            mtype = scalar_value(wm, cid, "type")
            if mtype and mtype != "unknown" and name != "type":
                facets["subtype"] = mtype
            fams = {benchmark_family(scalar_value(wm, r.dst, "family"))
                    for r in wm.find(Relation, src=cid) if r.kind == "instantiates"}
            fams.discard(None)
            if len(fams) == 1 and name not in ("algorithm", "algorithmRef"):
                facets["family"] = fams.pop()
        elif atype == "protocol":
            ptype, version = scalar_value(wm, cid, "type"), scalar_value(wm, cid, "version")
            if ptype and ptype != "unknown" and name != "type":
                facets["subtype"] = ptype
                if version and name != "version":
                    facets["family"] = f"{ptype}-{version}"
        elif atype == "certificate":
            fmt = scalar_value(wm, cid, "certificateFormat")
            if isinstance(fmt, str) and fmt.strip() and name != "certificateFormat":
                facets["subtype"] = fmt.strip().lower()
        langs = {language_of_location(e.location) for e in wm.find(Evidence, cid=cid) if e.location}
        langs.discard(None)
        if len(langs) == 1:
            facets["language"] = langs.pop()
        return facets
    comp = wm.one(Component, cid=cid)
    if comp is not None:
        ctype = scalar_value(wm, cid, "ctype", comp.ctype)
        if ctype in ("library", "framework") and name != "ctype":
            facets["assetType"] = "library"
            facets["subtype"] = "library"
            fam = purl_family(scalar_value(wm, cid, "purl"))
            if fam and name not in ("purl", "name", "group"):
                facets["family"] = fam
    return facets


def benchmark_attribute(wm, cid: str, name: str) -> str:
    return benchmark_attribute_name(name, component=wm.exists(Component, cid=cid))


def reconciliation_record(r) -> dict:
    """The part of a reconciliation answer that a conflict record carries (numbers to four digits)."""
    d = r.to_dict()
    rec = {k: d[k] for k in RECORD_KEYS}
    rec["toolVersions"] = {k: v for k, v in rec["toolVersions"].items() if v}
    rec = {k: v for k, v in rec.items() if v not in (None, "", [], {})}
    return document_number(rec)


def benchmark_preferences(wm, cid: str, name: str, cands) -> tuple:
    """Copeland scores of the tool candidates from the benchmark's pairwise answers, and the answers."""
    bench = benchmark_of(wm)
    if bench is None or bench.reliability is None:
        return {}, []
    if any(origin_rank(a.origin) > 1 for a in cands):
        return {}, []          # the knowledge base or the identity decides; tools are not compared
    rel = bench.reliability
    tool_cands = sorted(cands, key=scalar_key)
    tools = {a: tool_of(wm, a.origin) for a in tool_cands}
    pairs = []
    for x, y in combinations(tool_cands, 2):
        tx, ty = tools[x], tools[y]
        if _norm_key(x) == _norm_key(y) or tx == ty or not rel.knows(tx) or not rel.knows(ty):
            continue
        pairs.append((x, y, tx, ty))
    if not pairs:
        return {}, []
    facets = category_of(wm, cid, name)
    attribute = benchmark_attribute(wm, cid, name)
    prefs = {a: 0 for a in tool_cands}
    answers = {}
    for x, y, tx, ty in pairs:
        r = rel.answer(tx, ty, facets, attribute)
        answers[(r.tool_a, r.tool_b)] = r
        if r.preferred == tx:
            prefs[x] += 1
            prefs[y] -= 1
        elif r.preferred == ty:
            prefs[y] += 1
            prefs[x] -= 1
    return prefs, [reconciliation_record(r) for _, r in sorted(answers.items())]


# --------------------------------------------------------------------------- #
# the rule
# --------------------------------------------------------------------------- #
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
    facts = []
    if name in UNION_ATTRS:
        merged = set()
        for a in sorted(cands, key=_sort_key):
            v = U(a.value_json)
            for x in (v if isinstance(v, list) else [v]):
                if x not in (None, ""):
                    merged.add(x if not isinstance(x, (dict, list)) else J(x))
        facts.append(Resolved(cid, name, J(sorted(merged, key=lambda x: str(x))), False))
        return facts
    if name in DICT_ATTRS:
        merged = {}
        conflict = False
        for a in reversed(sorted(cands, key=_sort_key)):          # highest precedence written last
            v = U(a.value_json)
            if isinstance(v, dict):
                for k, x in v.items():
                    if k in merged and merged[k] != x:
                        conflict = True
                    merged[k] = x
        facts.append(Resolved(cid, name, J(merged), conflict))
        return facts

    prefs, answers = benchmark_preferences(wm, cid, name, cands)
    cands = sorted(cands, key=lambda a: _sort_key(a, prefs.get(a, 0)))
    chosen = cands[0]
    chosen_norm = _norm_key(chosen)
    tool_cands = [a for a in cands if origin_rank(a.origin) == 1]
    distinct_tool = {}
    for a in tool_cands:
        distinct_tool.setdefault(_norm_key(a), a)
    conflict = len(distinct_tool) > 1
    override = (origin_rank(chosen.origin) > 1 and tool_cands and
                any(_norm_key(a) != chosen_norm for a in tool_cands))
    facts.append(Resolved(cid, name, chosen.value_json, bool(conflict or override)))
    if conflict or override:
        if override:
            rule_name = "settle.kb-authoritative"
        elif prefs and prefs.get(chosen, 0) > max(prefs.get(a, 0) for a in tool_cands if _norm_key(a) != chosen_norm):
            rule_name = "settle.benchmark-preference"
        else:
            rule_name = "settle.tool-precedence"
        listed = []
        for a in cands:
            c = {"value": U(a.value_json), "origin": a.origin, "strength": a.strength, "trust": a.trust,
                 "confidence": a.confidence}
            if answers and a in prefs:
                c["preference"] = prefs[a]
            listed.append(c)
        facts.append(Conflict(cid, name, chosen.value_json, J(listed), rule_name, J(answers) if answers else ""))
    return facts
