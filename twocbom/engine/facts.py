"""Typed, immutable facts and the working memory."""
from __future__ import annotations

import json
from dataclasses import dataclass, fields, is_dataclass
from typing import Any, Iterable, Optional


def J(obj: Any) -> str:
    """Encode a JSON value canonically so it can live inside a hashable fact."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def U(text: Optional[str]) -> Any:
    """Decode a value encoded with :func:`J`."""
    return None if text is None else json.loads(text)


class Fact:
    """Base class of all facts.  Concrete facts are frozen dataclasses (hashable, comparable)."""

    def subject_key(self) -> Optional[str]:
        for attr in ("cid", "ref", "src"):
            v = getattr(self, attr, None)
            if v is not None:
                return v
        return None

    def describe(self) -> str:
        if is_dataclass(self):
            parts = []
            for f in fields(self):
                v = getattr(self, f.name)
                s = str(v)
                if len(s) > 60:
                    s = s[:57] + "..."
                parts.append(f"{f.name}={s}")
            return f"{type(self).__name__}({', '.join(parts)})"
        return repr(self)


# ----------------------------------------------------------------------------
# Fact vocabulary of the 2CBOM expert system
# ----------------------------------------------------------------------------
@dataclass(frozen=True)
class Config(Fact):
    profile: str
    strip_prefixes: tuple = ()


@dataclass(frozen=True)
class Source(Fact):
    sid: str
    digest: str
    fmt: str
    spec_version: str
    tool: str
    tool_version: str
    trust: int
    method: str
    path: str


@dataclass(frozen=True)
class RawComponent(Fact):
    sid: str
    ref: str
    ctype: str
    name: str
    version: str
    group: str
    purl: str
    cpe: str
    root: bool = False


@dataclass(frozen=True)
class RawAsset(Fact):
    sid: str
    ref: str
    asset_type: str
    name: str
    fields_json: str      # type-specific fields, CycloneDX-1.6 attribute names
    oid: str = ""


@dataclass(frozen=True)
class RawEvidence(Fact):
    sid: str
    ref: str
    location: str
    line: int
    offset: int
    symbol: str
    context: str
    method: str
    confidence: float


@dataclass(frozen=True)
class RawRelation(Fact):
    sid: str
    src: str
    dst: str
    kind: str


@dataclass(frozen=True)
class Candidate(Fact):
    """Canonical identity proposed for a raw asset or component."""
    sid: str
    ref: str
    cid: str
    asset_type: str          # asset type, or "component"
    canonical_json: str      # AlgorithmDescriptor / identity basis
    confidence: float
    notes_json: str
    basis: str = ""


@dataclass(frozen=True)
class Subsumed(Fact):
    """A less specific raw asset is absorbed by a more specific one found at the same location."""
    sid: str
    ref: str
    cid: str          # the absorbing canonical id
    by_sid: str
    by_ref: str


@dataclass(frozen=True)
class Asset(Fact):
    cid: str
    asset_type: str


@dataclass(frozen=True)
class Component(Fact):
    cid: str
    ctype: str


@dataclass(frozen=True)
class Member(Fact):
    sid: str
    ref: str
    cid: str


@dataclass(frozen=True)
class Alias(Fact):
    cid: str
    name: str


@dataclass(frozen=True)
class Attr(Fact):
    """A candidate attribute assertion with provenance (one per source/origin)."""
    cid: str
    name: str
    value_json: str
    origin: str        # source id, "kb" or "derived"
    strength: int      # specificity bonus (tool strength or derivation rank)
    trust: int
    confidence: float


@dataclass(frozen=True)
class Resolved(Fact):
    cid: str
    name: str
    value_json: str
    conflict: bool


@dataclass(frozen=True)
class Conflict(Fact):
    cid: str
    name: str
    chosen_json: str
    candidates_json: str
    rule: str


@dataclass(frozen=True)
class Evidence(Fact):
    cid: str
    sid: str
    tool: str
    method: str
    location: str
    line: int
    offset: int
    symbol: str
    context: str
    confidence: float


@dataclass(frozen=True)
class Relation(Fact):
    src: str
    dst: str
    kind: str
    sid: str
    via: str = ""


@dataclass(frozen=True)
class Suite(Fact):
    cid: str              # protocol asset
    name: str
    identifier: str
    algorithms_json: str  # list of algorithm cids
    sid: str
    kex_known: bool


@dataclass(frozen=True)
class Assessment(Fact):
    cid: str
    quantum_class: str
    nist_level: int        # -1 when unknown
    classical_level: int   # -1 when unknown
    ir8547: str
    cnsa2: bool
    fips: str              # "true" / "false" / "unknown"
    priority: str
    rationale_json: str


@dataclass(frozen=True)
class Finding(Fact):
    code: str
    severity: str
    subject: str
    message: str
    rule: str


# ----------------------------------------------------------------------------
# Working memory
# ----------------------------------------------------------------------------
class WorkingMemory:
    """Set-semantics fact store with lazily built per-attribute indexes."""

    def __init__(self):
        self._by_type: dict[type, list] = {}
        self._all: set = set()
        self._index: dict[tuple, dict] = {}
        self._seq = 0

    def __len__(self):
        return len(self._all)

    def add(self, fact: Fact) -> bool:
        if fact in self._all:
            return False
        self._all.add(fact)
        self._by_type.setdefault(type(fact), []).append(fact)
        # invalidate indexes of this type
        for key in [k for k in self._index if k[0] is type(fact)]:
            del self._index[key]
        self._seq += 1
        return True

    def add_all(self, facts: Iterable[Fact]) -> list:
        return [f for f in facts if self.add(f)]

    def get(self, ftype: type) -> list:
        return list(self._by_type.get(ftype, ()))

    def find(self, ftype: type, **kv) -> list:
        if not kv:
            return self.get(ftype)
        first_key = next(iter(kv))
        idx = self._index.get((ftype, first_key))
        if idx is None:
            idx = {}
            for f in self._by_type.get(ftype, ()):
                idx.setdefault(getattr(f, first_key), []).append(f)
            self._index[(ftype, first_key)] = idx
        cands = idx.get(kv[first_key], ())
        if len(kv) == 1:
            return list(cands)
        return [f for f in cands if all(getattr(f, k) == v for k, v in kv.items())]

    def one(self, ftype: type, **kv) -> Optional[Fact]:
        r = self.find(ftype, **kv)
        return r[0] if r else None

    def exists(self, ftype: type, **kv) -> bool:
        return bool(self.find(ftype, **kv))

    def types(self) -> list:
        return list(self._by_type)

    def version(self) -> int:
        return self._seq
