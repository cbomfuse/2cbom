"""Format-agnostic intermediate representation (IR) produced by every adapter.

Adapters perform *syntactic* lifting only: they rename fields to the
CycloneDX 1.6 attribute vocabulary and kebab-case pre-standard enumerations.
All *semantic* work (canonical identity, entity resolution, enrichment,
assessment) is done by the rule base so that every decision is traceable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class SourceInfo:
    path: str
    digest: str
    fmt: str
    spec_version: str
    tool: str = "unknown"
    tool_version: str = ""
    notes: list = field(default_factory=list)
    tools: list = field(default_factory=list)       # every (name, version) in metadata.tools, document order
    subject: tuple = ("", "")                         # metadata.component (name, version)


@dataclass
class IRComponent:
    ref: str
    ctype: str
    name: str
    version: Optional[str] = None
    group: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    root: bool = False


@dataclass
class IRAsset:
    ref: str
    asset_type: str
    name: str
    fields: dict = field(default_factory=dict)
    oid: Optional[str] = None


@dataclass
class IREvidence:
    ref: str
    location: Optional[str] = None
    line: Optional[int] = None
    offset: Optional[int] = None
    symbol: Optional[str] = None
    context: Optional[str] = None
    confidence: Optional[float] = None
    method: Optional[str] = None


@dataclass
class IRRelation:
    src: str
    dst: str
    kind: str


@dataclass
class IngestResult:
    source: SourceInfo
    components: list = field(default_factory=list)
    assets: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    relations: list = field(default_factory=list)
    findings: list = field(default_factory=list)   # (code, message)

    def asset_refs(self) -> set:
        return {a.ref for a in self.assets}


# --------------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------------- #
def first(d: dict, *keys, default=None):
    for k in keys:
        if isinstance(d, dict) and k in d and d[k] not in (None, "", [], {}):
            return d[k]
    return default


def as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def to_int(v) -> Optional[int]:
    try:
        if v is None or v == "":
            return None
        return int(v)
    except (TypeError, ValueError):
        return None


def to_float(v) -> Optional[float]:
    try:
        if v is None or v == "":
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def extract_tools(metadata: dict) -> list:
    """Every (name, version) listed in CycloneDX 1.4/1.5/1.6/1.7 ``metadata.tools``, in document order.

    Tool components come first, then services (CycloneDX 1.5+ object form); the legacy array form is
    read as is.  Which entry names the generator is decided later, against the tool profiles.
    """
    tools = (metadata or {}).get("tools")
    out = []
    if isinstance(tools, dict):
        for c in tools.get("components") or []:
            if not isinstance(c, dict):
                continue
            name = c.get("name") or "unknown"
            group = c.get("group")
            if group and group not in name:
                name = f"{group}/{name}"
            out.append((str(name), str(c.get("version") or "")))
        for s in tools.get("services") or []:
            if isinstance(s, dict):
                out.append((str(s.get("name") or "unknown"), str(s.get("version") or "")))
    elif isinstance(tools, list):
        for t in tools:
            if not isinstance(t, dict):
                continue
            name = t.get("name") or "unknown"
            vendor = t.get("vendor")
            if vendor and vendor.lower() not in name.lower():
                name = f"{vendor} {name}"
            out.append((str(name), str(t.get("version") or "")))
    return out


def extract_tool(metadata: dict) -> tuple[str, str]:
    """Return (tool name, version) of the first entry of ``metadata.tools``."""
    tools = extract_tools(metadata)
    return tools[0] if tools else ("unknown", "")


def extract_subject(metadata: dict) -> tuple[str, str]:
    """(name, version) of ``metadata.component``, the subject of the BOM (some tools name themselves there)."""
    comp = (metadata or {}).get("component")
    if not isinstance(comp, dict):
        return "", ""
    return str(comp.get("name") or ""), str(comp.get("version") or "")


def fingerprint_from_hashes(hashes) -> Optional[str]:
    best = None
    for h in as_list(hashes):
        if not isinstance(h, dict):
            continue
        alg = str(h.get("alg", "")).upper().replace("-", "")
        content = h.get("content")
        if not content:
            continue
        if alg == "SHA256":
            return f"sha256:{content.lower()}"
        if best is None:
            best = f"{alg.lower()}:{content.lower()}"
    return best


def props_to_dict(properties) -> dict:
    out: dict[str, Any] = {}
    for p in as_list(properties):
        if isinstance(p, dict) and p.get("name") is not None:
            out[str(p["name"])] = p.get("value")
    return out
