"""Declarative knowledge base: algorithm catalogue, lexicon, tool profiles, policies.

The knowledge base is data, not code.  Rules consult it through the
:class:`KnowledgeBase` facade so that every inference the expert system makes
can be traced to a catalogue entry (explanation facility).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Optional


def _load(name: str) -> dict:
    with resources.files(__package__).joinpath(name).open("r", encoding="utf-8") as fh:
        return json.load(fh)


@dataclass(frozen=True)
class ToolProfile:
    name: str
    trust: int
    detection_method: str
    strengths: tuple


class KnowledgeBase:
    """Facade over the JSON knowledge files."""

    def __init__(self, catalogue: dict, aliases: dict, tools: dict, policies: dict):
        self.catalogue = catalogue
        self.aliases = aliases
        self.tools = tools
        self.policies = policies
        self.version = catalogue.get("version", "unknown")
        self.families: dict = catalogue["families"]
        self.curves: dict = catalogue["curves"]
        self.ae_modes = set(catalogue.get("aeModes", []))
        self.hybrid_families = set(catalogue.get("hybridFamilies", []))
        self.pq_families = set(catalogue.get("pqFamilies", []))
        self.cipher_suite_ids = {k.lower(): v for k, v in catalogue.get("cipherSuiteIds", {}).items()}
        self.tls_groups = catalogue.get("tlsGroups", {})
        # reverse OID index: oid -> (family, suffix)
        self.oid_index: dict[str, tuple[str, str]] = {}
        for fam, spec in self.families.items():
            for suffix, oid in (spec.get("oids") or {}).items():
                self.oid_index[oid] = (fam, suffix)
        for curve, spec in self.curves.items():
            if spec.get("oid"):
                self.oid_index[spec["oid"]] = ("ec", "-" + curve)
        # lexicon
        atoms = aliases["atoms"]
        self.full_names: dict = aliases["fullNames"]
        self.atom_kinds: dict[str, tuple] = {}
        for kind in ("family", "mode", "padding", "curve", "suffix"):
            for atom, value in atoms[kind].items():
                self.atom_kinds[atom] = (kind, value)
        for atom, (hfam, size) in atoms["hash"].items():
            self.atom_kinds[atom] = ("hash", (hfam, size))
        for atom in atoms["stop"]:
            self.atom_kinds[atom] = ("stop", None)
        self.max_atom_len = max(len(a) for a in self.atom_kinds)
        # tools
        self._tool_alias: dict[str, str] = {}
        for tname, spec in tools["tools"].items():
            for alias in spec.get("aliases", []) + [tname]:
                self._tool_alias[alias.lower()] = tname

    # ---- catalogue --------------------------------------------------------
    def family(self, name: str) -> Optional[dict]:
        return self.families.get(name)

    def family_names(self):
        return list(self.families)

    def level(self, family: str, parameter_set: Optional[str], curve: Optional[str], hash_: Optional[str]):
        """Return (classical, nist) for a canonical descriptor, or (None, None)."""
        spec = self.families.get(family)
        if spec is None:
            return None, None
        if spec.get("levelFromHash") and hash_:
            hfam, _, hset = hash_.partition("-")
            return self.level(hfam, hset or None, None, None)
        if curve:
            cspec = self.curves.get(curve)
            if cspec:
                return cspec["classical"], cspec["nist"]
        sets = spec.get("parameterSets") or {}
        ps = parameter_set or spec.get("defaultParameterSet")
        if ps and ps in sets:
            return sets[ps]["classical"], sets[ps]["nist"]
        return None, None

    def oid(self, family: str, parameter_set, curve, mode, padding, hash_) -> Optional[str]:
        spec = self.families.get(family)
        if not spec or not spec.get("oids"):
            return None
        oids = spec["oids"]
        candidates = []
        if parameter_set and mode:
            candidates.append(f"{parameter_set}-{mode}")
        if parameter_set:
            candidates.append(parameter_set)
        if padding and hash_:
            candidates.append(f"-{padding}-{hash_}")
        if padding:
            candidates.append(f"-{padding}")
        if hash_:
            candidates.append(f"-{hash_}")
            candidates.append(hash_)
        if mode:
            candidates.append(f"-{mode}")
        candidates.append("")
        for c in candidates:
            if c in oids:
                return oids[c]
        return None

    def cnsa2(self, family: str, parameter_set: Optional[str]) -> bool:
        spec = self.families.get(family)
        if not spec:
            return False
        if spec.get("cnsa2"):
            return True
        return bool(parameter_set and parameter_set in (spec.get("cnsa2ParameterSets") or []))

    # ---- tools ------------------------------------------------------------
    def tool_profile(self, name: Optional[str]) -> ToolProfile:
        default = self.tools["default"]
        key = self._tool_alias.get((name or "").lower().strip())
        if key is None and name:
            low = name.lower()
            for alias, tname in self._tool_alias.items():
                if alias in low:
                    key = tname
                    break
        if key is None:
            return ToolProfile(name or "unknown", default["trust"], default["detectionMethod"], tuple(default["strengths"]))
        spec = self.tools["tools"][key]
        return ToolProfile(key, spec["trust"], spec["detectionMethod"], tuple(spec.get("strengths", [])))


_DEFAULT: Optional[KnowledgeBase] = None


def load_kb() -> KnowledgeBase:
    """Load (and cache) the packaged knowledge base."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = KnowledgeBase(_load("catalogue.json"), _load("aliases.json"),
                                 _load("tools.json"), _load("policies.json"))
    return _DEFAULT
