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
    basis: str = "knowledge-base"      # "knowledge-base", "benchmark" or "default"


class ToolProfiles:
    """Tool trust profiles (``tools.json``) and the attribution of sources to them.

    A name resolves to a profile by exact alias match, else by the *longest* alias it contains (so
    ``cbomkit-theia 1.3`` is cbomkit-theia rather than cbomkit, and ``CBOM-Lens`` is cbom-lens rather
    than the generic ``cbom`` alias), else to the default profile.
    """

    def __init__(self, doc: dict, basis: Optional[dict] = None):
        self.doc = doc
        self.version = doc.get("version", "unknown")
        self.default = doc["default"]
        self.entries: dict = doc["tools"]
        self.basis: dict = dict(basis) if basis else {tid: "knowledge-base" for tid in self.entries}
        self._alias: dict[str, str] = {}
        for tname, spec in self.entries.items():
            for alias in list(spec.get("aliases", [])) + [tname]:
                self._alias[alias.lower().strip()] = tname

    def overlay(self, doc: dict, basis: str = "benchmark") -> "ToolProfiles":
        """A new profile set in which the tools of ``doc`` replace (or add to) the entries of this one.

        An overlaid tool takes trust, detection method and strengths from ``doc``; its aliases are the
        union of both, and on an alias claimed by two tools the overlay wins.  Tools missing from
        ``doc`` keep their entries.
        """
        tools = {k: dict(v) for k, v in self.entries.items()}
        basis_map = dict(self.basis)
        for tid, spec in doc.get("tools", {}).items():
            old = tools.get(tid, {})
            aliases = list(dict.fromkeys(list(old.get("aliases", [])) + list(spec.get("aliases", []))))
            tools[tid] = {"aliases": aliases, "trust": spec["trust"],
                          "detectionMethod": spec.get("detectionMethod") or old.get("detectionMethod") or "unknown",
                          "strengths": list(spec.get("strengths", []))}
            basis_map[tid] = basis
        merged = ToolProfiles({"version": self.version, "default": self.default, "tools": tools}, basis_map)
        # aliases claimed by an overlaid tool win over the same alias of another tool
        for tid, spec in doc.get("tools", {}).items():
            for alias in list(spec.get("aliases", [])) + [tid]:
                merged._alias[alias.lower().strip()] = tid
        return merged

    def _key(self, name: Optional[str], substring: bool = True) -> Optional[str]:
        low = (name or "").lower().strip()
        if not low:
            return None
        key = self._alias.get(low)
        if key is None and substring:
            hits = [alias for alias in self._alias if alias and alias in low]
            if hits:
                key = self._alias[min(hits, key=lambda a: (-len(a), a))]
        return key

    def known(self, name: Optional[str], substring: bool = True) -> bool:
        return self._key(name, substring) is not None

    def profile(self, name: Optional[str]) -> ToolProfile:
        key = self._key(name)
        if key is None:
            d = self.default
            return ToolProfile(name or "unknown", d["trust"], d["detectionMethod"], tuple(d["strengths"]), "default")
        spec = self.entries[key]
        return ToolProfile(key, spec["trust"], spec["detectionMethod"], tuple(spec.get("strengths", [])),
                           self.basis.get(key, "knowledge-base"))

    def attribute(self, tools: list, subject: Optional[tuple] = None) -> tuple:
        """Choose the generating tool of a source: ``(profile, reported name, reported version)``.

        ``tools`` are the ``(name, version)`` pairs a CBOM lists in ``metadata.tools`` (document
        order).  The first one that names a known tool exactly wins, else the first one that contains
        a known alias -- so a CBOM listing a helper library first (cdxgen lists ``dosai`` before
        itself) is still attributed to its generator.  When ``metadata.tools`` is empty, a
        ``metadata.component`` (``subject``) whose name is exactly a known alias is taken as the tool;
        CBOM-Lens names itself only there.
        """
        tools = [(str(n or ""), str(v or "")) for n, v in tools if n]
        for substring in (False, True):
            for name, version in tools:
                if self.known(name, substring):
                    return self.profile(name), name, version
        if not tools and subject and subject[0] and self.known(subject[0], substring=False):
            return self.profile(subject[0]), str(subject[0]), str(subject[1] or "")
        name, version = tools[0] if tools else ("unknown", "")
        return self.profile(name if name != "unknown" else None), name, version


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
        self.tool_profiles = ToolProfiles(tools)

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
        return self.tool_profiles.profile(name)


_DEFAULT: Optional[KnowledgeBase] = None


def load_kb() -> KnowledgeBase:
    """Load (and cache) the packaged knowledge base."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = KnowledgeBase(_load("catalogue.json"), _load("aliases.json"),
                                 _load("tools.json"), _load("policies.json"))
    return _DEFAULT
