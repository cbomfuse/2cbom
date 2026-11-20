"""Ingestion: detect the source format and lift it into the IR."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..canonical import sha256_hex
from . import cyclonedx, ibmcbom
from .base import IngestResult, SourceInfo


@dataclass
class FormatInfo:
    family: str          # cyclonedx-json | ibm-cbom-json | cyclonedx-prestandard-json | unknown
    spec_version: str
    confidence: float
    notes: list


def _has_crypto(doc: dict) -> bool:
    def walk(components):
        for c in components or []:
            if not isinstance(c, dict):
                continue
            if c.get("cryptoProperties") or str(c.get("type", "")).lower() in ("cryptographic-asset", "crypto-asset"):
                return True
            if walk(c.get("components")):
                return True
        return False
    return walk(doc.get("components"))


def detect_format(doc: dict) -> FormatInfo:
    """Rule-based format detection (the first layer of the knowledge base)."""
    bom_format = str(doc.get("bomFormat") or "").strip()
    spec = str(doc.get("specVersion") or "").strip()
    notes = []
    if bom_format.upper() == "CBOM" or spec.lower().startswith("1.4-cbom"):
        return FormatInfo("ibm-cbom-json", spec or "1.4-cbom-1.0", 1.0, ["bomFormat=CBOM / 1.4-cbom specVersion"])
    if bom_format == "CycloneDX":
        if spec in cyclonedx.SUPPORTED_VERSIONS:
            return FormatInfo("cyclonedx-json", spec, 1.0, [])
        if spec in ("1.4", "1.3"):
            # CycloneDX 1.4 with crypto-asset components is the IBM extension without the CBOM marker
            if _has_crypto(doc):
                return FormatInfo("ibm-cbom-json", spec, 0.8, ["CycloneDX 1.4 carrying crypto-asset components"])
            return FormatInfo("cyclonedx-prestandard-json", spec, 0.7, ["CycloneDX 1.4 SBOM (no crypto assets)"])
        notes.append(f"unknown CycloneDX specVersion {spec!r}; reading with the 1.6 adapter")
        return FormatInfo("cyclonedx-json", spec or "1.6", 0.5, notes)
    if _has_crypto(doc):
        if any(str(c.get("type", "")).lower() == "crypto-asset" for c in doc.get("components", []) if isinstance(c, dict)):
            return FormatInfo("ibm-cbom-json", spec or "1.4-cbom-1.0", 0.6, ["no bomFormat; crypto-asset component type"])
        return FormatInfo("cyclonedx-json", spec or "1.6", 0.6, ["no bomFormat; cryptographic-asset components found"])
    return FormatInfo("unknown", spec, 0.0, ["no CycloneDX/CBOM markers found"])


def load_json(path: str) -> tuple[dict, str]:
    data = Path(path).read_bytes()
    return json.loads(data.decode("utf-8")), "sha256:" + sha256_hex(data)


def ingest_document(doc: dict, path: str = "<memory>", digest: Optional[str] = None,
                    tool_override: Optional[str] = None) -> IngestResult:
    info = detect_format(doc)
    if info.family == "unknown":
        raise ValueError(f"{path}: not a CycloneDX or IBM CBOM document")
    if digest is None:
        from ..canonical import digest as _d
        digest = _d(doc)
    source = SourceInfo(path=path, digest=digest, fmt=info.family, spec_version=info.spec_version, notes=list(info.notes))
    if info.family == "ibm-cbom-json":
        result = ibmcbom.ingest(doc, source)
    else:
        result = cyclonedx.ingest(doc, source)
    if tool_override:
        result.source.tool = tool_override
    return result


def ingest_file(path: str, tool_override: Optional[str] = None) -> IngestResult:
    doc, digest = load_json(path)
    return ingest_document(doc, path=path, digest=digest, tool_override=tool_override)


__all__ = ["FormatInfo", "IngestResult", "SourceInfo", "detect_format", "ingest_document", "ingest_file", "load_json"]
