"""Canonical identity for 2CBOM (Sections 4 and 8 of the specification).

* :func:`parse_algorithm` implements the canonical naming grammar: any
  tool-specific spelling of an algorithm ("AES128-GCM", "AES/GCM/NoPadding",
  "aes-128-gcm", "SHA256withRSA", "Kyber768", "1.2.840.113549.1.1.11", ...) is
  mapped to an :class:`AlgorithmDescriptor` whose canonical string is unique.
* :func:`parse_cipher_suite` decomposes IANA TLS cipher-suite names.
* :func:`jcs_dumps` / :func:`digest` give the RFC 8785 canonical serialisation
  and the content digest used for integrity and for deterministic serial numbers.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field, replace
from typing import Iterable, Optional

from .knowledge import KnowledgeBase, load_kb
from .model import ID_PREFIX

NAMESPACE_2CBOM = uuid.uuid5(uuid.NAMESPACE_URL, "https://2cbom.org/ns/1.0")

_SEP_RE = re.compile(r"[\s_\-/\\,.+()\[\]{}:;'\"]+")
_OID_RE = re.compile(r"^\d+(\.\d+)+$")
_NUM_RE = re.compile(r"\d+")

# Slot order of the canonical string (Definition "canonical string").
SLOT_ORDER = ("family", "parameter_set", "curve", "mode", "padding", "hash")

# Modes for which a padding scheme is meaningless (AEAD and stream-like modes).
_UNPADDED_MODES = {"gcm", "ccm", "ocb", "eax", "siv", "gcm-siv", "ctr", "ofb", "cfb", "xts", "kw", "kwp"}


# --------------------------------------------------------------------------- #
# Canonical serialisation (RFC 8785 JSON Canonicalization Scheme)
# --------------------------------------------------------------------------- #
def jcs_dumps(obj) -> str:
    """RFC 8785 canonical JSON for the 2CBOM value domain (no floats except finite decimals)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj) -> str:
    """Content digest of a JSON value in canonical form."""
    return "sha256:" + sha256_hex(jcs_dumps(obj).encode("utf-8"))


def stable_uuid(seed: str) -> str:
    """Deterministic UUIDv5 in the 2CBOM namespace."""
    return str(uuid.uuid5(NAMESPACE_2CBOM, seed))


def short_hash(text: str, n: int = 16) -> str:
    return sha256_hex(text.encode("utf-8"))[:n]


# --------------------------------------------------------------------------- #
# Token normalisation
# --------------------------------------------------------------------------- #
def norm_token(s: Optional[str]) -> str:
    """Lower-case and collapse separators to single hyphens."""
    if s is None:
        return ""
    s = _SEP_RE.sub("-", str(s).strip().lower())
    return s.strip("-")


def squash(s: Optional[str]) -> str:
    """Lower-case and remove every separator (the segmentation alphabet)."""
    if s is None:
        return ""
    return _SEP_RE.sub("", str(s).strip().lower())


def kebab(s: Optional[str]) -> Optional[str]:
    """camelCase / snake_case -> kebab-case (used for pre-standard vocabularies)."""
    if s is None:
        return None
    s = str(s).strip()
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", s)
    s = s.replace("_", "-").replace(" ", "-").lower()
    s = re.sub(r"-+", "-", s)
    return s


def normalize_location(path: Optional[str], strip_prefixes: Iterable[str] = ()) -> Optional[str]:
    """Normalise a file location so that the same file reported by two tools compares equal."""
    if path is None:
        return None
    p = str(path).strip().replace("\\", "/")
    for prefix in sorted(strip_prefixes, key=len, reverse=True):
        if prefix and p.startswith(prefix):
            p = p[len(prefix):]
            break
    p = re.sub(r"^(\./)+", "", p)
    p = re.sub(r"^/+", "", p)
    p = re.sub(r"/{2,}", "/", p)
    return p


def normalize_dn(dn: Optional[str]) -> Optional[str]:
    """Normalise an X.500 distinguished name string (attribute types upper-cased, spacing collapsed)."""
    if dn is None:
        return None
    parts = [p.strip() for p in re.split(r"\s*,\s*", str(dn).strip()) if p.strip()]
    out = []
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            out.append(f"{k.strip().upper()}={v.strip()}")
        else:
            out.append(p)
    return ",".join(out)


def normalize_protocol_version(ptype: str, version: Optional[str]) -> Optional[str]:
    if version is None:
        return None
    v = str(version).strip().lower()
    v = v.replace("tlsv", "").replace("tls", "").replace("dtlsv", "").replace("dtls", "").replace("sshv", "").replace("ssh", "")
    v = v.replace("ikev", "").replace("ike", "").strip(" -_:")
    m = re.search(r"ssl\s*v?\s*(\d(?:\.\d)?)", v)
    if m:
        n = m.group(1)
        return f"ssl{n}.0" if "." not in n else f"ssl{n}"
    v = v.lstrip("v").strip()
    m = re.search(r"\d+(?:\.\d+)?", v)
    if not m:
        return None
    n = m.group(0)
    if ptype == "tls" and "." not in n:
        n = {"1": "1.0", "2": "1.2", "3": "1.3"}.get(n, n)
    return n


# --------------------------------------------------------------------------- #
# Algorithm descriptors
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class AlgorithmDescriptor:
    family: str
    parameter_set: Optional[str] = None
    curve: Optional[str] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    hash: Optional[str] = None
    primitive: Optional[str] = None       # derived primitive (may be refined by hints)
    components: tuple = ()                 # canonical strings of constituents (hybrids, cipher suites)

    def canonical(self) -> str:
        parts = [getattr(self, slot) for slot in SLOT_ORDER]
        return "-".join(p for p in parts if p)

    def cid(self) -> str:
        return f"{ID_PREFIX}alg:{self.canonical()}"

    def is_hybrid(self) -> bool:
        return "+" in self.family

    def to_dict(self) -> dict:
        d = {"family": self.family, "parameterSet": self.parameter_set, "curve": self.curve,
             "mode": self.mode, "padding": self.padding, "hash": self.hash,
             "primitive": self.primitive, "components": list(self.components)}
        return {k: v for k, v in d.items() if v not in (None, [], ())}

    @staticmethod
    def from_dict(d: dict) -> "AlgorithmDescriptor":
        return AlgorithmDescriptor(
            family=d["family"], parameter_set=d.get("parameterSet"), curve=d.get("curve"),
            mode=d.get("mode"), padding=d.get("padding"), hash=d.get("hash"),
            primitive=d.get("primitive"), components=tuple(d.get("components") or ()))


@dataclass
class ParseResult:
    descriptor: Optional[AlgorithmDescriptor]
    confidence: float
    notes: list = field(default_factory=list)
    residue: list = field(default_factory=list)
    pre_standard: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.descriptor is not None


# --------------------------------------------------------------------------- #
# Segmentation (greedy longest match over the lexicon)
# --------------------------------------------------------------------------- #
def words_of(raw: str) -> list:
    """Separator-delimited words of a raw name (lower-cased)."""
    return [w for w in _SEP_RE.split(str(raw).strip().lower()) if w]


def segment(text: str, kb: KnowledgeBase, boundaries: Optional[set] = None) -> list:
    """Split a squashed string into (kind, value, literal) tokens.

    Kinds: family, hash, mode, padding, curve, suffix, stop, number, residue.
    Digit runs are numbers unless they are part of a longer known atom.
    Atoms of one or two characters ("ec", "dh", "s", "f", "id", ...) only match
    on word boundaries, so that "FrobnicateCipher" does not yield "ec"; the
    SLH-DSA size suffixes "s"/"f" may also follow a number at a word end.
    """
    tokens = []
    i, n = 0, len(text)
    residue = ""
    if boundaries is None:
        boundaries = {0, n}
    while i < n:
        best = None
        for L in range(min(kb.max_atom_len, n - i), 0, -1):
            cand = text[i:i + L]
            if cand not in kb.atom_kinds:
                continue
            if L <= 2:
                on_boundary = i in boundaries and (i + L) in boundaries
                after_number = (cand in ("s", "f") and (i + L) in boundaries and tokens and not residue
                                and (tokens[-1][0] == "number" or (tokens[-1][0] == "hash" and tokens[-1][1][1])))
                if not (on_boundary or after_number):
                    continue
            best = (L, cand)
            break
        if best is None:
            m = _NUM_RE.match(text, i)
            if m:
                if residue:
                    tokens.append(("residue", residue, residue))
                    residue = ""
                tokens.append(("number", m.group(0), m.group(0)))
                i = m.end()
                continue
            residue += text[i]
            i += 1
            continue
        if residue:
            tokens.append(("residue", residue, residue))
            residue = ""
        L, atom = best
        kind, value = kb.atom_kinds[atom]
        tokens.append((kind, value, atom))
        i += L
    if residue:
        tokens.append(("residue", residue, residue))
    return tokens


def _hash_string(hfam: Optional[str], size: Optional[str]) -> Optional[str]:
    if not hfam:
        return None
    if hfam in ("sha1", "md5", "md4", "md2", "ripemd160", "sm3", "whirlpool", "blake3"):
        return hfam
    if size:
        return f"{hfam}-{size}"
    return hfam


def _hash_from_fields(hfam, size):
    if hfam == "sha2" and size is None:
        return None  # "SHA" without a size is not a hash identity
    return _hash_string(hfam, size)


# --------------------------------------------------------------------------- #
# The canonical naming grammar
# --------------------------------------------------------------------------- #
def parse_algorithm(name: Optional[str], hints: Optional[dict] = None, kb: Optional[KnowledgeBase] = None) -> ParseResult:
    """Map a raw algorithm name (plus optional structured hints) to a canonical descriptor.

    ``hints`` may contain CycloneDX-style fields: primitive, parameterSetIdentifier,
    curve, mode, padding, oid.  Name-derived slots take precedence over hints;
    hints fill slots the name leaves open.  Conflicts are reported in ``notes``.
    """
    kb = kb or load_kb()
    hints = dict(hints or {})
    notes: list = []
    raw = (name or "").strip()

    # 0. OID given directly (either as the name or as a hint)
    oid_src = raw if _OID_RE.match(raw) else (hints.get("oid") if hints.get("oid") and _OID_RE.match(str(hints["oid"])) else None)
    if oid_src and oid_src in kb.oid_index:
        fam, suffix = kb.oid_index[oid_src]
        desc = _descriptor_from_oid(fam, suffix)
        if _OID_RE.match(raw):
            return _finish(desc, 1.0, notes + [f"identity-from-oid:{oid_src}"], [], None, hints, kb)
        # name present: parse the name too and merge (name wins, oid fills)
        parsed = parse_algorithm(raw, {k: v for k, v in hints.items() if k != "oid"}, kb)
        if parsed.ok and parsed.descriptor.family == desc.family:
            merged = _merge_slots(parsed.descriptor, desc)
            parsed.notes.append(f"oid-fill:{oid_src}")
            return _finish(merged, parsed.confidence, parsed.notes, parsed.residue, parsed.pre_standard, hints, kb)
        if not parsed.ok:
            return _finish(desc, 0.9, notes + [f"identity-from-oid:{oid_src}", "name-unparsed"], [], None, hints, kb)
        parsed.notes.append(f"oid-family-mismatch:{oid_src}")
        return _finish(parsed.descriptor, min(parsed.confidence, 0.7), parsed.notes, parsed.residue, parsed.pre_standard, hints, kb)

    if not raw and not hints:
        return ParseResult(None, 0.0, ["empty-name"])

    # 1. Cipher-suite shaped names are composite algorithms
    if _looks_like_suite(raw):
        suite = parse_cipher_suite(raw, kb)
        if suite:
            desc = AlgorithmDescriptor(family="suite", parameter_set=suite["canonical"], primitive="combiner",
                                       components=tuple(c.canonical() for _, c in suite["components"]))
            return ParseResult(desc, 1.0, ["cipher-suite-as-algorithm"])

    words = words_of(raw)
    squashed = "".join(words)
    boundaries = {0}
    pos = 0
    for w in words:
        pos += len(w)
        boundaries.add(pos)

    # 2. Whole-name aliases
    pre_standard = None
    if squashed in kb.full_names:
        entry = kb.full_names[squashed]
        desc = AlgorithmDescriptor(family=entry["family"], parameter_set=entry.get("parameterSet"),
                                   mode=entry.get("mode"), padding=entry.get("padding"), hash=entry.get("hash"),
                                   curve=entry.get("curve"))
        pre_standard = entry.get("preStandard")
        if pre_standard:
            notes.append(f"pre-standard-name:{raw}")
        return _finish(desc, 1.0, notes, [], pre_standard, hints, kb)

    # 2b. hybrid group names (e.g. X25519MLKEM768) - also in tlsGroups
    if squashed in kb.tls_groups:
        return _finish(AlgorithmDescriptor(family=kb.tls_groups[squashed]), 1.0, notes, [], None, hints, kb)

    # 3. Segmentation
    tokens = segment(squashed, kb, boundaries) if squashed else []
    interp = _interpret(tokens, kb, notes)
    desc, confidence, residue, pre_standard = interp

    if desc is None:
        # the name alone is not enough: can hints identify the asset?
        fam_hint = hints.get("family")
        if fam_hint and fam_hint in kb.families:
            desc = AlgorithmDescriptor(family=fam_hint)
            confidence = 0.6
            notes.append("identity-from-hints")
        else:
            return ParseResult(None, 0.0, notes + ["unresolved-name"], residue, pre_standard)
    return _finish(desc, confidence, notes, residue, pre_standard, hints, kb)


def _looks_like_suite(raw: str) -> bool:
    up = raw.upper()
    return (up.startswith("TLS_") or up.startswith("SSL_")) and ("_" in up[4:])


def _descriptor_from_oid(fam: str, suffix: str) -> AlgorithmDescriptor:
    """Rebuild a descriptor from a catalogue OID key such as '128-gcm' or '-pkcs1v15-sha2-256'."""
    kb = load_kb()
    if fam == "ec" and suffix.startswith("-"):
        return AlgorithmDescriptor(family="ec", curve=suffix[1:])
    spec = kb.families[fam]
    if suffix == "":
        return AlgorithmDescriptor(family=fam)
    if suffix.startswith("-"):
        rest = suffix[1:]
        padding = None
        hash_ = None
        for pad in ("pkcs1v15", "oaep", "pss"):
            if rest.startswith(pad):
                padding = pad
                rest = rest[len(pad):].lstrip("-")
                break
        if rest:
            hash_ = rest
        return AlgorithmDescriptor(family=fam, padding=padding, hash=hash_ or None)
    if "-" in suffix and spec.get("parameterSetKind") == "key-bits":
        ps, mode = suffix.split("-", 1)
        return AlgorithmDescriptor(family=fam, parameter_set=ps, mode=mode)
    if spec.get("levelFromHash"):
        return AlgorithmDescriptor(family=fam, hash=suffix)
    return AlgorithmDescriptor(family=fam, parameter_set=suffix)


def _merge_slots(primary: AlgorithmDescriptor, filler: AlgorithmDescriptor) -> AlgorithmDescriptor:
    kw = {}
    for slot in ("parameter_set", "curve", "mode", "padding", "hash"):
        if getattr(primary, slot) is None and getattr(filler, slot) is not None:
            kw[slot] = getattr(filler, slot)
    return replace(primary, **kw) if kw else primary


def _interpret(tokens: list, kb: KnowledgeBase, notes: list):
    families, hashes, numbers, modes, paddings, curves, suffixes, residue = [], [], [], [], [], [], [], []
    stops = []
    for idx, (kind, value, lit) in enumerate(tokens):
        if kind == "family":
            families.append((idx, value, lit))
        elif kind == "hash":
            hashes.append((idx, value[0], value[1], lit))
        elif kind == "number":
            numbers.append((idx, value))
        elif kind == "mode":
            modes.append((idx, value))
        elif kind == "padding":
            paddings.append((idx, value))
        elif kind == "curve":
            curves.append((idx, value))
        elif kind == "suffix":
            suffixes.append((idx, value))
        elif kind == "stop":
            stops.append((idx, lit))
        elif kind == "residue":
            residue.append(lit)

    consumed_numbers: set = set()

    # attach bare sizes to size-less hash tokens ("sha" "256" -> sha2-256)
    resolved_hashes = []
    for (idx, hfam, size, lit) in hashes:
        if size is None:
            nxt = [n for n in numbers if n[0] == idx + 1 and n[0] not in consumed_numbers]
            if nxt:
                size = nxt[0][1]
                consumed_numbers.add(nxt[0][0])
                if hfam == "sha2" and size == "1":
                    hfam, size = "sha1", None
                elif hfam == "sha2" and size == "3":
                    hfam = "sha3"
                    nxt2 = [n for n in numbers if n[0] == idx + 2 and n[0] not in consumed_numbers]
                    size = None
                    if nxt2:
                        size = nxt2[0][1]
                        consumed_numbers.add(nxt2[0][0])
        resolved_hashes.append((idx, hfam, size))

    fams = [f[1] for f in families]
    stop_lits = {s[1] for s in stops}
    pre_standard = None

    # chacha20 + poly1305 -> AEAD construction
    if "chacha20" in fams and "poly1305" in fams:
        fams = [f for f in fams if f not in ("chacha20", "poly1305")] + ["chacha20-poly1305"]
    if "xchacha20" in fams and "poly1305" in fams:
        fams = [f for f in fams if f not in ("xchacha20", "poly1305")] + ["xchacha20-poly1305"]
    # "aes" + "ctr" + "drbg" -> ctr-drbg
    if "drbg" in fams and any(m[1] == "ctr" for m in modes):
        fams = [f for f in fams if f != "drbg"] + ["ctr-drbg"]
        modes = [m for m in modes if m[1] != "ctr"]
    # hmac + drbg
    if "drbg" in fams and "hmac" in fams:
        fams = [f for f in fams if f not in ("drbg", "hmac")] + ["hmac-drbg"]

    primary = _choose_primary(fams, resolved_hashes, kb)
    hybrid = _hybrid_family(families, curves, numbers, consumed_numbers, kb)
    if hybrid:
        desc = AlgorithmDescriptor(family=hybrid[0], primitive="combiner", components=tuple(hybrid[1]))
        conf = 1.0 if not residue else 0.7
        return desc, conf, residue, None

    if primary is None:
        if curves:
            desc = AlgorithmDescriptor(family="ec", curve=curves[0][1])
            return desc, 0.9 if not residue else 0.6, residue, None
        if resolved_hashes:
            idx, hfam, size = resolved_hashes[0]
            hs = _hash_from_fields(hfam, size)
            if hs is None:
                notes.append("hash-without-size")
                return AlgorithmDescriptor(family="sha2"), 0.5, residue, None
            fam, _, ps = hs.partition("-")
            desc = AlgorithmDescriptor(family=fam, parameter_set=ps or None)
            return desc, 1.0 if not residue else 0.7, residue, None
        return None, 0.0, residue, None

    spec = kb.families.get(primary, {})
    slots = set(spec.get("slots", []))
    desc_kw: dict = {"family": primary}

    # hash slot
    hash_value = None
    if resolved_hashes:
        cand = [_hash_from_fields(h[1], h[2]) for h in resolved_hashes]
        cand = [c for c in cand if c]
        if cand:
            hash_value = cand[0]
    # pre-standard PQ names
    lit_by_family = {f[1]: f[2] for f in families}
    lit = lit_by_family.get(primary, "")
    if lit in ("kyber", "dilithium", "falcon", "sphincs", "sphincsplus"):
        pre_standard = lit
        notes.append(f"pre-standard-name:{lit}")

    # parameter set
    kind = spec.get("parameterSetKind")
    free_numbers = [n for n in numbers if n[0] not in consumed_numbers]
    if "parameterSet" in slots:
        ps = None
        if primary == "slh-dsa":
            hf = resolved_hashes[0] if resolved_hashes else None
            hfam = "shake" if (hf and hf[1] == "shake") else "sha2"
            size = (hf[2] if hf and hf[2] else (free_numbers[0][1] if free_numbers else None))
            if hf and hf[2]:
                pass
            elif free_numbers:
                consumed_numbers.add(free_numbers[0][0])
            suf = suffixes[0][1] if suffixes else None
            if size:
                ps = f"{hfam}-{size}{suf or ''}"
                if not suf:
                    notes.append("slh-dsa-variant-suffix-missing")
            hash_value = None
        elif free_numbers:
            num = free_numbers[0][1]
            consumed_numbers.add(free_numbers[0][0])
            if primary == "ml-dsa" and lit == "dilithium":
                num = kb.catalogue["dilithiumMap"].get(num, num)
            elif primary == "fn-dsa" and lit == "falcon":
                num = kb.catalogue["falconMap"].get(num, num)
            ps = num
        elif kind == "variant" and lit.startswith("argon2") and len(lit) > 6:
            ps = lit[6:]
        if ps is not None:
            known = spec.get("parameterSets") or {}
            if known and ps not in known:
                notes.append(f"parameter-set-not-in-catalogue:{ps}")
            desc_kw["parameter_set"] = ps
    elif free_numbers and kind is None and primary not in ("ed25519", "ed448", "x25519", "x448"):
        notes.append(f"ignored-number:{free_numbers[0][1]}")

    if "curve" in slots and curves:
        desc_kw["curve"] = curves[0][1]
    if "mode" in slots and modes:
        mvals = [m[1] for m in modes]
        if "gcm" in mvals and "siv" in mvals:
            desc_kw["mode"] = "gcm-siv"
        else:
            desc_kw["mode"] = mvals[0]
    if "padding" in slots:
        if paddings:
            desc_kw["padding"] = paddings[0][1]
        elif primary == "rsa" and "mgf1" in stop_lits and not any(p[1] == "oaep" for p in paddings):
            desc_kw["padding"] = "pss"
    if "hash" in slots and hash_value:
        desc_kw["hash"] = hash_value
    if hash_value and "hash" not in slots and primary not in ("sha2", "sha3", "shake", "sha1", "md5"):
        notes.append(f"ignored-hash:{hash_value}")
    if modes and "mode" not in slots:
        notes.append(f"ignored-mode:{modes[0][1]}")
    if paddings and "padding" not in slots:
        notes.append(f"ignored-padding:{paddings[0][1]}")

    desc = AlgorithmDescriptor(**desc_kw)
    confidence = 1.0
    if residue:
        confidence = 0.7
    extra_fams = [f for f in fams if f != primary and f not in ("hmac",)]
    if extra_fams and primary not in ("pbkdf2", "hkdf", "kbkdf", "hmac-drbg"):
        notes.append("extra-families:" + ",".join(sorted(set(extra_fams))))
        confidence = min(confidence, 0.8)
    return desc, confidence, residue, pre_standard


_PRIORITY = ["pbkdf2", "pbkdf1", "hkdf", "kbkdf", "x963kdf", "concatkdf", "scrypt", "bcrypt", "argon2",
             "ctr-drbg", "hmac-drbg", "hash-drbg", "drbg", "hmac",
             "ml-kem", "ml-dsa", "slh-dsa", "fn-dsa", "hqc", "frodokem", "bike", "classic-mceliece", "ntru", "ntru-prime",
             "lms", "hss", "xmss", "xmss-mt",
             "rsa", "dsa", "ecdsa", "eddsa", "ed25519", "ed448", "ecdh", "x25519", "x448", "dh", "ecies", "sm2", "elgamal", "ec", "psk",
             "chacha20-poly1305", "xchacha20-poly1305", "aes", "camellia", "aria", "sm4", "seed", "twofish", "serpent",
             "tdea", "des", "blowfish", "cast5", "idea", "rc2", "rc4", "chacha20", "xchacha20", "salsa20",
             "cmac", "gmac", "kmac", "poly1305", "siphash", "null"]


def _choose_primary(fams: list, hashes: list, kb: KnowledgeBase) -> Optional[str]:
    if not fams:
        return None
    present = set(fams)
    for p in _PRIORITY:
        if p in present:
            # "hmac" together with a KDF/DRBG is a construction detail of that KDF
            return p
    return fams[0]


def _hybrid_family(families, curves, numbers, consumed, kb: KnowledgeBase):
    """Two key-establishment families in one name form a hybrid combiner (e.g. x25519+ml-kem-768)."""
    kex = [(idx, fam, lit) for (idx, fam, lit) in families if fam in kb.hybrid_families]
    if len(kex) < 2:
        return None
    parts = []
    for i, (idx, fam, lit) in enumerate(kex):
        nxt_idx = kex[i + 1][0] if i + 1 < len(kex) else 10 ** 9
        nums = [n for n in numbers if idx < n[0] < nxt_idx and n[0] not in consumed]
        crv = [c for c in curves if idx < c[0] < nxt_idx]
        if fam in ("x25519", "x448"):
            parts.append(fam)
        elif fam in ("ecdh", "ec") and crv:
            parts.append(f"ecdh-{crv[0][1]}")
        elif nums:
            num = nums[0][1]
            if fam == "ml-kem" and lit == "kyber":
                num = kb.catalogue["kyberMap"].get(num, num)
            parts.append(f"{fam}-{num}")
        else:
            parts.append(fam)
    return "+".join(parts), parts


def _finish(desc: AlgorithmDescriptor, confidence: float, notes: list, residue: list,
            pre_standard: Optional[str], hints: dict, kb: KnowledgeBase) -> ParseResult:
    """Apply hints, normalise slot values against the family's allowed slots and derive the primitive."""
    spec = kb.families.get(desc.family.split("+")[0], {}) if not desc.is_hybrid() else {}
    slots = set(spec.get("slots", []))
    kw: dict = {}

    def hint(name):
        v = hints.get(name)
        if v in (None, "", "unknown", "other"):
            return None
        return str(v)

    hv = hint("parameterSetIdentifier") or hint("parameterSet")
    if hv is not None and "parameterSet" in slots:
        hv_norm = norm_token(hv)
        if desc.parameter_set is None:
            kw["parameter_set"] = hv_norm
        elif desc.parameter_set != hv_norm:
            notes.append(f"hint-conflict:parameterSet:{hv_norm}")
    cv = hint("curve")
    if cv is not None and "curve" in slots:
        cv_norm = squash(cv)
        cv_canon = kb.atom_kinds.get(cv_norm, (None, cv_norm))[1] if cv_norm in kb.atom_kinds else cv_norm
        if desc.curve is None:
            kw["curve"] = cv_canon
        elif desc.curve != cv_canon:
            notes.append(f"hint-conflict:curve:{cv_canon}")
    mv = hint("mode")
    if mv is not None and "mode" in slots:
        mv_norm = squash(mv)
        mv_canon = kb.atom_kinds.get(mv_norm, (None, norm_token(mv)))[1]
        if desc.mode is None:
            kw["mode"] = mv_canon
        elif desc.mode != mv_canon:
            notes.append(f"hint-conflict:mode:{mv_canon}")
    pv = hint("padding")
    if pv is not None and "padding" in slots:
        pv_norm = squash(pv)
        pv_canon = kb.atom_kinds.get(pv_norm, (None, norm_token(pv)))[1]
        if desc.padding is None:
            kw["padding"] = pv_canon
        elif desc.padding != pv_canon:
            notes.append(f"hint-conflict:padding:{pv_canon}")
    hh = hint("hash")
    if hh is not None and "hash" in slots and desc.hash is None:
        parsed = parse_algorithm(hh, None, kb)
        if parsed.ok and parsed.descriptor.family in ("sha1", "sha2", "sha3", "shake", "md5", "blake2b", "blake2s", "blake3", "sm3"):
            kw["hash"] = parsed.descriptor.canonical()

    if desc.is_hybrid() and not desc.components:
        kw["components"] = tuple(desc.family.split("+"))
    if kw:
        desc = replace(desc, **kw)

    # normalisation conventions (Section 4.3)
    if desc.mode in _UNPADDED_MODES and desc.padding is not None:
        notes.append(f"dropped-padding:{desc.padding}")
        desc = replace(desc, padding=None)
    if desc.family == "rsa" and desc.hash and desc.padding is None:
        desc = replace(desc, padding="pkcs1v15")  # RSASSA-PKCS1-v1_5 is the default signature padding

    # primitive derivation
    prim = desc.primitive
    if prim is None:
        if desc.is_hybrid() or desc.family == "suite":
            prim = "combiner"
        else:
            prim = spec.get("primitive", "unknown")
            if spec.get("primitive") == "block-cipher" and desc.mode in kb.ae_modes:
                prim = "ae"
            elif desc.family == "rsa":
                if desc.padding == "oaep":
                    prim = "pke"
                elif desc.padding == "pss" or desc.hash:
                    prim = "signature"
                else:
                    hp = hint("primitive")
                    prim = kebab(hp) if hp in ("signature", "pke", "keygen") else "pke"
                    if prim == "keygen":
                        prim = "pke"
            elif desc.family in ("ec",):
                hp = kebab(hint("primitive"))
                prim = hp if hp in ("signature", "key-agree", "pke") else "unknown"
            elif desc.family == "drbg":
                prim = "drbg"
        desc = replace(desc, primitive=prim)
    return ParseResult(desc, confidence, notes, residue, pre_standard)


# --------------------------------------------------------------------------- #
# Cipher suites
# --------------------------------------------------------------------------- #
_SUITE_HASH = {"SHA": "sha1", "SHA256": "sha2-256", "SHA384": "sha2-384", "SHA512": "sha2-512", "MD5": "md5"}


def parse_cipher_suite(name: str, kb: Optional[KnowledgeBase] = None) -> Optional[dict]:
    """Decompose an IANA cipher suite name into (role, AlgorithmDescriptor) constituents.

    Returns ``{"name": IANA name, "canonical": lower-kebab, "components": [(role, desc), ...],
    "kex_known": bool}`` or None if the name is not suite-shaped.
    """
    kb = kb or load_kb()
    if name is None:
        return None
    n = name.strip()
    if n.lower().startswith("0x") and n.lower() in kb.cipher_suite_ids:
        n = kb.cipher_suite_ids[n.lower()]
    up = n.upper().replace("-", "_")
    if not (up.startswith("TLS_") or up.startswith("SSL_")):
        return None
    toks = up.split("_")[1:]
    components = []
    kex_known = True
    if "WITH" in toks:
        w = toks.index("WITH")
        kexauth = toks[:w]
        rest = toks[w + 1:]
        kex = None
        auth = None
        for t in kexauth:
            if t in ("ECDHE", "ECDH"):
                kex = "ecdh"
            elif t in ("DHE", "DH"):
                kex = "dh"
            elif t == "RSA":
                if kex is None:
                    kex = "rsa"
                else:
                    auth = "rsa"
            elif t == "ECDSA":
                auth = "ecdsa"
            elif t == "DSS":
                auth = "dsa"
            elif t == "PSK":
                if kex is None:
                    kex = "psk"
                else:
                    auth = "psk"
            elif t == "ANON":
                auth = None
            elif t == "SRP":
                kex = kex or "srp"
        if kex == "rsa" and auth is None:
            auth = "rsa"  # RSA key transport authenticates with the RSA certificate
        if kex and kex != "srp":
            components.append(("kex", AlgorithmDescriptor(family=kex, primitive="key-agree" if kex != "rsa" else "pke")))
        if auth:
            components.append(("auth", AlgorithmDescriptor(family=auth, primitive="signature" if auth != "psk" else "key-agree")))
    else:
        rest = toks
        kex_known = False  # TLS 1.3: key exchange is negotiated through groups
    hash_tok = rest[-1] if rest and rest[-1] in _SUITE_HASH else None
    cipher_toks = rest[:-1] if hash_tok else rest
    cipher_name = "_".join(cipher_toks)
    if cipher_name and cipher_name != "NULL":
        pr = parse_algorithm(cipher_name.replace("_", "-"), None, kb)
        if pr.ok:
            components.append(("cipher", pr.descriptor))
    elif cipher_name == "NULL":
        components.append(("cipher", AlgorithmDescriptor(family="null", primitive="other")))
    if hash_tok:
        fam, _, ps = _SUITE_HASH[hash_tok].partition("-")
        components.append(("prf", AlgorithmDescriptor(family=fam, parameter_set=ps or None, primitive="hash")))
    return {"name": up, "canonical": up.lower().replace("_", "-"), "components": components, "kex_known": kex_known}


# --------------------------------------------------------------------------- #
# Identifiers of the other asset kinds
# --------------------------------------------------------------------------- #
def certificate_id(fingerprint: Optional[str], subject: Optional[str], issuer: Optional[str],
                   serial: Optional[str], not_before: Optional[str], not_after: Optional[str],
                   location: Optional[str] = None) -> tuple[str, str]:
    """Return (cid, identity-basis)."""
    if fingerprint:
        fp = fingerprint.strip().lower()
        alg, sep, hexpart = fp.partition(":")
        if sep and alg.replace("-", "") in ("sha256", "sha1", "sha512", "md5", "sha384"):
            fp = f"{alg.replace('-', '')}:{hexpart.replace(':', '')}"
        else:
            fp = "sha256:" + fp.replace(":", "")
        return f"{ID_PREFIX}cert:fp:{fp}", "fingerprint"
    if subject or issuer or serial:
        basis = jcs_dumps({"subject": normalize_dn(subject), "issuer": normalize_dn(issuer),
                           "serial": (serial or "").lower().replace(":", ""),
                           "notBefore": not_before, "notAfter": not_after})
        return f"{ID_PREFIX}cert:dn:{short_hash(basis, 24)}", "distinguished-name"
    if location:
        return f"{ID_PREFIX}cert:loc:{short_hash(location, 24)}", "location"
    return f"{ID_PREFIX}cert:unresolved:{short_hash(jcs_dumps([subject, issuer, serial, not_before, not_after]), 24)}", "unresolved"


def material_id(mtype: str, fingerprint: Optional[str], algorithm_cid: Optional[str],
                identifier: Optional[str], location: Optional[str], size: Optional[int],
                fallback_seed: str) -> tuple[str, str]:
    t = mtype or "unknown"
    if fingerprint:
        fp = fingerprint.strip().lower()
        alg, sep, hexpart = fp.partition(":")
        fp = f"{alg.replace('-', '')}:{hexpart.replace(':', '')}" if sep else "sha256:" + fp.replace(":", "")
        return f"{ID_PREFIX}key:{t}:fp:{fp}", "fingerprint"
    if identifier:
        return f"{ID_PREFIX}key:{t}:id:{short_hash(identifier, 24)}", "identifier"
    if location:
        basis = jcs_dumps({"alg": algorithm_cid, "loc": location, "size": size})
        return f"{ID_PREFIX}key:{t}:loc:{short_hash(basis, 24)}", "location"
    return f"{ID_PREFIX}key:{t}:src:{short_hash(fallback_seed, 24)}", "source-local"


def protocol_id(ptype: str, version: Optional[str]) -> str:
    t = ptype or "unknown"
    return f"{ID_PREFIX}proto:{t}-{version}" if version else f"{ID_PREFIX}proto:{t}"


def component_id(purl: Optional[str], cpe: Optional[str], group: Optional[str], name: Optional[str], version: Optional[str]) -> tuple[str, str]:
    if purl:
        p = purl.strip()
        p = p.split("?", 1)[0]  # qualifiers are not identity
        return f"{ID_PREFIX}comp:{p}", "purl"
    if cpe:
        return f"{ID_PREFIX}comp:{cpe.strip().lower()}", "cpe"
    basis = "/".join(x for x in [norm_token(group), norm_token(name)] if x) + (f"@{str(version).strip().lower()}" if version else "")
    return f"{ID_PREFIX}comp:{basis or 'unknown'}", "name-version"
