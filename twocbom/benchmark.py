"""Benchmark results of the CBOMFuse orchestrator (``cbomfuse/orch``) as 2CBOM knowledge.

The orchestrator runs CBOM generators against the ``cbomfuse/baseline`` ground truth and writes, per
run::

    <run>/scorecard.json        scores, head-to-head tables and the ledger (one row per item and tool)
    <run>/priors.json           the same without the ledger
    <run>/twocbom/tools.json    a tool profile in the schema of ``twocbom/knowledge/tools.json``

2CBOM uses them in two places:

* **tool profiles** -- the benchmark profile is laid over the packaged one: benchmarked tools get
  their measured trust and strengths, their aliases (including the names the tools write into their
  own CBOMs) are added, and tools the benchmark did not measure keep their hand-set entries;
* **settlement** -- when benchmarked tools disagree about a tool-asserted attribute,
  ``settle.resolve-attribute`` asks :meth:`Reliability.reconcile` which of the two tools is more
  reliable for that attribute in the asset's category (language, asset type, subtype, family) and
  ranks the candidates by the decided answers before strength and trust.  Undecided answers leave the
  scalar order (strength, then trust) in charge -- the "reconcile, scalar fallback" rule of the
  orchestrator's evaluation.

:class:`Reliability` is a dependency-free port of ``orchestrator.reconcile.Scorecard.reconcile`` for
scoring models 1.0 and 1.1 (``tests/test_benchmark.py`` checks it against answers produced by the
orchestrator itself).  1.1 changed how the orchestrator matches detections (artifact cases, certificate
identity), not the ledger rows or the aggregation repeated here.  Files produced under another scoring
model are refused, because their numbers would not mean what this code assumes.
"""
from __future__ import annotations

import hashlib
import json
import math
import weakref
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Union

from .canonical import digest as content_digest
from .model import DETECTION_METHODS

SUPPORTED_SCORING_MODELS = ("1.0", "1.1")

# The scoring parameters of orchestrator scoring models 1.0/1.1 (orchestrator.config.DEFAULT_CONFIG["scoring"]);
# a scorecard's own run.config.scoring overrides them, exactly as in the orchestrator.
DEFAULT_SCORING = {
    "weights": {"recall": 0.35, "precision": 0.15, "completeness": 0.15, "correctness": 0.25, "locality": 0.10},
    "min_support": 5,
    "min_support_head_to_head": 3,
    "undecided_below": 0.60,
    "backoff_relevance_decay": 0.15,
    "shrinkage_prior_weight": 5,
}

# Facets dropped first when a category has too little support (least informative first).
DEFAULT_BACKOFF_ORDER = ("case", "scenario", "library", "implicit", "pqc", "language", "family", "subtype", "assetType")

METRICS = ("recall", "precision", "completeness", "correctness", "locality")
LIST_FACETS = {"scenario": "scenarios", "library": "libraries"}
FP_FACETS = ("language", "case", "assetType", "subtype", "family")

# 2CBOM / CycloneDX attribute spellings -> orchestrator attribute names (orchestrator.reconcile).
ATTRIBUTE_ALIASES = {
    "parameterset": "parameterSetIdentifier", "parameter_set": "parameterSetIdentifier", "parameterSet": "parameterSetIdentifier",
    "keysize": "parameterSetIdentifier", "keySize": "parameterSetIdentifier", "family": "identity", "descriptor": "identity",
    "hash": "identity", "cryptofunctions": "cryptoFunctions", "functions": "cryptoFunctions",
    "classicalsecuritylevel": "classicalSecurityLevel", "nistquantumsecuritylevel": "nistQuantumSecurityLevel",
    "securityLevel": "classicalSecurityLevel", "quantumSecurityLevel": "nistQuantumSecurityLevel",
    "ciphersuites": "cipherSuites", "signaturealgorithm": "signatureAlgorithmRef", "signatureAlgorithm": "signatureAlgorithmRef",
    "subjectpublickeyalgorithm": "subjectPublicKeyRef", "subjectPublicKeyAlgorithm": "subjectPublicKeyRef",
    "subjectname": "subjectName", "issuername": "issuerName", "notvalidbefore": "notValidBefore", "notvalidafter": "notValidAfter",
    "algorithmref": "algorithmRef", "algorithm": "algorithmRef", "materialtype": "type", "protocoltype": "type",
}

# 2CBOM attribute names with no orchestrator alias: the tool's own primitive claim is kept as
# toolPrimitive (the canonical primitive is derived from the identity); a component's name is its identity.
TWOCBOM_ATTRIBUTES = {"toolPrimitive": "primitive"}
TWOCBOM_COMPONENT_ATTRIBUTES = {"name": "identity", "group": "identity"}

# 2CBOM catalogue family -> orchestrator lexicon family, where the spellings differ.
FAMILY_TO_BENCHMARK = {
    "tdea": "3des", "chacha20-poly1305": "chacha20", "xchacha20-poly1305": "xchacha20",
    "blake2b": "blake2", "blake2s": "blake2", "ed25519": "eddsa", "ed448": "eddsa", "x25519": "ecdh", "x448": "ecdh",
    "drbg": "csprng", "ctr-drbg": "csprng", "hash-drbg": "csprng", "hmac-drbg": "csprng",
    "ripemd160": "ripemd", "shake": "sha3", "keccak": "sha3",
}

# File extension of an evidence location -> benchmark language (the corpus uses the first five, plus
# "Artifacts" for certificates, keys, keystores and secret/TLS configuration stored as files).
LANGUAGE_BY_EXTENSION = {
    ".py": "Python", ".pyi": "Python", ".java": "Java", ".go": "Go", ".cs": "C#",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala", ".c": "C", ".h": "C", ".cc": "C++", ".cpp": "C++",
    ".cxx": "C++", ".hpp": "C++", ".rs": "Rust", ".rb": "Ruby", ".php": "PHP", ".swift": "Swift",
    **{ext: "Artifacts" for ext in (
        ".pem", ".crt", ".cer", ".cert", ".der", ".ca-bundle", ".p7b", ".p7c", ".p7s", ".spc", ".csr", ".req",
        ".crl", ".key", ".pub", ".p8", ".pk8", ".p12", ".pfx", ".jks", ".jceks", ".bks", ".keystore",
        ".truststore", ".env", ".tf", ".hcl", ".cnf")},
}


class BenchmarkError(ValueError):
    """A benchmark file is missing, malformed, or was produced under an unsupported scoring model."""


# --------------------------------------------------------------------------- #
# statistics (orchestrator.evaluate.stats, verbatim)
# --------------------------------------------------------------------------- #
def lbeta(a: float, b: float) -> float:
    return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)


def _betacf(a: float, b: float, x: float, max_iter: int = 300, eps: float = 3e-14) -> float:
    """Continued fraction for the incomplete beta function (Numerical Recipes, modified Lentz)."""
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, max_iter + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def betainc(a: float, b: float, x: float) -> float:
    """Regularised incomplete beta function I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbt = -lbeta(a, b) + a * math.log(x) + b * math.log(1.0 - x)
    if x < (a + 1.0) / (a + b + 2.0):
        return math.exp(lbt) * _betacf(a, b, x) / a
    return 1.0 - math.exp(lbt) * _betacf(b, a, 1.0 - x) / b


def beta_cdf(x: float, a: float, b: float) -> float:
    return betainc(a, b, x)


def beta_pdf(x: float, a: float, b: float) -> float:
    if x <= 0.0 or x >= 1.0:
        return 0.0
    return math.exp((a - 1.0) * math.log(x) + (b - 1.0) * math.log(1.0 - x) - lbeta(a, b))


def prob_greater(a1: float, b1: float, a2: float, b2: float, n: int = 600) -> float:
    """P(X > Y) for X ~ Beta(a1, b1), Y ~ Beta(a2, b2) by Simpson integration of pdf_X(x) * cdf_Y(x)."""
    if n % 2:
        n += 1
    h = 1.0 / n
    total = 0.0
    for i in range(n + 1):
        x = i * h
        if i == 0 or i == n:
            w = 1.0
        elif i % 2:
            w = 4.0
        else:
            w = 2.0
        xx = min(max(x, 1e-9), 1.0 - 1e-9)
        total += w * beta_pdf(xx, a1, b1) * beta_cdf(xx, a2, b2)
    p = total * h / 3.0
    return min(1.0, max(0.0, p))


def prob_above_half(a: float, b: float) -> float:
    return 1.0 - betainc(a, b, 0.5)


def posterior(correct: float, total: float, prior_a: float = 1.0, prior_b: float = 1.0) -> tuple:
    """Beta posterior parameters for ``correct`` successes in ``total`` trials (fractional allowed)."""
    correct = max(0.0, min(float(correct), float(total)))
    return prior_a + correct, prior_b + (float(total) - correct)


# --------------------------------------------------------------------------- #
# categories and ledger rows (orchestrator.evaluate.scoring / pairwise)
# --------------------------------------------------------------------------- #
def category_key(facets: dict) -> str:
    if not facets:
        return "*"
    return ";".join(f"{k}={facets[k]}" for k in sorted(facets))


def parse_category(text: Optional[str]) -> dict:
    """``language=Java;subtype=hash`` -> dict (``*`` or empty -> {})."""
    out: dict = {}
    if not text or text.strip() in ("*", ""):
        return out
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"category facet {part!r} must look like name=value")
        k, v = part.split("=", 1)
        k, v = k.strip(), v.strip()
        if k in ("implicit", "pqc"):
            v = v.lower() in ("1", "true", "yes")
        out[k] = v
    return out


def row_matches(row: dict, facets: dict) -> bool:
    for k, v in facets.items():
        if k in LIST_FACETS:
            if v not in (row.get(LIST_FACETS[k]) or []):
                return False
        elif k == "tool":
            if row.get("tool") != v:
                return False
        else:
            if row.get(k) != v:
                return False
    return True


def fp_matches(row: dict, facets: dict) -> bool:
    for k, v in facets.items():
        if k in ("tool",):
            if row.get("tool") != v:
                return False
        elif k in FP_FACETS:
            if row.get(k) != v:
                return False
    return True


def _mean(values: Iterable) -> Optional[float]:
    vals = [v for v in values if v is not None]
    return sum(vals) / len(vals) if vals else None


def _r(v: Optional[float]) -> Optional[float]:
    return round(v, 4) if v is not None else None


def category_score(gt_rows: list, fp_rows: list, weights: dict) -> dict:
    """Support and composite score of one category (the part of ``aggregate`` that reconciliation reads)."""
    rows = [r for r in gt_rows if r.get("scored")]
    support = len(rows)
    detected_rows = [r for r in rows if r.get("detected")]
    detected = len(detected_rows)
    recall = detected / support if support else None
    tp_refs = set()
    for r in detected_rows:
        for ref in r.get("detectionRefs") or ([r["bestDetection"]["ref"]] if r.get("bestDetection") else []):
            tp_refs.add((r["case"], ref))
    tp = len(tp_refs)
    fp = len(fp_rows)
    precision = tp / (tp + fp) if (tp + fp) else None
    completeness = _mean(r.get("completeness") for r in detected_rows)
    correctness = _mean(r.get("correctness") for r in detected_rows)
    loc_vals = []
    for r in detected_rows:
        loc = r.get("locations")
        if loc and loc.get("expected"):
            loc_vals.append(loc["matched"] / loc["expected"])
    locality = _mean(loc_vals)
    metrics = {"recall": recall, "precision": precision, "completeness": completeness, "correctness": correctness,
               "locality": locality}
    total_w = sum(weights.get(m, 0.0) for m in METRICS if metrics[m] is not None)
    score = None
    if total_w > 0:
        score = sum(weights.get(m, 0.0) * metrics[m] for m in METRICS if metrics[m] is not None) / total_w
    return {"support": support, "score": _r(score)}


def attribute_evidence(gt_rows: list, attribute: str) -> tuple:
    """(sum of correct, number reported) for an attribute over detected, scored rows."""
    correct = 0.0
    n = 0
    for r in gt_rows:
        if not r.get("scored") or not r.get("detected"):
            continue
        a = (r.get("attributes") or {}).get(attribute)
        if not a or a.get("reported") in (None, "", [], {}):
            continue
        n += 1
        correct += float(a.get("correct") or 0.0)
    return correct, n


def _norm_reported(v) -> str:
    if isinstance(v, list):
        return json.dumps(sorted(str(x).lower() for x in v))
    if isinstance(v, dict):
        return json.dumps(v, sort_keys=True)
    return str(v).strip().lower()


def _h2h_empty() -> dict:
    return {"aWins": 0, "bWins": 0, "bothWrong": 0, "agree": 0, "agreeWrong": 0, "aOnly": 0, "bOnly": 0, "bothMissed": 0,
            "compared": 0}


def head_to_head(rows_a: list, rows_b: list, facets: Optional[dict] = None) -> dict:
    """``{attribute: counts}`` (plus the ``"*"`` aggregate) on items that both tools' ledgers scored."""
    facets = facets or {}
    index_b = {(r["case"], r["assetId"]): r for r in rows_b if r.get("kind") == "gt" and r.get("scored")}
    out: dict = defaultdict(_h2h_empty)
    for ra in rows_a:
        if ra.get("kind") != "gt" or not ra.get("scored"):
            continue
        if facets and not row_matches(ra, facets):
            continue
        rb = index_b.get((ra["case"], ra["assetId"]))
        if rb is None:
            continue
        da, db = bool(ra.get("detected")), bool(rb.get("detected"))
        agg = out["*"]
        agg["compared"] += 1
        if da and not db:
            agg["aOnly"] += 1
        elif db and not da:
            agg["bOnly"] += 1
        elif not da and not db:
            agg["bothMissed"] += 1
        if not (da and db):
            continue
        attrs_a = ra.get("attributes") or {}
        attrs_b = rb.get("attributes") or {}
        for name in sorted(set(attrs_a) | set(attrs_b)):
            xa, xb = attrs_a.get(name), attrs_b.get(name)
            if not xa or not xb:
                continue
            ra_rep = xa.get("reported") not in (None, "", [], {})
            rb_rep = xb.get("reported") not in (None, "", [], {})
            st = out[name]
            st["compared"] += 1
            if ra_rep and not rb_rep:
                st["aOnly"] += 1
                continue
            if rb_rep and not ra_rep:
                st["bOnly"] += 1
                continue
            if not ra_rep and not rb_rep:
                st["bothMissed"] += 1
                continue
            ca, cb = float(xa.get("correct") or 0.0), float(xb.get("correct") or 0.0)
            if _norm_reported(xa["reported"]) == _norm_reported(xb["reported"]):
                st["agree"] += 1
                if ca < 0.999:
                    st["agreeWrong"] += 1
                continue
            if ca > cb + 1e-9:
                st["aWins"] += 1
            elif cb > ca + 1e-9:
                st["bWins"] += 1
            else:
                st["bothWrong"] += 1
    agg = out["*"]
    for name, st in out.items():
        if name == "*":
            continue
        for k in ("aWins", "bWins", "bothWrong", "agree", "agreeWrong"):
            agg[k] += st[k]
    return dict(out)


def pair_key(tool_a: str, tool_b: str) -> tuple:
    """Canonical ordering so that (A,B) and (B,A) share one record; the flag says whether to swap."""
    if tool_a <= tool_b:
        return f"{tool_a}|{tool_b}", False
    return f"{tool_b}|{tool_a}", True


def swap_counts(counts: dict) -> dict:
    return {**counts, "aWins": counts["bWins"], "bWins": counts["aWins"], "aOnly": counts["bOnly"], "bOnly": counts["aOnly"]}


def benchmark_attribute_name(name: Optional[str], component: bool = False) -> Optional[str]:
    """A 2CBOM attribute name as the benchmark knows it (then normalised like the orchestrator does)."""
    if name is None:
        return None
    if component and name in TWOCBOM_COMPONENT_ATTRIBUTES:
        return TWOCBOM_COMPONENT_ATTRIBUTES[name]
    return normalize_attribute_name(TWOCBOM_ATTRIBUTES.get(name, name))


def normalize_attribute_name(name: Optional[str]) -> Optional[str]:
    if name is None:
        return None
    n = name.strip()
    if n in ATTRIBUTE_ALIASES:
        return ATTRIBUTE_ALIASES[n]
    return ATTRIBUTE_ALIASES.get(n.lower(), n)


# --------------------------------------------------------------------------- #
# reconciliation
# --------------------------------------------------------------------------- #
@dataclass
class Reconciliation:
    tool_a: str
    tool_b: str
    attribute: Optional[str]
    category: dict
    category_used: dict
    backoff_steps: int
    tier: str
    p_a_better: float
    relevance: float
    confidence: float
    decision: str
    preferred: Optional[str]
    weights: dict
    support: dict
    versions: dict
    explanation: list = field(default_factory=list)

    def to_dict(self) -> dict:
        """The orchestrator's ``Reconciliation.to_dict()`` without ``valueEvidence``."""
        return {
            "toolA": self.tool_a, "toolB": self.tool_b, "attribute": self.attribute,
            "category": self.category, "categoryUsed": self.category_used, "backoffSteps": self.backoff_steps,
            "tier": self.tier, "pABetter": round(self.p_a_better, 4), "relevance": round(self.relevance, 4),
            "confidence": round(self.confidence, 4), "decision": self.decision, "preferred": self.preferred,
            "weights": {k: round(v, 4) for k, v in self.weights.items()}, "support": self.support,
            "toolVersions": self.versions, "scoringModelVersion": "1.0", "explanation": self.explanation,
        }


def _read_json(path: Path) -> tuple:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise BenchmarkError(f"{path}: {exc.strerror or exc}") from exc
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"{path}: not a JSON document ({exc})") from exc
    if not isinstance(doc, dict):
        raise BenchmarkError(f"{path}: expected a JSON object")
    return doc, "sha256:" + hashlib.sha256(data).hexdigest()


def _check_scoring_model(doc: dict, what: str, required: bool) -> Optional[str]:
    version = doc.get("scoringModelVersion")
    if version is None and not required:
        return None
    if str(version) not in SUPPORTED_SCORING_MODELS:
        raise BenchmarkError(f"{what} was produced under scoring model {version!r}; this 2CBOM understands "
                             f"{', '.join(SUPPORTED_SCORING_MODELS)}")
    return str(version)


class Reliability:
    """Answers *tools A and B disagree on attribute Y of an asset in category X -- whom to believe?*

    Built from an orchestrator ``scorecard.json`` (with ledger: any category can be scored exactly) or
    ``priors.json`` (precomputed categories and head-to-head tables only; the attribute tier needs the
    ledger, as in the orchestrator).
    """

    def __init__(self, doc: dict, *, digest: Optional[str] = None, path: Optional[str] = None):
        if not isinstance(doc, dict):
            raise BenchmarkError("priors must be a JSON object")
        self.scoring_model_version = _check_scoring_model(doc, "the scorecard/priors file", required=True)
        for key in ("tools", "scores", "pairwise"):
            if doc.get(key) is not None and not isinstance(doc.get(key), dict):
                raise BenchmarkError(f"priors member {key!r} must be an object")
        if doc.get("ledger") is not None and not isinstance(doc.get("ledger"), list):
            raise BenchmarkError("priors member 'ledger' must be an array")
        self.doc = doc
        self.path = path
        self.digest = digest or content_digest(doc)
        self.tools: dict = doc.get("tools") or {}
        self.scores: dict = doc.get("scores") or {}
        self.pairwise: dict = doc.get("pairwise") or {}
        cfg = ((doc.get("run") or {}).get("config") or {}).get("scoring") or {}
        self.scoring_cfg: dict = {**DEFAULT_SCORING, **cfg}
        self.weights: dict = {**DEFAULT_SCORING["weights"], **(self.scoring_cfg.get("weights") or {})}
        self.backoff_order = tuple(self.scoring_cfg.get("backoff_order") or DEFAULT_BACKOFF_ORDER)
        self._gt_rows: dict = {}
        self._fp_rows: dict = {}
        for row in doc.get("ledger") or []:
            if not isinstance(row, dict) or "tool" not in row:
                raise BenchmarkError("every ledger row must be an object with a 'tool'")
            if row.get("kind") == "fp":
                self._fp_rows.setdefault(row["tool"], []).append(row)
            else:
                self._gt_rows.setdefault(row["tool"], []).append(row)
        self._cache: dict = {}
        self._answers: dict = {}

    @classmethod
    def load(cls, path: Union[str, Path]) -> "Reliability":
        p = Path(path)
        if p.is_dir():
            for name in ("scorecard.json", "priors.json"):
                if (p / name).is_file():
                    p = p / name
                    break
            else:
                raise BenchmarkError(f"{path}: no scorecard.json or priors.json")
        doc, digest = _read_json(p)
        return cls(doc, digest=digest, path=str(p))

    # ------------------------------------------------------------------ tools
    @property
    def has_ledger(self) -> bool:
        return bool(self._gt_rows)

    @property
    def run_id(self) -> Optional[str]:
        return (self.doc.get("run") or {}).get("id")

    def tool_ids(self) -> list:
        return sorted(set(self.tools) | set(self.scores) | set(self._gt_rows))

    def knows(self, tool: Optional[str]) -> bool:
        return bool(tool) and tool in self.tool_ids()

    def version_of(self, tool: str) -> Optional[str]:
        t = self.tools.get(tool) or {}
        return t.get("version") or t.get("tag")

    def versions(self, tool: str) -> set:
        """Every version string under which the benchmarked build of ``tool`` is known."""
        t = self.tools.get(tool) or {}
        return {v for v in (t.get("version"), t.get("tag"), (t.get("reported") or {}).get("version")) if v}

    def gt_rows(self, tool: str) -> list:
        return self._gt_rows.get(tool, [])

    def fp_rows(self, tool: str) -> list:
        return self._fp_rows.get(tool, [])

    # ------------------------------------------------------------------ scores
    def category_score(self, tool: str, facets: dict) -> Optional[dict]:
        key = (tool, category_key(facets))
        if key in self._cache:
            return self._cache[key]
        if self.has_ledger:
            rows = [r for r in self.gt_rows(tool) if row_matches(r, facets)]
            fps = [r for r in self.fp_rows(tool) if fp_matches(r, facets)]
            result = category_score(rows, fps, self.weights)
        else:
            tool_scores = self.scores.get(tool) or {}
            if not facets:
                result = tool_scores.get("overall")
            else:
                result = (tool_scores.get("byCategory") or {}).get(category_key(facets))
        self._cache[key] = result
        return result

    def head_to_head(self, tool_a: str, tool_b: str, facets: dict) -> dict:
        if self.has_ledger:
            return head_to_head(self.gt_rows(tool_a), self.gt_rows(tool_b), facets)
        key, swapped = pair_key(tool_a, tool_b)
        table = (self.pairwise.get(key) or {}).get(category_key(facets)) or {}
        return {attr: (swap_counts(c) if swapped else c) for attr, c in table.items()}

    def backoff_chain(self, facets: dict) -> list:
        chain = [dict(facets)]
        current = dict(facets)
        for facet in self.backoff_order:
            if facet in current:
                current = {k: v for k, v in current.items() if k != facet}
                chain.append(dict(current))
        if current:
            chain.append({})
        return chain

    # ------------------------------------------------------------------ reconciliation
    def reconcile(self, tool_a: str, tool_b: str, category: Union[dict, str, None] = None,
                  attribute: Optional[str] = None, value_a=None, value_b=None) -> Reconciliation:
        """Port of ``orchestrator.reconcile.Scorecard.reconcile`` (scoring model 1.0)."""
        facets = parse_category(category) if isinstance(category, str) else dict(category or {})
        attribute = normalize_attribute_name(attribute)
        cfg = self.scoring_cfg
        min_support = int(cfg.get("min_support", 5))
        min_h2h = int(cfg.get("min_support_head_to_head", 3))
        decay = float(cfg.get("backoff_relevance_decay", 0.15))
        undecided_below = float(cfg.get("undecided_below", 0.6))
        chain = self.backoff_chain(facets)
        explanation: list = []
        versions = {tool_a: self.version_of(tool_a), tool_b: self.version_of(tool_b)}

        def finish(tier: str, p: float, used: dict, steps: int, support: dict) -> Reconciliation:
            relevance = 1.0 / (1.0 + decay * steps)
            p_adj = 0.5 + (p - 0.5) * relevance
            confidence = max(p_adj, 1.0 - p_adj)
            if p_adj >= undecided_below:
                decision, preferred = "prefer-a", tool_a
            elif (1.0 - p_adj) >= undecided_below:
                decision, preferred = "prefer-b", tool_b
            else:
                decision, preferred = "undecided", None
            if steps:
                explanation.append(f"backed off {steps} facet(s) from {category_key(facets)} to {category_key(used)}; "
                                   f"relevance {relevance:.2f}")
            explanation.append(f"P({tool_a} more reliable) = {p_adj:.3f} -> {decision}")
            return Reconciliation(tool_a, tool_b, attribute, facets, used, steps, tier, p_adj, relevance, confidence,
                                  decision, preferred, {tool_a: p_adj, tool_b: 1.0 - p_adj}, support, versions,
                                  explanation)

        # missing-vs-present is a completeness question, not a conflict
        a_missing = value_a in (None, "", [], {}) and value_b not in (None, "", [], {}) and value_b is not None
        b_missing = value_b in (None, "", [], {}) and value_a not in (None, "", [], {}) and value_a is not None
        if attribute and (a_missing or b_missing):
            present, other = (tool_b, tool_a) if a_missing else (tool_a, tool_b)
            for steps, used in enumerate(chain):
                corr, n = attribute_evidence([r for r in self.gt_rows(present) if row_matches(r, used)], attribute)
                if n >= min_support or used == {}:
                    a, b = posterior(corr, n)
                    rate = a / (a + b)
                    p = rate if present == tool_a else 1.0 - rate
                    explanation.append(f"{other} reported no value; {present} reports {attribute} correctly "
                                       f"{corr:.1f}/{n} times in {category_key(used)}")
                    return finish("completeness", p, used, steps, {present: {"correct": round(corr, 2), "reported": n}})

        # tier 1: head-to-head
        attr_key = attribute or "*"
        for steps, used in enumerate(chain):
            counts = self.head_to_head(tool_a, tool_b, used).get(attr_key)
            if not counts:
                continue
            n = counts["aWins"] + counts["bWins"]
            if n >= min_h2h:
                a, b = posterior(counts["aWins"], n)
                p = prob_above_half(a, b)
                explanation.append(f"head-to-head on {attr_key} in {category_key(used)}: {tool_a} right "
                                   f"{counts['aWins']}x, {tool_b} right {counts['bWins']}x, both wrong "
                                   f"{counts['bothWrong']}x, agreed {counts['agree']}x")
                return finish("head-to-head", p, used, steps, {"disagreements": n, "counts": counts})

        # tier 2: independent attribute correctness
        if attribute:
            for steps, used in enumerate(chain):
                ca, na = attribute_evidence([r for r in self.gt_rows(tool_a) if row_matches(r, used)], attribute)
                cb, nb = attribute_evidence([r for r in self.gt_rows(tool_b) if row_matches(r, used)], attribute)
                if (na >= min_support and nb >= min_support) or (used == {} and (na or nb)):
                    pa = posterior(ca, na)
                    pb = posterior(cb, nb)
                    p = prob_greater(pa[0], pa[1], pb[0], pb[1])
                    explanation.append(f"{attribute} correctness in {category_key(used)}: {tool_a} {ca:.1f}/{na}, "
                                       f"{tool_b} {cb:.1f}/{nb}")
                    return finish("attribute", p, used, steps,
                                  {tool_a: {"correct": round(ca, 2), "reported": na},
                                   tool_b: {"correct": round(cb, 2), "reported": nb}})

        # tier 3 / 4: composite category score, then global
        for steps, used in enumerate(chain):
            sa, sb = self.category_score(tool_a, used), self.category_score(tool_b, used)
            if not sa or not sb:
                continue
            na, nb = sa.get("support", 0), sb.get("support", 0)
            if sa.get("score") is None or sb.get("score") is None:
                continue
            if (na >= min_support and nb >= min_support) or used == {}:
                pa = posterior(sa["score"] * na, na)
                pb = posterior(sb["score"] * nb, nb)
                p = prob_greater(pa[0], pa[1], pb[0], pb[1]) if (na and nb) else 0.5
                tier = "global" if used == {} else "category"
                explanation.append(f"composite score in {category_key(used)}: {tool_a} {sa['score']:.3f} (n={na}), "
                                   f"{tool_b} {sb['score']:.3f} (n={nb})")
                return finish(tier, p, used, steps, {tool_a: {"score": sa["score"], "support": na},
                                                      tool_b: {"score": sb["score"], "support": nb}})
        explanation.append("no evidence for either tool")
        return finish("none", 0.5, {}, len(chain) - 1, {})

    def answer(self, tool_a: str, tool_b: str, facets: dict, attribute: Optional[str]) -> Reconciliation:
        """Cached :meth:`reconcile` for a conflict between two present values (tools in canonical order)."""
        if tool_b < tool_a:
            tool_a, tool_b = tool_b, tool_a
        key = (tool_a, tool_b, category_key(facets), attribute)
        r = self._answers.get(key)
        if r is None:
            r = self._answers[key] = self.reconcile(tool_a, tool_b, facets, attribute)
        return r


# --------------------------------------------------------------------------- #
# the benchmark as a whole
# --------------------------------------------------------------------------- #
def validate_tool_profiles(doc: dict, what: str = "tool profile") -> None:
    """Check a ``tools.json`` document (2CBOM knowledge-base schema, optionally with orchestrator extras)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("tools"), dict):
        raise BenchmarkError(f"{what}: expected an object with a 'tools' object")
    _check_scoring_model(doc, what, required=False)
    for tid, spec in doc["tools"].items():
        if not isinstance(spec, dict):
            raise BenchmarkError(f"{what}: tool {tid!r} must be an object")
        trust = spec.get("trust")
        if not isinstance(trust, int) or isinstance(trust, bool) or not 0 <= trust <= 100:
            raise BenchmarkError(f"{what}: tool {tid!r} needs an integer trust in [0, 100], got {trust!r}")
        method = spec.get("detectionMethod", "unknown")
        if method not in DETECTION_METHODS:
            raise BenchmarkError(f"{what}: tool {tid!r} has detection method {method!r} outside {list(DETECTION_METHODS)}")
        for key in ("aliases", "strengths"):
            v = spec.get(key, [])
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise BenchmarkError(f"{what}: tool {tid!r} member {key!r} must be a list of strings")


def _clean(d: dict) -> dict:
    return {k: v for k, v in d.items() if v not in (None, "", [], {})}


class Benchmark:
    """An orchestrator run as seen by 2CBOM: a tool profile overlay, reliability priors, or both."""

    def __init__(self, tool_profiles: Optional[dict] = None, reliability: Optional[Reliability] = None, *,
                 tool_profiles_digest: Optional[str] = None, tool_profiles_path: Optional[str] = None):
        if tool_profiles is None and reliability is None:
            raise BenchmarkError("a benchmark needs a tool profile (twocbom/tools.json), priors "
                                 "(scorecard.json / priors.json) or both")
        if tool_profiles is not None:
            validate_tool_profiles(tool_profiles, tool_profiles_path or "tool profile")
        self.tool_profiles = tool_profiles
        self.tool_profiles_path = tool_profiles_path
        self.tool_profiles_digest = (tool_profiles_digest or content_digest(tool_profiles)) if tool_profiles is not None else None
        self.reliability = reliability
        versions = {v for v in ((tool_profiles or {}).get("scoringModelVersion"),
                                reliability.scoring_model_version if reliability else None) if v}
        if len(versions) > 1:
            raise BenchmarkError(f"the tool profile and the priors use different scoring models: {sorted(versions)}")
        self.scoring_model_version = next(iter(versions), None)
        ident = "|".join((self.tool_profiles_digest or "", reliability.digest if reliability else ""))
        self.digest = "sha256:" + hashlib.sha256(ident.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------ queries
    def tool_profile_overlay(self) -> Optional[dict]:
        return self.tool_profiles

    def benchmarked_versions(self, tool: str) -> set:
        """Versions under which ``tool`` was measured (release, tag and self-reported), normalised."""
        found = set()
        spec = ((self.tool_profiles or {}).get("tools") or {}).get(tool) or {}
        b = spec.get("benchmark") or {}
        for v in (b.get("version"), b.get("tag"), b.get("reportedVersion")):
            if v:
                found.add(str(v))
        if self.reliability is not None:
            found |= {str(v) for v in self.reliability.versions(tool)}
        return {normalize_version(v) for v in found}

    def is_benchmarked(self, tool: str) -> bool:
        return tool in ((self.tool_profiles or {}).get("tools") or {}) or bool(self.reliability and self.reliability.knows(tool))

    # ------------------------------------------------------------------ lineage
    def lineage(self) -> dict:
        out: dict = {}
        if self.scoring_model_version:
            out["scoringModelVersion"] = self.scoring_model_version
        if self.tool_profiles is not None:
            tp = self.tool_profiles
            tools = {}
            for tid, spec in sorted(tp["tools"].items()):
                b = spec.get("benchmark") or {}
                tools[tid] = _clean({
                    "trust": spec["trust"], "strengths": sorted(spec.get("strengths") or []),
                    "detectionMethod": spec.get("detectionMethod"),
                    "version": b.get("version"), "tag": b.get("tag"), "commit": b.get("commit"),
                    "imageDigest": b.get("imageDigest"), "reportedVersion": b.get("reportedVersion"),
                })
            out["toolProfiles"] = _clean({
                "version": tp.get("version"), "generated": tp.get("generated"), "digest": self.tool_profiles_digest,
                "baseline": _clean(tp.get("baseline") or {}), "tools": tools,
            })
        if self.reliability is not None:
            r = self.reliability
            base = r.doc.get("baseline") or {}
            run = r.doc.get("run") or {}
            tools = {}
            for tid in r.tool_ids():
                t = r.tools.get(tid) or {}
                tools[tid] = _clean({"version": t.get("version"), "tag": t.get("tag"), "commit": t.get("commit"),
                                     "imageDigest": t.get("image_digest"),
                                     "reportedVersion": (t.get("reported") or {}).get("version")})
            cfg = r.scoring_cfg
            out["priors"] = _clean({
                "run": run.get("id"), "generated": run.get("finishedAt") or run.get("startedAt"), "digest": r.digest,
                "ledger": r.has_ledger,
                "baseline": _clean({"repo": base.get("repo"), "commit": base.get("evaluatedCommit") or base.get("commit"),
                                    "ref": base.get("ref")}),
                "tools": tools,
            })
            out["settlement"] = {
                "rule": "reconcile, scalar fallback",
                "undecidedBelow": _num(float(cfg.get("undecided_below", 0.6))),
                "backoffRelevanceDecay": _num(float(cfg.get("backoff_relevance_decay", 0.15))),
                "minSupport": int(cfg.get("min_support", 5)),
                "minSupportHeadToHead": int(cfg.get("min_support_head_to_head", 3)),
            }
        return out

    def summary(self) -> str:
        lines = []
        if self.tool_profiles is not None:
            tp = self.tool_profiles
            lines.append(f"tool profile {tp.get('version', 'unknown')} ({self.tool_profiles_path or 'in memory'}), "
                         f"scoring model {tp.get('scoringModelVersion', 'n/a')}")
            for tid, spec in sorted(tp["tools"].items()):
                b = spec.get("benchmark") or {}
                lines.append(f"  {tid:<18} trust {spec['trust']:>3}  {b.get('version') or '-':<12} "
                             f"strengths: {', '.join(spec.get('strengths') or []) or '-'}")
        if self.reliability is not None:
            r = self.reliability
            lines.append(f"priors run {r.run_id or 'unknown'} ({r.path or 'in memory'}), scoring model "
                         f"{r.scoring_model_version}, ledger {'included' if r.has_ledger else 'not included'}")
            for tid in r.tool_ids():
                lines.append(f"  {tid:<18} {r.version_of(tid) or '-'}")
        return "\n".join(lines)


def normalize_version(v: str) -> str:
    v = str(v).strip().lower()
    return v[1:] if v.startswith("v") and v[1:2].isdigit() else v


def _num(x):
    """Numbers as 2CBOM documents carry them: integers, or decimals with at most four digits."""
    if isinstance(x, bool) or x is None:
        return x
    if isinstance(x, float):
        x = round(x, 4)
        return int(x) if x.is_integer() else x
    if isinstance(x, dict):
        return {k: _num(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_num(v) for v in x]
    return x


def _looks_like_priors(doc: dict) -> bool:
    return any(k in doc for k in ("ledger", "scores", "pairwise")) and "scoringModelVersion" in doc


def _looks_like_tool_profiles(doc: dict) -> bool:
    tools = doc.get("tools")
    return isinstance(tools, dict) and "default" in doc and all(isinstance(v, dict) and "trust" in v for v in tools.values())


def load_benchmark(path: Union[str, Path, None] = None, *, tool_profiles: Union[str, Path, None] = None,
                   priors: Union[str, Path, None] = None) -> Benchmark:
    """Load an orchestrator run.

    ``path`` may be a run directory (``twocbom/tools.json`` plus ``scorecard.json`` or ``priors.json``),
    its ``twocbom/`` export directory (``tools.json`` plus ``priors.json``) or a single file of either
    kind.  ``tool_profiles`` and ``priors`` name the files explicitly and take precedence.
    """
    tp_path = Path(tool_profiles) if tool_profiles else None
    pr_path = Path(priors) if priors else None
    if path is not None:
        p = Path(path)
        if p.is_dir():
            if tp_path is None:
                tp_path = next((c for c in (p / "twocbom" / "tools.json", p / "tools.json") if c.is_file()), None)
            if pr_path is None:
                pr_path = next((c for c in (p / "scorecard.json", p / "priors.json", p / "twocbom" / "priors.json")
                                if c.is_file()), None)
            if tp_path is None and pr_path is None:
                raise BenchmarkError(f"{p}: no twocbom/tools.json, scorecard.json or priors.json in this directory")
        elif p.is_file():
            doc, _ = _read_json(p)
            if _looks_like_priors(doc):
                pr_path = pr_path or p
            elif _looks_like_tool_profiles(doc):
                tp_path = tp_path or p
            else:
                raise BenchmarkError(f"{p}: neither an orchestrator scorecard/priors file nor a tool profile")
        else:
            raise BenchmarkError(f"{p}: no such file or directory")
    tp_doc = tp_digest = None
    if tp_path is not None:
        tp_doc, tp_digest = _read_json(tp_path)
    reliability = Reliability.load(pr_path) if pr_path is not None else None
    return Benchmark(tp_doc, reliability, tool_profiles_digest=tp_digest,
                     tool_profiles_path=str(tp_path) if tp_path is not None else None)


# --------------------------------------------------------------------------- #
# registry: the rules find the active benchmark through the Config fact
# --------------------------------------------------------------------------- #
_ACTIVE: "weakref.WeakValueDictionary[str, Benchmark]" = weakref.WeakValueDictionary()


def register(benchmark: Benchmark) -> str:
    """Make ``benchmark`` reachable from rules by its digest (held only as long as the caller holds it)."""
    _ACTIVE[benchmark.digest] = benchmark
    return benchmark.digest


def lookup(digest: Optional[str]) -> Optional[Benchmark]:
    if not digest:
        return None
    b = _ACTIVE.get(digest)
    if b is None:
        raise BenchmarkError(f"benchmark {digest} is not registered; pass it through MergeOptions.benchmark")
    return b


# --------------------------------------------------------------------------- #
# vocabulary bridges between 2CBOM facts and benchmark categories
# --------------------------------------------------------------------------- #
def benchmark_family(family: Optional[str]) -> Optional[str]:
    if not family:
        return None
    return FAMILY_TO_BENCHMARK.get(family, family)


def language_of_location(location: Optional[str]) -> Optional[str]:
    if not location:
        return None
    name = location.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in name:
        return None
    return LANGUAGE_BY_EXTENSION.get("." + name.rsplit(".", 1)[-1].lower())


def purl_family(purl: Optional[str]) -> Optional[str]:
    """``pkg:pypi/cryptography@41.0.0`` -> ``pypi/cryptography`` (the orchestrator's library family)."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    body = body.split("@", 1)[0]
    return body.lower() or None


def document_number(x):
    return _num(x)
