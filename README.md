# twocbom — Canonical Cryptography Bill of Materials (2CBOM)

`twocbom` is the reference implementation of the **2CBOM** model (see
`spec/2cbom-standard.tex`) and a **rule-based expert system** that merges the
CBOMs produced by heterogeneous generators — CycloneDX 1.5/1.6/1.7 documents
from CBOMkit, cdxgen, cryptobom-forge, cbomkit-theia, … and pre-standard IBM
`1.4-cbom-1.0` documents — into one canonical, deterministic, conformance-checked
2CBOM document suitable for post-quantum-cryptography (PQC) compliance work.

Pure Python 3.10+, no runtime dependencies (`jsonschema` is optional).

```
pip install -e ".[dev]"
python -m pytest -q                      # 124 tests
twocbom merge examples/*.json -o merged.2cbom.json --cyclonedx merged.cdx.json --report report.md --trace trace.json
twocbom validate merged.2cbom.json
twocbom explain trace.json 2cbom:alg:x25519+ml-kem-768
twocbom canon "AES/GCM/NoPadding" "SHA256withRSA" "Kyber768" "0x1301"
twocbom inspect examples/ibm-prestandard-cbom14.json
twocbom rules
twocbom schema > twocbom-1.0.schema.json
```

## What problem it solves

CBOM generators disagree on *names* (`AES128-GCM`, `AES/GCM/NoPadding`,
`aes-128-gcm`, `2.16.840.1.101.3.4.1.6`), on *structure* (CycloneDX 1.6
`cryptographic-asset` vs. IBM `crypto-asset`, `evidence.occurrences` vs.
`detectionContext`, kebab-case vs. camelCase enumerations), on *completeness*
(one tool sees the key size, another the mode, a third only "AES"), and on
*assessment* (security levels copied from different tables). A compliance
inventory built on such inputs is neither reproducible nor auditable.

2CBOM fixes this with three ideas, all formalised in the specification:

1. **Canonical identity.** A deterministic naming grammar maps every spelling
   of an algorithm to one identifier (`2cbom:alg:rsa-pkcs1v15-sha2-256`);
   certificates, keys, protocols and software components get content-derived
   identifiers as well. Pre-standard names (Kyber, Dilithium, Falcon, SPHINCS+)
   are mapped to their FIPS names and recorded as aliases.
2. **Strict closure and assessment.** Every certificate links to its signature
   and key algorithms, every key to its algorithm, every protocol to the
   constituents of its cipher suites; every asset receives a determinate
   quantum class, NIST IR 8547 status, CNSA 2.0 and FIPS status and a
   migration priority. *Unknown is never upgraded to safe.*
3. **Order-free merge with provenance.** Inputs are turned into a set of
   provenance-tagged assertions; a monotonic forward-chaining rule engine
   computes the unique fixpoint; attributes are resolved by a total order
   (catalogue > derived > tool specificity > tool trust > confidence > value).
   The result is byte-identical for any input order (RFC 8785 canonical JSON,
   SHA-256 digest, UUIDv5 serial number) and every conflict is recorded.

## Architecture

```
inputs ──► ingest/            syntactic lifting to a format-agnostic IR
            cyclonedx.py       CycloneDX 1.5 / 1.6 / 1.7
            ibmcbom.py         IBM 1.4-cbom-1.0 (crypto-asset, detectionContext, dependencyType)
        ──► engine/            production system: typed facts, indexed working memory,
                               salience-ordered agenda, refraction, monotonic fixpoint, trace
        ──► rules/             the knowledge-driven rule base (45 rules, 7 phases)
            normalize.py  900  canonical identity candidates
            resolve.py    850  subsumption ("AES" @ line 42 ⊂ "aes-128-gcm" @ line 42); DN-cert ⊂ fingerprint-cert
                          800  materialisation, provenance-tagged attributes, evidence, typed relations
            closure.py    700  cert → signature/key algorithms, key → algorithm (+size refinement),
                               protocol → cipher-suite constituents, hybrid → constituents
            enrich.py     600  knowledge base: security levels, OIDs, standards, FIPS, CNSA 2.0
            settle.py     500  deterministic attribute resolution + conflict records
            assess.py     400  quantum class, IR 8547 timeline, migration priority (worst-of aggregation)
            check.py      300  conformance findings C1–C20, P1–P2 (profile-dependent severities)
        ──► merge.py           assembly, canonical serialisation, sealing (digest + serial number)
        ──► export/            CycloneDX 1.6 projection (lossy but conformant), Markdown report
        ──► validate.py        JSON Schema (generated from the closed vocabularies) + semantic checks
knowledge/                     declarative KB: catalogue.json (≈70 families, parameter sets, levels,
                               OIDs), aliases.json (lexicon), tools.json (trust profiles), policies.json
```

The engine is a classic expert-system architecture: facts are immutable
dataclasses in a set-semantics working memory; a rule is a condition generator
plus an action; on each cycle the highest-salience rule with unfired
activations fires all of them. Because actions only add facts, the computation
is a monotone fixpoint whose result does not depend on input order, which is
what makes the merge commutative, associative and idempotent (tested in
`tests/test_merge.py`). Every firing is logged, so `twocbom explain` can answer
*why* an asset was classified the way it was.

## Example

`examples/` contains five synthetic CBOMs of one fictitious payments service
scanned by five tools (CBOMkit, cdxgen, cryptobom-forge, an IBM pre-standard
scanner and a CycloneDX 1.7 container scanner). Merged under the strict profile
they yield 27 canonical assets from 30 raw detections, among them:

| canonical id | merged from | assessment |
|---|---|---|
| `2cbom:alg:aes-128-gcm` | `AES128-GCM` (CBOMkit), `AES-128-GCM` (IBM 1.4), `AES` (forge, subsumed by location) | quantum-safe, cat. 1, not CNSA 2.0 |
| `2cbom:alg:rsa-pkcs1v15-sha2-256` | `SHA256withRSA`, `RSA` (forge), `sha256WithRSAEncryption` (cert), OID `1.2.840.113549.1.1.11` | quantum-vulnerable, deprecated after 2030 |
| `2cbom:alg:ml-dsa-65` | `Dilithium3` | quantum-safe, cat. 3 |
| `2cbom:alg:x25519+ml-kem-768` | `X25519MLKEM768` (+ synthesised constituents) | quantum-safe hybrid |
| `2cbom:cert:fp:sha256:8f43…` | IBM (by DN) + 1.7 scanner (by fingerprint) | quantum-vulnerable (RSA) |
| `2cbom:proto:tls-1.2` | CBOMkit + IBM (suites decomposed to `tdea-cbc`, `sha1`, …) | classically weak (3DES/SHA-1 suite) |
| `2cbom:proto:tls-1.3` | cdxgen + 1.7 scanner (hybrid group + RSA certificate) | quantum-vulnerable (authentication) |

## Profiles and findings

* **core** — structural validity: identities resolved or flagged, evidence
  present, closed vocabularies, referential integrity, lineage.
* **strict** (PQC compliance) — additionally: no unresolved identities, no
  unknown assessments, parameter sets for all located detections, certificate
  and key closure. A document is conformant when it has no `error` findings.

Finding codes are stable (`2CBOM-C10-PARAMETER-SET-MISSING`, …) and listed in
the specification, Section 7.

## Positioning

The ingestion layer is designed to take per-tool outputs as produced by a CBOM
benchmarking harness, so the expert system can be used both to reconcile
production scans and to study generator disagreement on a benchmark corpus.

## Knowledge base caveats

The catalogue encodes NIST SP 800-57, the NIST PQC security categories, FIPS
203/204/205, SP 800-208, CNSA 2.0 and NIST IR 8547 as understood at the
knowledge-base date (`catalogue.json` → `version`). Entries carry a `note`
where a value is a conservative estimate (e.g. RSA-4096 → 128 bits) or where a
standard was not final. Review the catalogue before using the output as a
formal attestation; the whole point of the design is that every such decision
is a data item that can be audited and changed without touching code.

## Layout

```
twocbom/            package            spec/2cbom-standard.tex   formal specification (Overleaf-ready)
tests/              pytest suite       examples/                 five tool outputs of one application
twocbom/schema/     JSON Schema 1.0    pyproject.toml
```

Licence: Apache-2.0.
