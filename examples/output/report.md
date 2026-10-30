# 2CBOM report (strict profile)

- Serial number: `urn:uuid:93964e46-d4b1-5ee8-a7b4-c4a6034a2e98`
- Digest: `sha256:0e0e5f0828454a5b48fb32a1ea9ea5770da024a7cf2d74493fce8d3ab05fdf42`
- Generated: 2026-10-29T00:00:00Z by twocbom 1.0.0
- Conformant: **yes** (0 errors, 16 warnings, 21 infos)
- Assets: 27 | Components: 7 | Relations: 59

## Sources

| id | tool | format | spec | trust | assets | digest |
|---|---|---|---|---|---|---|
| src-2362e304470a | cdxgen 11.4.0 | cyclonedx-json | 1.6 | 70 | 7 | `sha256:2362e304470a0b1e…` |
| src-36d615754603 | cbomkit 2.1.0 | cyclonedx-json | 1.6 | 80 | 6 | `sha256:36d615754603c610…` |
| src-6b22f6d672d9 | ibm-cbom 0.9.3 | ibm-cbom-json | 1.4-cbom-1.0 | 60 | 5 | `sha256:6b22f6d672d965dc…` |
| src-e275c2b5f4f5 | cbomkit-theia 1.3.0 | cyclonedx-json | 1.7 | 75 | 8 | `sha256:e275c2b5f4f5fca7…` |
| src-e5fc2a359bba | cryptobom-forge 1.2.0 | cyclonedx-json | 1.6 | 65 | 4 | `sha256:e5fc2a359bba31f4…` |

## Post-quantum readiness

| quantum class | assets |  | migration priority | assets |
|---|---|---|---|---|
| classically-weak | 4 |  | immediate | 4 |
| quantum-vulnerable | 12 |  | high | 8 |
| unknown | 0 |  | medium | 4 |
| quantum-safe | 11 |  | low | 8 |
|  |  |  | none | 3 |
|  |  |  | unknown | 0 |

## Assets

| id | type | quantum class | NIST IR 8547 | NIST cat. | classical bits | CNSA 2.0 | priority | sources | evidence |
|---|---|---|---|---|---|---|---|---|---|
| `2cbom:alg:aes-128-gcm` | algorithm | quantum-safe | acceptable | 1 | 128 | no | low | 3 | 4 |
| `2cbom:alg:aes-256-cbc-pkcs7` | algorithm | quantum-safe | acceptable | 5 | 256 | yes | none | 1 | 1 |
| `2cbom:alg:aes-256-gcm` | algorithm | quantum-safe | acceptable | 5 | 256 | yes | none | 2 | 2 |
| `2cbom:alg:chacha20-poly1305` | algorithm | quantum-safe | acceptable | 5 | 256 | no | low | 1 | 1 |
| `2cbom:alg:des-cbc` | algorithm | classically-weak | disallowed | 0 | 56 | no | immediate | 1 | 1 |
| `2cbom:alg:ecdh` | algorithm | quantum-vulnerable | disallowed-after-2035 | - | - | no | high | 1 | 1 |
| `2cbom:alg:ecdsa-p256-sha2-256` | algorithm | quantum-vulnerable | disallowed-after-2035 | 0 | 128 | no | medium | 1 | 1 |
| `2cbom:alg:hmac-sha2-256` | algorithm | quantum-safe | acceptable | 2 | 128 | no | low | 1 | 1 |
| `2cbom:alg:ml-dsa-65` | algorithm | quantum-safe | acceptable | 3 | 192 | no | low | 1 | 1 |
| `2cbom:alg:ml-kem-768` | algorithm | quantum-safe | acceptable | 3 | 192 | no | low | 1 | 2 |
| `2cbom:alg:pbkdf2-sha2-256` | algorithm | quantum-safe | acceptable | 2 | 128 | no | low | 1 | 1 |
| `2cbom:alg:rsa` | algorithm | quantum-vulnerable | disallowed-after-2035 | - | - | no | high | 1 | 1 |
| `2cbom:alg:rsa-2048` | algorithm | quantum-vulnerable | deprecated-after-2030 | 0 | 112 | no | high | 3 | 3 |
| `2cbom:alg:rsa-2048-oaep` | algorithm | quantum-vulnerable | deprecated-after-2030 | 0 | 112 | no | high | 2 | 3 |
| `2cbom:alg:rsa-pkcs1v15-sha2-256` | algorithm | quantum-vulnerable | deprecated-after-2030 | 0 | 112 | no | medium | 4 | 4 |
| `2cbom:alg:sha1` | algorithm | classically-weak | disallowed | 0 | 80 | no | immediate | 2 | 2 |
| `2cbom:alg:sha2-256` | algorithm | quantum-safe | acceptable | 2 | 128 | no | low | 3 | 4 |
| `2cbom:alg:sha2-384` | algorithm | quantum-safe | acceptable | 4 | 192 | yes | none | 2 | 2 |
| `2cbom:alg:tdea-cbc` | algorithm | classically-weak | disallowed | 0 | 112 | no | immediate | 1 | 1 |
| `2cbom:alg:x25519` | algorithm | quantum-vulnerable | disallowed-after-2035 | 0 | 128 | no | high | 1 | 1 |
| `2cbom:alg:x25519+ml-kem-768` | algorithm | quantum-safe | acceptable | 3 | 128 | no | low | 1 | 1 |
| `2cbom:cert:fp:sha256:8f434346648f6b96df89dda901c5176b10a6...` | certificate | quantum-vulnerable | deprecated-after-2030 | 0 | 112 | no | medium | 2 | 2 |
| `2cbom:key:private-key:loc:9940fc91b8e14941fd22aabf` | related-crypto-material | quantum-vulnerable | deprecated-after-2030 | 0 | 112 | no | high | 1 | 1 |
| `2cbom:key:private-key:loc:e22a1f2a68d7ffddd2733622` | related-crypto-material | quantum-vulnerable | deprecated-after-2030 | 0 | 112 | no | high | 1 | 1 |
| `2cbom:key:public-key:loc:37fffc6fd0dfba644509ea11` | related-crypto-material | quantum-vulnerable | deprecated-after-2030 | 0 | 112 | no | high | 1 | 1 |
| `2cbom:proto:tls-1.2` | protocol | classically-weak | disallowed | 0 | 80 | no | immediate | 2 | 3 |
| `2cbom:proto:tls-1.3` | protocol | quantum-vulnerable | deprecated-after-2030 | 0 | 112 | no | medium | 2 | 2 |

## Findings

- **warning** `2CBOM-C02-EVIDENCE-UNLOCATED` `2cbom:alg:aes-256-gcm`: asset is only derived; no occurrence location recorded
- **warning** `2CBOM-C02-EVIDENCE-UNLOCATED` `2cbom:alg:chacha20-poly1305`: asset is only derived; no occurrence location recorded
- **warning** `2CBOM-C02-EVIDENCE-UNLOCATED` `2cbom:alg:ecdh`: asset is only derived; no occurrence location recorded
- **warning** `2CBOM-C02-EVIDENCE-UNLOCATED` `2cbom:alg:rsa`: asset is only derived; no occurrence location recorded
- **warning** `2CBOM-C02-EVIDENCE-UNLOCATED` `2cbom:alg:sha2-384`: asset is only derived; no occurrence location recorded
- **warning** `2CBOM-C02-EVIDENCE-UNLOCATED` `2cbom:alg:tdea-cbc`: asset is only derived; no occurrence location recorded
- **warning** `2CBOM-C02-EVIDENCE-UNLOCATED` `2cbom:alg:x25519`: asset is only derived; no occurrence location recorded
- **warning** `2CBOM-C10-PARAMETER-SET-MISSING` `2cbom:alg:ecdh`: missing curve for family 'ecdh'; security level cannot be derived
- **warning** `2CBOM-C10-PARAMETER-SET-MISSING` `2cbom:alg:rsa`: missing parameterSet for family 'rsa'; security level cannot be derived
- **warning** `2CBOM-C15-WEAK-IDENTITY` `2cbom:key:private-key:loc:9940fc91b8e14941fd22aabf`: identity derived from location; occurrences from other sources may not merge
- **warning** `2CBOM-C15-WEAK-IDENTITY` `2cbom:key:private-key:loc:e22a1f2a68d7ffddd2733622`: identity derived from location; occurrences from other sources may not merge
- **warning** `2CBOM-C15-WEAK-IDENTITY` `2cbom:key:public-key:loc:37fffc6fd0dfba644509ea11`: identity derived from location; occurrences from other sources may not merge
- **warning** `2CBOM-P01-CLASSICALLY-WEAK` `2cbom:alg:des-cbc`: classically weak: replace now (catalogue family 'des': classically-weak; classical strength 56 bits is below the 112-bit floor)
- **warning** `2CBOM-P01-CLASSICALLY-WEAK` `2cbom:alg:sha1`: classically weak: replace now (catalogue family 'sha1': classically-weak; classical strength 80 bits is below the 112-bit floor)
- **warning** `2CBOM-P01-CLASSICALLY-WEAK` `2cbom:alg:tdea-cbc`: classically weak: replace now (catalogue family 'tdea': classically-weak; 64-bit block (Sweet32); encryption disallowed by NIST after 2023.)
- **warning** `2CBOM-P01-CLASSICALLY-WEAK` `2cbom:proto:tls-1.2`: classically weak: replace now (suite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: quantum-vulnerable; suite TLS_RSA_WITH_3DES_EDE_CBC_SHA: classically-weak)

<details><summary>21 informational findings</summary>

- `2CBOM-C14-SOURCE-CONFLICT` `2cbom:alg:aes-128-gcm`: toolPrimitive: sources disagree (src-e5fc2a359bba='block-cipher'); chose 'ae' by precedence
- `2CBOM-C14-SOURCE-CONFLICT` `2cbom:cert:fp:sha256:8f434346648f6b96df89dda901...`: issuerName: sources disagree (src-6b22f6d672d9='CN=Example Issuing CA, O=Example Corp, C=CA'); chose 'CN=Example Issuing CA,O=Example Corp,C=CA' by precedence
- `2CBOM-C14-SOURCE-CONFLICT` `2cbom:cert:fp:sha256:8f434346648f6b96df89dda901...`: subjectName: sources disagree (src-6b22f6d672d9='CN=api.payments.example.com, O=Example Corp, C=CA'); chose 'CN=api.payments.example.com,O=Example Corp,C=CA' by precedence
- `2CBOM-C16-PRESTANDARD-NAME` `2cbom:alg:ml-dsa-65`: pre-standard names ['Dilithium3'] mapped to 2cbom:alg:ml-dsa-65
- `2CBOM-C17-SPEC-VERSION-NONSTANDARD` `src-6b22f6d672d9`: pre-standard IBM CBOM (specVersion 1.4-cbom-1.0) lifted to the CycloneDX 1.6 model
- `2CBOM-I01-SUBSUMED` `2cbom:alg:aes-128-gcm`: detection 'forge-1' (AES) from src-e5fc2a359bba absorbed into 2cbom:alg:aes-128-gcm (same location)
- `2CBOM-I01-SUBSUMED` `2cbom:alg:rsa-2048-oaep`: detection 'ibm-rsa' (RSA-2048) from src-6b22f6d672d9 absorbed into 2cbom:alg:rsa-2048-oaep (same location)
- `2CBOM-I01-SUBSUMED` `2cbom:alg:rsa-pkcs1v15-sha2-256`: detection 'forge-3' (RSA) from src-e5fc2a359bba absorbed into 2cbom:alg:rsa-pkcs1v15-sha2-256 (same location)
- `2CBOM-I01-SUBSUMED` `2cbom:cert:fp:sha256:8f434346648f6b96df89dda901...`: detection 'ibm-cert' (server.crt) from src-6b22f6d672d9 absorbed into 2cbom:cert:fp:sha256:8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4 (same location)
- `2CBOM-P02-QUANTUM-VULNERABLE` `2cbom:alg:ecdh`: quantum-vulnerable; NIST IR 8547: disallowed-after-2035; migration priority high
- `2CBOM-P02-QUANTUM-VULNERABLE` `2cbom:alg:ecdsa-p256-sha2-256`: quantum-vulnerable; NIST IR 8547: disallowed-after-2035; migration priority medium
- `2CBOM-P02-QUANTUM-VULNERABLE` `2cbom:alg:rsa`: quantum-vulnerable; NIST IR 8547: disallowed-after-2035; migration priority high
- `2CBOM-P02-QUANTUM-VULNERABLE` `2cbom:alg:rsa-2048`: quantum-vulnerable; NIST IR 8547: deprecated-after-2030; migration priority high
- `2CBOM-P02-QUANTUM-VULNERABLE` `2cbom:alg:rsa-2048-oaep`: quantum-vulnerable; NIST IR 8547: deprecated-after-2030; migration priority high
- `2CBOM-P02-QUANTUM-VULNERABLE` `2cbom:alg:rsa-pkcs1v15-sha2-256`: quantum-vulnerable; NIST IR 8547: deprecated-after-2030; migration priority medium
- `2CBOM-P02-QUANTUM-VULNERABLE` `2cbom:alg:x25519`: quantum-vulnerable; NIST IR 8547: disallowed-after-2035; migration priority high
- `2CBOM-P02-QUANTUM-VULNERABLE` `2cbom:cert:fp:sha256:8f434346648f6b96df89dda901...`: quantum-vulnerable; NIST IR 8547: deprecated-after-2030; migration priority medium
- `2CBOM-P02-QUANTUM-VULNERABLE` `2cbom:key:private-key:loc:9940fc91b8e14941fd22aabf`: quantum-vulnerable; NIST IR 8547: deprecated-after-2030; migration priority high
- `2CBOM-P02-QUANTUM-VULNERABLE` `2cbom:key:private-key:loc:e22a1f2a68d7ffddd2733622`: quantum-vulnerable; NIST IR 8547: deprecated-after-2030; migration priority high
- `2CBOM-P02-QUANTUM-VULNERABLE` `2cbom:key:public-key:loc:37fffc6fd0dfba644509ea11`: quantum-vulnerable; NIST IR 8547: deprecated-after-2030; migration priority high
- `2CBOM-P02-QUANTUM-VULNERABLE` `2cbom:proto:tls-1.3`: quantum-vulnerable; NIST IR 8547: deprecated-after-2030; migration priority medium

</details>

## Resolved conflicts

- `2cbom:alg:aes-128-gcm`.toolPrimitive → `'ae'` (settle.tool-precedence); candidates: src-36d615754603='ae'; src-e5fc2a359bba='block-cipher'; src-6b22f6d672d9='ae'
- `2cbom:cert:fp:sha256:8f434346648f6b96df89dda901...`.issuerName → `'CN=Example Issuing CA,O=Example Corp,C=CA'` (settle.tool-precedence); candidates: src-e275c2b5f4f5='CN=Example Issuing CA,O=Example Corp,C=CA'; src-6b22f6d672d9='CN=Example Issuing CA, O=Example Corp, C=CA'
- `2cbom:cert:fp:sha256:8f434346648f6b96df89dda901...`.subjectName → `'CN=api.payments.example.com,O=Example Corp,C=CA'` (settle.tool-precedence); candidates: src-e275c2b5f4f5='CN=api.payments.example.com,O=Example Corp,C=CA'; src-6b22f6d672d9='CN=api.payments.example.com, O=Example Corp, C=CA'
