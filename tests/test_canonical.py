import pytest

from twocbom.canonical import (AlgorithmDescriptor, certificate_id, component_id, digest, jcs_dumps,
                               normalize_location, parse_algorithm, parse_cipher_suite, stable_uuid)

CASES = [
    ("AES128-GCM", "aes-128-gcm", "ae"),
    ("aes-128-gcm", "aes-128-gcm", "ae"),
    ("AES/GCM/NoPadding", "aes-gcm", "ae"),
    ("AES/CBC/PKCS5Padding", "aes-cbc-pkcs5", "block-cipher"),
    ("AES-256-CBC", "aes-256-cbc", "block-cipher"),
    ("RSA-2048", "rsa-2048", "pke"),
    ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "rsa-oaep-sha2-256", "pke"),
    ("SHA256withRSA", "rsa-pkcs1v15-sha2-256", "signature"),
    ("sha256WithRSAEncryption", "rsa-pkcs1v15-sha2-256", "signature"),
    ("1.2.840.113549.1.1.11", "rsa-pkcs1v15-sha2-256", "signature"),
    ("SHA256withRSAandMGF1", "rsa-pss-sha2-256", "signature"),
    ("RSASSA-PSS", "rsa-pss", "signature"),
    ("rsaEncryption", "rsa", "pke"),
    ("SHA-256", "sha2-256", "hash"),
    ("sha256", "sha2-256", "hash"),
    ("SHA2-256", "sha2-256", "hash"),
    ("SHA-1", "sha1", "hash"),
    ("SHA3-256", "sha3-256", "hash"),
    ("SHAKE128", "shake-128", "xof"),
    ("SHA-512/256", "sha2-512-256", "hash"),
    ("HMAC-SHA256", "hmac-sha2-256", "mac"),
    ("HmacSHA256", "hmac-sha2-256", "mac"),
    ("PBKDF2WithHmacSHA256", "pbkdf2-sha2-256", "kdf"),
    ("HKDF-SHA384", "hkdf-sha2-384", "kdf"),
    ("ECDSA-P256", "ecdsa-p256", "signature"),
    ("ecdsa-with-SHA256", "ecdsa-sha2-256", "signature"),
    ("secp256r1", "ec-p256", "unknown"),
    ("ecPublicKey", "ec", "unknown"),
    ("X25519", "x25519", "key-agree"),
    ("Ed25519", "ed25519", "signature"),
    ("ML-KEM-768", "ml-kem-768", "kem"),
    ("Kyber768", "ml-kem-768", "kem"),
    ("ML-DSA-65", "ml-dsa-65", "signature"),
    ("Dilithium3", "ml-dsa-65", "signature"),
    ("Falcon-512", "fn-dsa-512", "signature"),
    ("SLH-DSA-SHA2-128s", "slh-dsa-sha2-128s", "signature"),
    ("SPHINCS+-SHAKE-256f", "slh-dsa-shake-256f", "signature"),
    ("X25519MLKEM768", "x25519+ml-kem-768", "combiner"),
    ("3DES", "tdea", "block-cipher"),
    ("DESede/CBC/PKCS5Padding", "tdea-cbc-pkcs5", "block-cipher"),
    ("DES-EDE3-CBC", "tdea-cbc", "block-cipher"),
    ("RC4", "rc4", "stream-cipher"),
    ("ChaCha20-Poly1305", "chacha20-poly1305", "ae"),
    ("AES-128-GCM-SIV", "aes-128-gcm-siv", "ae"),
    ("SecureRandom", "drbg", "drbg"),
    ("CTR-DRBG", "ctr-drbg", "drbg"),
    ("DH-2048", "dh-2048", "key-agree"),
    ("HQC-128", "hqc-128", "kem"),
    ("Argon2id", "argon2-id", "kdf"),
]


@pytest.mark.parametrize("raw,canonical,primitive", CASES)
def test_canonical_names(raw, canonical, primitive):
    pr = parse_algorithm(raw)
    assert pr.ok, pr.notes
    assert pr.descriptor.canonical() == canonical
    assert pr.descriptor.primitive == primitive
    assert pr.descriptor.cid() == "2cbom:alg:" + canonical


@pytest.mark.parametrize("raw,canonical,primitive", CASES)
def test_canonical_strings_are_fixed_points(raw, canonical, primitive):
    """The grammar maps every canonical string to itself (Theorem 2)."""
    pr = parse_algorithm(canonical)
    assert pr.ok and pr.descriptor.canonical() == canonical


def test_hints_fill_missing_slots_and_name_wins_on_conflict():
    d = parse_algorithm("AES", {"parameterSetIdentifier": "128", "mode": "gcm"}).descriptor
    assert d.canonical() == "aes-128-gcm"
    pr = parse_algorithm("AES-128", {"parameterSetIdentifier": "256"})
    assert pr.descriptor.canonical() == "aes-128"
    assert any(n.startswith("hint-conflict") for n in pr.notes)
    assert parse_algorithm("ECDSA", {"curve": "P-384"}).descriptor.canonical() == "ecdsa-p384"
    assert parse_algorithm("RSA", {"parameterSetIdentifier": "2048", "padding": "oaep"}).descriptor.canonical() == "rsa-2048-oaep"


def test_unresolved_and_pre_standard():
    assert not parse_algorithm("foobar").ok
    assert not parse_algorithm("GCM").ok
    pr = parse_algorithm("kyber-1024")
    assert pr.descriptor.canonical() == "ml-kem-1024" and pr.pre_standard == "kyber"


def test_cipher_suites():
    s = parse_cipher_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    roles = dict((r, d.canonical()) for r, d in s["components"])
    assert roles == {"kex": "ecdh", "auth": "rsa", "cipher": "aes-128-gcm", "prf": "sha2-256"}
    assert s["kex_known"]
    s = parse_cipher_suite("TLS_AES_256_GCM_SHA384")
    assert dict((r, d.canonical()) for r, d in s["components"]) == {"cipher": "aes-256-gcm", "prf": "sha2-384"}
    assert not s["kex_known"]
    s = parse_cipher_suite("0xC02F")
    assert s["name"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    s = parse_cipher_suite("TLS_RSA_WITH_3DES_EDE_CBC_SHA")
    assert dict((r, d.canonical()) for r, d in s["components"]) == {"kex": "rsa", "auth": "rsa", "cipher": "tdea-cbc", "prf": "sha1"}
    assert parse_cipher_suite("AES-128-GCM") is None


def test_identity_functions():
    cid, basis = certificate_id("SHA256:AB:CD", None, None, None, None, None)
    assert cid == "2cbom:cert:fp:sha256:abcd" and basis == "fingerprint"
    cid1, _ = certificate_id(None, "CN=a, O=b", "CN=ca", "01", "2024", "2026")
    cid2, _ = certificate_id(None, "cn=a,o=b", "cn=ca", "01", "2024", "2026")
    assert cid1 == cid2
    assert component_id("pkg:maven/g/a@1.0?type=jar", None, None, None, None)[0] == "2cbom:comp:pkg:maven/g/a@1.0"
    assert component_id(None, None, "Org", "Lib Name", "1.2")[0] == "2cbom:comp:org/lib-name@1.2"
    assert normalize_location("./src\\a.java", ()) == "src/a.java"
    assert normalize_location("/workspace/src/a.java", ("/workspace/",)) == "src/a.java"


def test_jcs_and_digest_are_deterministic():
    a = {"b": [1, 2, {"z": "é", "a": None}], "a": "x"}
    b = {"a": "x", "b": [1, 2, {"a": None, "z": "é"}]}
    assert jcs_dumps(a) == jcs_dumps(b) == '{"a":"x","b":[1,2,{"a":null,"z":"é"}]}'
    assert digest(a) == digest(b)
    assert stable_uuid("x") == stable_uuid("x") != stable_uuid("y")


def test_descriptor_roundtrip():
    d = AlgorithmDescriptor(family="rsa", parameter_set="2048", padding="oaep", hash="sha2-256", primitive="pke")
    assert AlgorithmDescriptor.from_dict(d.to_dict()) == d
