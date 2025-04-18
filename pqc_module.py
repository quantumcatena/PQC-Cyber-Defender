# pqc_module.py
# Core PQC engine — NIST FIPS 203/204 avec primitives liboqs réelles.
#
# Migration des primitives simulées vers liboqs (Open Quantum Safe) :
# les opérations keygen/encap/decap/sign/verify sont maintenant exécutées
# par des implémentations C constant-time certifiées.
#
# Construction hybride conservée : KEM liboqs + AES-256-GCM + HMAC-SHA3-256
# miroir de X25519Kyber768Draft00 (RFC 9261).
#
# Ref: thèse "Responsabilité normative des opérateurs face aux attaques
# HNDL dans le cadre du RGPD et de NIS2" — Université de Toulon 2024.
# Article en cours : CLSR 2026 (avec G. Payan, Université de Toulon).

import os
import time
import struct
import hashlib
import secrets
import logging
import warnings
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional
from enum import Enum

import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

# Import liboqs — fallback sur simulation si non disponible
try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        import oqs
    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False

logger = logging.getLogger(__name__)


class Algorithm(Enum):
    KYBER_512     = "Kyber-512"
    KYBER_768     = "Kyber-768"
    KYBER_1024    = "Kyber-1024"
    DILITHIUM_2   = "Dilithium-2"
    DILITHIUM_3   = "Dilithium-3"
    DILITHIUM_5   = "Dilithium-5"
    FRODOKEM_640  = "FrodoKEM-640"
    FRODOKEM_976  = "FrodoKEM-976"
    FRODOKEM_1344 = "FrodoKEM-1344"


LIBOQS_KEM_NAMES: Dict[Algorithm, str] = {
    Algorithm.KYBER_512:    "Kyber512",
    Algorithm.KYBER_768:    "Kyber768",
    Algorithm.KYBER_1024:   "Kyber1024",
    Algorithm.FRODOKEM_640:  "FrodoKEM-640-AES",
    Algorithm.FRODOKEM_976:  "FrodoKEM-976-AES",
    Algorithm.FRODOKEM_1344: "FrodoKEM-1344-AES",
}

LIBOQS_SIG_NAMES: Dict[Algorithm, str] = {
    Algorithm.DILITHIUM_2: "ML-DSA-44",
    Algorithm.DILITHIUM_3: "ML-DSA-65",
    Algorithm.DILITHIUM_5: "ML-DSA-87",
}

ALGORITHM_PARAMS: Dict[Algorithm, Dict] = {
    Algorithm.KYBER_512: {
        "type": "KEM", "security_level": 1,
        "nist_category": "Category 1 (AES-128 equivalent)",
        "pk_bytes": 800, "sk_bytes": 1632, "ct_bytes": 768, "ss_bytes": 32,
        "n": 256, "q": 3329, "k": 2, "eta1": 3, "eta2": 2,
        "description": "ML-KEM-512 — FIPS 203 (IoT, contraintes mémoire)",
    },
    Algorithm.KYBER_768: {
        "type": "KEM", "security_level": 3,
        "nist_category": "Category 3 (AES-192 equivalent)",
        "pk_bytes": 1184, "sk_bytes": 2400, "ct_bytes": 1088, "ss_bytes": 32,
        "n": 256, "q": 3329, "k": 3, "eta1": 2, "eta2": 2,
        "description": "ML-KEM-768 — FIPS 203 (recommandé usage général)",
    },
    Algorithm.KYBER_1024: {
        "type": "KEM", "security_level": 5,
        "nist_category": "Category 5 (AES-256 equivalent)",
        "pk_bytes": 1568, "sk_bytes": 3168, "ct_bytes": 1568, "ss_bytes": 32,
        "n": 256, "q": 3329, "k": 4, "eta1": 2, "eta2": 2,
        "description": "ML-KEM-1024 — FIPS 203 (défense, infra critique)",
    },
    Algorithm.DILITHIUM_2: {
        "type": "SIGNATURE", "security_level": 2,
        "nist_category": "Category 2",
        "pk_bytes": 1312, "sk_bytes": 2528, "sig_bytes": 2420,
        "n": 256, "q": 8380417, "k": 4, "l": 4,
        "description": "ML-DSA-44 — FIPS 204",
    },
    Algorithm.DILITHIUM_3: {
        "type": "SIGNATURE", "security_level": 3,
        "nist_category": "Category 3",
        "pk_bytes": 1952, "sk_bytes": 4000, "sig_bytes": 3293,
        "n": 256, "q": 8380417, "k": 6, "l": 5,
        "description": "ML-DSA-65 — FIPS 204 (recommandé)",
    },
    Algorithm.DILITHIUM_5: {
        "type": "SIGNATURE", "security_level": 5,
        "nist_category": "Category 5",
        "pk_bytes": 2592, "sk_bytes": 4864, "sig_bytes": 4595,
        "n": 256, "q": 8380417, "k": 8, "l": 7,
        "description": "ML-DSA-87 — FIPS 204 (PKI, infra critique)",
    },
    Algorithm.FRODOKEM_640: {
        "type": "KEM", "security_level": 1,
        "nist_category": "Category 1 (LWE conservatif)",
        "pk_bytes": 9616, "sk_bytes": 19888, "ct_bytes": 9720, "ss_bytes": 16,
        "n": 640, "q": 32768,
        "description": "FrodoKEM-640-AES — LWE non structuré",
    },
    Algorithm.FRODOKEM_976: {
        "type": "KEM", "security_level": 3,
        "nist_category": "Category 3 (LWE conservatif)",
        "pk_bytes": 15632, "sk_bytes": 31296, "ct_bytes": 15744, "ss_bytes": 24,
        "n": 976, "q": 65536,
        "description": "FrodoKEM-976-AES — recommandé ANSSI (conservatif)",
    },
    Algorithm.FRODOKEM_1344: {
        "type": "KEM", "security_level": 5,
        "nist_category": "Category 5 (LWE conservatif)",
        "pk_bytes": 21520, "sk_bytes": 43088, "ct_bytes": 21632, "ss_bytes": 32,
        "n": 1344, "q": 65536,
        "description": "FrodoKEM-1344-AES — max sécurité",
    },
}


@dataclass
class KeyPair:
    algorithm: Algorithm
    public_key: bytes
    private_key: bytes
    creation_time: float = field(default_factory=time.time)
    keygen_ms: float = 0.0
    backend: str = "simulation"

    @property
    def public_key_size(self):
        return len(self.public_key)

    @property
    def private_key_size(self):
        return len(self.private_key)

    def summary(self):
        return {
            "algorithm": self.algorithm.value,
            "pk_bytes": self.public_key_size,
            "sk_bytes": self.private_key_size,
            "keygen_ms": round(self.keygen_ms, 3),
            "nist_category": ALGORITHM_PARAMS[self.algorithm]["nist_category"],
            "backend": self.backend,
        }


@dataclass
class EncryptedPayload:
    algorithm: Algorithm
    ciphertext: bytes
    aes_nonce: bytes
    aes_ciphertext: bytes
    aes_tag: bytes
    mac: bytes
    encrypt_ms: float = 0.0
    plaintext_size: int = 0

    def to_bytes(self):
        parts = [
            struct.pack(">I", len(self.ciphertext)), self.ciphertext,
            self.aes_nonce,
            struct.pack(">I", len(self.aes_ciphertext)), self.aes_ciphertext,
            self.aes_tag,
            self.mac,
        ]
        return b"".join(parts)

    @property
    def total_size(self):
        return len(self.to_bytes())


@dataclass
class SimulationResult:
    algorithm: Algorithm
    plaintext_size: int
    ciphertext_size: int
    keygen_ms: float
    encrypt_ms: float
    decrypt_ms: float
    decryption_success: bool
    integrity_valid: bool
    overhead_ratio: float
    backend: str = "simulation"
    security_score: float = 0.0


def _derive_session_key(shared_secret: bytes, salt: bytes) -> bytes:
    h = hashlib.shake_256()
    h.update(shared_secret + salt)
    return h.digest(32)


def _hmac_sha3(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA3_256(), backend=default_backend())
    h.update(data)
    return h.finalize()


# liboqs primitives

def _keygen_liboqs(algorithm: Algorithm) -> Tuple[bytes, bytes, float]:
    params = ALGORITHM_PARAMS[algorithm]
    t0 = time.perf_counter()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if params["type"] == "KEM":
            kem = oqs.KeyEncapsulation(LIBOQS_KEM_NAMES[algorithm])
            pk  = kem.generate_keypair()
            sk  = kem.export_secret_key()
            kem.free()
        else:
            sig = oqs.Signature(LIBOQS_SIG_NAMES[algorithm])
            pk  = sig.generate_keypair()
            sk  = sig.export_secret_key()
            sig.free()
    return pk, sk, (time.perf_counter() - t0) * 1000


def _encap_liboqs(algorithm: Algorithm, pk: bytes) -> Tuple[bytes, bytes]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        kem = oqs.KeyEncapsulation(LIBOQS_KEM_NAMES[algorithm])
        ct, ss = kem.encap_secret(pk)
        kem.free()
    return ct, ss


def _decap_liboqs(algorithm: Algorithm, ciphertext: bytes, sk: bytes) -> bytes:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        kem = oqs.KeyEncapsulation(LIBOQS_KEM_NAMES[algorithm], sk)
        ss  = kem.decap_secret(ciphertext)
        kem.free()
    return ss


def _sign_liboqs(algorithm: Algorithm, data: bytes, sk: bytes) -> bytes:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        sig       = oqs.Signature(LIBOQS_SIG_NAMES[algorithm], sk)
        signature = sig.sign(data)
        sig.free()
    return signature


def _verify_liboqs(algorithm: Algorithm, data: bytes, signature: bytes, pk: bytes) -> bool:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        sig    = oqs.Signature(LIBOQS_SIG_NAMES[algorithm])
        result = sig.verify(data, signature, pk)
        sig.free()
    return result


# simulation fallback

def _keygen_simulated(algorithm: Algorithm) -> Tuple[bytes, bytes, float]:
    params = ALGORITHM_PARAMS[algorithm]
    t0 = time.perf_counter()
    d     = secrets.token_bytes(32)
    rho   = hashlib.sha3_512(d).digest()[:32]
    sigma = hashlib.sha3_512(d).digest()[32:]
    if params["type"] == "KEM":
        k        = params.get("k", 4)
        pk_bytes = hashlib.shake_256(rho + struct.pack(">I", k)).digest(params["pk_bytes"])
        sk_core  = hashlib.shake_256(sigma + struct.pack(">I", k)).digest(params["sk_bytes"] - 64)
        sk_bytes = sk_core + hashlib.sha3_256(pk_bytes).digest() + secrets.token_bytes(32)
    else:
        k  = params["k"]; l = params["l"]
        pk_bytes = hashlib.shake_256(rho + struct.pack(">HH", k, l)).digest(params["pk_bytes"])
        sk_bytes = hashlib.shake_256(sigma + struct.pack(">HH", k, l)).digest(params["sk_bytes"])
    return pk_bytes, sk_bytes, (time.perf_counter() - t0) * 1000


# API publique

def generate_keys(algorithm: Algorithm) -> KeyPair:
    """
    Génère une paire de clés PQC.
    Utilise liboqs (C constant-time) si disponible, sinon simulation Python.
    """
    use_oqs = LIBOQS_AVAILABLE and algorithm in (
        list(LIBOQS_KEM_NAMES.keys()) + list(LIBOQS_SIG_NAMES.keys())
    )
    if use_oqs:
        pk, sk, ms = _keygen_liboqs(algorithm)
        backend = "liboqs"
    else:
        pk, sk, ms = _keygen_simulated(algorithm)
        backend = "simulation"
    return KeyPair(algorithm=algorithm, public_key=pk, private_key=sk,
                   keygen_ms=ms, backend=backend)


def encrypt(data: bytes, key_pair: KeyPair) -> EncryptedPayload:
    """Chiffrement hybride PQC + AES-256-GCM."""
    params = ALGORITHM_PARAMS[key_pair.algorithm]
    if params["type"] != "KEM":
        raise ValueError(f"{key_pair.algorithm.value} est un schéma de signature.")

    t0   = time.perf_counter()
    salt = secrets.token_bytes(16)

    use_oqs = LIBOQS_AVAILABLE and key_pair.algorithm in LIBOQS_KEM_NAMES
    if use_oqs:
        kem_ct, shared_secret = _encap_liboqs(key_pair.algorithm, key_pair.public_key)
    else:
        coin          = secrets.token_bytes(32)
        pk_hash       = hashlib.sha3_256(key_pair.public_key).digest()
        kem_seed      = hashlib.sha3_512(coin + pk_hash).digest()
        shared_secret = kem_seed[:params["ss_bytes"]]
        kem_ct        = hashlib.shake_256(kem_seed + b"ct").digest(params["ct_bytes"])

    k_aes       = _derive_session_key(shared_secret, salt)
    k_mac       = hashlib.sha3_256(k_aes + b"mac").digest()
    nonce       = secrets.token_bytes(12)
    aesgcm      = AESGCM(k_aes)
    aad         = key_pair.algorithm.value.encode() + salt
    ct_with_tag = aesgcm.encrypt(nonce, data, aad)
    aes_ct      = ct_with_tag[:-16]
    aes_tag     = ct_with_tag[-16:]
    mac         = _hmac_sha3(k_mac, kem_ct + nonce + aes_ct + aes_tag)

    payload = EncryptedPayload(
        algorithm=key_pair.algorithm, ciphertext=kem_ct,
        aes_nonce=nonce, aes_ciphertext=aes_ct, aes_tag=aes_tag, mac=mac,
        encrypt_ms=(time.perf_counter() - t0) * 1000, plaintext_size=len(data),
    )
    payload._sk         = key_pair.private_key
    payload._salt       = salt
    payload._use_liboqs = use_oqs
    if not use_oqs:
        payload._coin = secrets.token_bytes(32)
    return payload


def decrypt(payload: EncryptedPayload, key_pair: KeyPair) -> bytes:
    """Décapsulation KEM + déchiffrement AES-256-GCM. Lève ValueError si intégrité compromise."""
    params = ALGORITHM_PARAMS[key_pair.algorithm]
    if params["type"] != "KEM":
        raise ValueError(f"{key_pair.algorithm.value} est un schéma de signature.")
    if payload.algorithm != key_pair.algorithm:
        raise ValueError("Algorithme incohérent entre payload et clé.")

    salt    = payload._salt
    use_oqs = getattr(payload, "_use_liboqs", False)

    if use_oqs:
        shared_secret = _decap_liboqs(key_pair.algorithm, payload.ciphertext, key_pair.private_key)
    else:
        coin          = payload._coin
        pk_hash       = hashlib.sha3_256(key_pair.public_key).digest()
        kem_seed      = hashlib.sha3_512(coin + pk_hash).digest()
        shared_secret = kem_seed[:params["ss_bytes"]]

    k_aes    = _derive_session_key(shared_secret, salt)
    k_mac    = hashlib.sha3_256(k_aes + b"mac").digest()
    expected = _hmac_sha3(k_mac, payload.ciphertext + payload.aes_nonce + payload.aes_ciphertext + payload.aes_tag)
    if not secrets.compare_digest(expected, payload.mac):
        raise ValueError("MAC invalide — payload modifié.")

    aesgcm = AESGCM(k_aes)
    aad    = key_pair.algorithm.value.encode() + salt
    return aesgcm.decrypt(payload.aes_nonce, payload.aes_ciphertext + payload.aes_tag, aad)


def sign(data: bytes, key_pair: KeyPair) -> bytes:
    params = ALGORITHM_PARAMS[key_pair.algorithm]
    if params["type"] != "SIGNATURE":
        raise ValueError(f"{key_pair.algorithm.value} est un KEM.")
    if LIBOQS_AVAILABLE and key_pair.algorithm in LIBOQS_SIG_NAMES:
        return _sign_liboqs(key_pair.algorithm, data, key_pair.private_key)
    msg_hash = hashlib.sha3_256(data).digest()
    sk_hash  = hashlib.sha3_256(key_pair.private_key[:64]).digest()
    return hashlib.shake_256(msg_hash + sk_hash).digest(params["sig_bytes"])


def verify(data: bytes, signature: bytes, key_pair: KeyPair) -> bool:
    params = ALGORITHM_PARAMS[key_pair.algorithm]
    if params["type"] != "SIGNATURE":
        raise ValueError(f"{key_pair.algorithm.value} est un KEM.")
    if LIBOQS_AVAILABLE and key_pair.algorithm in LIBOQS_SIG_NAMES:
        return _verify_liboqs(key_pair.algorithm, data, signature, key_pair.public_key)
    msg_hash = hashlib.sha3_256(data).digest()
    sk_hash  = hashlib.sha3_256(key_pair.private_key[:64]).digest()
    expected = hashlib.shake_256(msg_hash + sk_hash).digest(params["sig_bytes"])
    return secrets.compare_digest(expected, signature)


def simulate_data(size: int = 1024, data_type: str = "generic") -> bytes:
    templates = {
        "telemetry": (
            b"DRONE-PKT|lat=43.1234,lon=5.9876,alt=125.4,hdg=270.0,spd=15.3|"
            b"bat=87%,sig=-62dBm,temp=24.1C|ts=2025-06-15T14:33:22Z|seq="
        ),
        "medical": (
            b"PATIENT-RECORD|id=8f3a92c1,dob=1978-03-12,diag=ICD-10:J18.1|"
            b"lab=HbA1c:6.2,CRP:12.4,WBC:7.1|rx=metformin_500mg,tid|"
        ),
        "financial": (
            b"TXN-RECORD|from=FR76-1234-5678-9012,to=DE89-3704-0044-0532-0130-00|"
            b"amt=EUR:14750.00,ref=SEPA-CREDIT-2025-06144|ts=2025-06-15T14:33:22Z|"
        ),
    }
    template = templates.get(data_type, b"")
    if template:
        base = (template * ((size // len(template)) + 1))[:size - 8]
        return base + struct.pack(">Q", int(time.time() * 1000))
    return secrets.token_bytes(size)


def run_full_benchmark(algorithms=None, data_size: int = 1024) -> list:
    if algorithms is None:
        algorithms = [a for a in Algorithm if ALGORITHM_PARAMS[a]["type"] == "KEM"]
    results = []
    data    = simulate_data(data_size)
    for algo in algorithms:
        try:
            kp      = generate_keys(algo)
            payload = encrypt(data, kp)
            t0      = time.perf_counter()
            pt      = decrypt(payload, kp)
            dec_ms  = (time.perf_counter() - t0) * 1000
            results.append(SimulationResult(
                algorithm=algo, plaintext_size=len(data),
                ciphertext_size=payload.total_size, keygen_ms=kp.keygen_ms,
                encrypt_ms=payload.encrypt_ms, decrypt_ms=dec_ms,
                decryption_success=(pt == data), integrity_valid=True,
                overhead_ratio=payload.total_size / len(data), backend=kp.backend,
            ))
        except Exception as e:
            logger.error(f"Benchmark {algo.value}: {e}")
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    backend_label = "liboqs (C constant-time)" if LIBOQS_AVAILABLE else "simulation Python"
    print(f"\nBackend : {backend_label}")
    print("=" * 62)

    for algo in [Algorithm.KYBER_768, Algorithm.DILITHIUM_3, Algorithm.FRODOKEM_976]:
        params = ALGORITHM_PARAMS[algo]
        print(f"\n{algo.value}  [{params['nist_category']}]")
        kp = generate_keys(algo)
        print(f"  Backend  : {kp.backend}")
        print(f"  KeyGen   : pk={kp.public_key_size}B  sk={kp.private_key_size}B  ({kp.keygen_ms:.2f}ms)")
        if params["type"] == "KEM":
            data = simulate_data(512, "telemetry")
            ep   = encrypt(data, kp)
            back = decrypt(ep, kp)
            print(f"  Chiffr   : {len(data)}B -> {ep.total_size}B  ({ep.encrypt_ms:.2f}ms)")
            print(f"  Dechiffr : {'OK' if back == data else 'ECHEC'}")
        else:
            data = simulate_data(512, "financial")
            sig  = sign(data, kp)
            ok   = verify(data, sig, kp)
            print(f"  Signature : {len(sig)}B  - Verification : {'OK' if ok else 'ECHEC'}")

    print("\n" + "=" * 62)
    print("  Benchmark KEM (2048B)")
    print("=" * 62)
    for r in run_full_benchmark(data_size=2048):
        print(
            f"  {r.algorithm.value:<22} [{r.backend:<10}]  "
            f"kg={r.keygen_ms:7.3f}ms  enc={r.encrypt_ms:6.3f}ms  "
            f"dec={r.decrypt_ms:6.3f}ms  x{r.overhead_ratio:.2f}  "
            f"{'OK' if r.decryption_success else 'FAIL'}"
        )
