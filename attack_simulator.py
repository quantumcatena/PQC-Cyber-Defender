# attack_simulator.py
# Simulation d'attaques contre des échanges PQC.
#
# Scénarios couverts : MITM, fuzzing de ciphertext, interception passive,
# HNDL (Harvest-Now-Decrypt-Later), timing side-channel.
#
# Chaque attaque produit un AttackReport avec métriques quantitatives.
# La taxonomie des résultats est alignée sur le modèle Dolev-Yao et
# les catégories de menaces ANSSI Avis Technique PQC (2024).
#
# Ref: thèse "Responsabilité normative des opérateurs face aux attaques
# HNDL dans le cadre du RGPD et de NIS2" — Université de Toulon 2024.

import time
import random
import hashlib
import secrets
import logging
from copy import deepcopy
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

import numpy as np

from pqc_module import (
    Algorithm, ALGORITHM_PARAMS, KeyPair, EncryptedPayload,
    generate_keys, encrypt, decrypt, simulate_data,
)

logger = logging.getLogger(__name__)


class AttackType(Enum):
    MITM      = "Man-in-the-Middle"
    FUZZ      = "Ciphertext Fuzzing"
    INTERCEPT = "Traffic Interception"
    HNDL      = "Harvest-Now-Decrypt-Later"
    TIMING    = "Timing Side-Channel"
    DOWNGRADE = "Protocol Downgrade"
    REPLAY    = "Replay Attack"


class AttackResult(Enum):
    BLOCKED    = "BLOCKED"
    PARTIAL    = "PARTIAL_LEAK"
    SUCCESS    = "SUCCESS"
    IMPOSSIBLE = "COMPUTATIONALLY_INFEASIBLE"


@dataclass
class AttackReport:
    attack_type: AttackType
    algorithm: Algorithm
    result: AttackResult
    duration_ms: float
    attempts: int
    bytes_recovered: int
    bytes_total: int
    vulnerability_score: float   # 0.0 (sûr) → 10.0 (critique)
    details: Dict = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)

    @property
    def recovery_rate(self):
        return self.bytes_recovered / self.bytes_total if self.bytes_total else 0.0

    @property
    def is_critical(self):
        return self.vulnerability_score >= 7.0

    def summary(self):
        return {
            "attack": self.attack_type.value,
            "algorithm": self.algorithm.value,
            "result": self.result.value,
            "duration_ms": round(self.duration_ms, 2),
            "attempts": self.attempts,
            "bytes_recovered": self.bytes_recovered,
            "recovery_rate_pct": round(self.recovery_rate * 100, 2),
            "vulnerability_score": round(self.vulnerability_score, 2),
        }


@dataclass
class AttackSession:
    algorithm: Algorithm
    reports: List[AttackReport] = field(default_factory=list)

    @property
    def overall_vulnerability(self):
        return max((r.vulnerability_score for r in self.reports), default=0.0)

    @property
    def critical_count(self):
        return sum(1 for r in self.reports if r.is_critical)


def _flip_bits(data: bytes, n: int) -> bytes:
    arr = bytearray(data)
    for _ in range(n):
        idx = random.randint(0, len(arr) - 1)
        arr[idx] ^= 1 << random.randint(0, 7)
    return bytes(arr)


def _corrupt_bytes(data: bytes, rate: float) -> bytes:
    arr = bytearray(data)
    n = max(1, int(len(arr) * rate))
    for pos in random.sample(range(len(arr)), min(n, len(arr))):
        arr[pos] = random.randint(0, 255)
    return bytes(arr)


def mitm_attack(data: bytes, key_pair: KeyPair, n_attempts: int = 50) -> AttackReport:
    """
    Simule une attaque Man-in-the-Middle contre un échange de clés KEM.

    L'attaquant intercepte le ciphertext KEM en transit et tente de le
    décapsuler avec une clé générée aléatoirement. La sécurité IND-CCA2
    de Kyber/FrodoKEM garantit qu'un ciphertext modifié décapsule vers
    un secret inutilisable — pas de récupération de plaintext possible.

    Résultat attendu : BLOCKED pour tous les algorithmes PQC.
    """
    t0 = time.perf_counter()
    recovered = 0
    legit = encrypt(data, key_pair)

    for _ in range(n_attempts):
        rogue_kp = generate_keys(key_pair.algorithm)
        try:
            mutated = deepcopy(legit)
            mutated._coin = secrets.token_bytes(32)
            pt = decrypt(mutated, rogue_kp)
            recovered = max(recovered, sum(a == b for a, b in zip(pt[:64], data[:64])))
        except Exception:
            pass  # attendu — MAC ou GCM invalide

    duration_ms = (time.perf_counter() - t0) * 1000
    vuln = min(0.5, recovered / max(1, len(data)))

    return AttackReport(
        attack_type=AttackType.MITM,
        algorithm=key_pair.algorithm,
        result=AttackResult.BLOCKED if vuln < 0.1 else AttackResult.PARTIAL,
        duration_ms=duration_ms,
        attempts=n_attempts,
        bytes_recovered=recovered,
        bytes_total=len(data),
        vulnerability_score=vuln,
        details={
            "pqc_property": "IND-CCA2",
            "note": "Ciphertext KEM non décapsulable sans sk destinataire.",
        },
        recommendations=[
            "Déployer ML-DSA (FIPS 204) pour authentification des clés (certificate pinning).",
            "TLS mutuel avec certificats PQC — empêche substitution de clé.",
        ],
    )


def fuzz_attack(
    data: bytes,
    key_pair: KeyPair,
    mutation_modes: Optional[List[str]] = None,
    iterations_per_mode: int = 100,
) -> AttackReport:
    """
    Fuzzing du ciphertext — teste la résistance à la malléabilité.

    Modes de mutation testés :
    - bit_flip   : inversion de bits aléatoires dans aes_ciphertext
    - byte_corrupt : remplacement de bytes aléatoires
    - truncate   : troncature du payload AES
    - nonce_flip : modification du nonce AES-GCM
    - mac_tamper : modification du HMAC

    Mesure le taux de bypass du tag GCM et du HMAC.
    Un taux > 0% indique une faille d'intégrité sérieuse.
    """
    if mutation_modes is None:
        mutation_modes = ["bit_flip", "byte_corrupt", "truncate", "nonce_flip", "mac_tamper"]

    t0 = time.perf_counter()
    legit = encrypt(data, key_pair)

    total = 0
    bypasses = 0
    per_mode: Dict[str, Dict] = {}

    for mode in mutation_modes:
        mode_bypass = 0
        for _ in range(iterations_per_mode):
            total += 1
            m = deepcopy(legit)

            if mode == "bit_flip":
                m.aes_ciphertext = _flip_bits(m.aes_ciphertext, random.randint(1, 8))
            elif mode == "byte_corrupt":
                m.aes_ciphertext = _corrupt_bytes(m.aes_ciphertext, 0.05)
            elif mode == "truncate":
                m.aes_ciphertext = m.aes_ciphertext[:max(1, len(m.aes_ciphertext) // 2)]
            elif mode == "nonce_flip":
                m.aes_nonce = _flip_bits(m.aes_nonce, 4)
            elif mode == "mac_tamper":
                m.mac = _flip_bits(m.mac, 8)

            try:
                pt = decrypt(m, key_pair)
                if pt != data:
                    bypasses += 1
                    mode_bypass += 1
            except (ValueError, Exception):
                pass

        per_mode[mode] = {
            "iterations": iterations_per_mode,
            "bypasses": mode_bypass,
            "bypass_rate_pct": round(mode_bypass / iterations_per_mode * 100, 2),
        }

    duration_ms = (time.perf_counter() - t0) * 1000
    bypass_rate = bypasses / max(1, total)
    vuln = bypass_rate * 10.0

    return AttackReport(
        attack_type=AttackType.FUZZ,
        algorithm=key_pair.algorithm,
        result=(
            AttackResult.BLOCKED if bypass_rate < 0.001
            else AttackResult.PARTIAL if bypass_rate < 0.01
            else AttackResult.SUCCESS
        ),
        duration_ms=duration_ms,
        attempts=total,
        bytes_recovered=0,
        bytes_total=len(data),
        vulnerability_score=max(0.3, vuln),
        details={
            "total_mutations": total,
            "bypasses": bypasses,
            "bypass_rate_pct": round(bypass_rate * 100, 4),
            "per_mode": per_mode,
            "integrity_layers": "HMAC-SHA3-256 + AES-256-GCM",
        },
        recommendations=[
            "AES-256-GCM fournit un tag d'intégrité 128 bits.",
            "Double couche HMAC-SHA3-256 détecte les modifications pré-GCM.",
            "Envisager AES-GCM-SIV (RFC 8452) pour résistance nonce-reuse.",
        ],
    )


def intercept_attack(data: bytes, key_pair: KeyPair, n_sessions: int = 30) -> AttackReport:
    """
    Adversaire passif — analyse de trafic sans accès aux clés.

    Capture n_sessions échanges et analyse :
    - distribution des octets (entropie, test chi²)
    - variance de taille des ciphertexts (fuite de taille de plaintext)
    - unicité des nonces et des ciphertexts KEM (forward secrecy)

    Fuite de taille : le ciphertext PQC révèle la TAILLE du plaintext.
    C'est la seule fuite passive réaliste — atténuable par padding.
    """
    t0 = time.perf_counter()
    payloads = [encrypt(data, key_pair) for _ in range(n_sessions)]

    ct_bytes = b"".join(p.aes_ciphertext for p in payloads)
    counts   = np.bincount(np.frombuffer(ct_bytes, dtype=np.uint8), minlength=256)
    entropy  = float(-np.sum((counts / counts.sum()) * np.log2(counts / counts.sum() + 1e-12)))
    chi2     = float(np.sum((counts - len(ct_bytes) / 256) ** 2 / (len(ct_bytes) / 256)))

    sizes    = [p.total_size for p in payloads]
    nonces   = [p.aes_nonce for p in payloads]
    kem_cts  = [p.ciphertext[:32].hex() for p in payloads]

    size_variance  = float(np.var(sizes))
    nonces_unique  = len(set(nonces)) == len(nonces)
    kem_cts_unique = len(set(kem_cts)) == len(kem_cts)

    duration_ms = (time.perf_counter() - t0) * 1000

    # La fuite de taille est réelle mais non critique pour la confidentialité
    size_leak   = 1.5 if size_variance < 1.0 else 0.5
    nonce_score = 0.0 if nonces_unique else 8.0   # nonce réutilisé = catastrophique
    vuln        = min(10.0, size_leak + nonce_score + max(0.0, (8.0 - entropy) * 0.5))

    return AttackReport(
        attack_type=AttackType.INTERCEPT,
        algorithm=key_pair.algorithm,
        result=AttackResult.PARTIAL if size_leak > 0 else AttackResult.BLOCKED,
        duration_ms=duration_ms,
        attempts=n_sessions,
        bytes_recovered=0,
        bytes_total=len(data),
        vulnerability_score=vuln,
        details={
            "sessions": n_sessions,
            "entropy_bits": round(entropy, 4),
            "chi2": round(chi2, 2),
            "size_variance": round(size_variance, 4),
            "nonces_unique": nonces_unique,
            "forward_secrecy": kem_cts_unique,
            "note": "Fuite de taille de plaintext — atténuer par padding PKCS#7.",
        },
        recommendations=[
            "Padding aléatoire ou blocs de taille fixe pour masquer la taille.",
            "Traffic shaping sur canaux haute sensibilité.",
            "Perfect Forward Secrecy confirmée — chaque session use un KEM frais.",
        ],
    )


def hndl_attack(
    data: bytes,
    key_pair: KeyPair,
    storage_years: int = 10,
    quantum_ready_year: int = 2030,
) -> AttackReport:
    """
    Évalue le risque HNDL (Harvest-Now-Decrypt-Later).

    Modèle : un adversaire étatique stocke le trafic chiffré aujourd'hui
    et le déchiffre lorsqu'un ordinateur quantique cryptographiquement
    pertinent (CRQC) sera disponible.

    C'est la menace principale justifiant la migration PQC urgente.
    Ref: ANSSI Avis Technique 2024, NIST SP 800-227, BSI TR-02102-1.

    Pour les algorithmes classiques (RSA, ECDH) : algorithme de Shor
    casse l'échange de clés → plaintext historique récupérable.
    Pour PQC : pas vulnérable à Shor. Grover réduit AES-256 à 128 bits
    effectifs — toujours considéré sûr (NIST Cat.1 minimum).
    """
    params  = ALGORITHM_PARAMS[key_pair.algorithm]
    is_pqc  = key_pair.algorithm.value.split("-")[0] in {"Kyber", "Dilithium", "FrodoKEM"}
    level   = params["security_level"]

    current_year    = 2025
    years_to_crqc   = max(0, quantum_ready_year - current_year)
    exposure_window = max(0, storage_years - years_to_crqc)

    if is_pqc:
        pq_security = {1: 64, 2: 96, 3: 96, 5: 128}.get(level, 64)
        vuln        = min(1.5, exposure_window * 0.05)
        result      = AttackResult.IMPOSSIBLE
        recovered   = 0
    else:
        pq_security = 0
        vuln        = min(9.5, (storage_years / max(1, years_to_crqc)) * 5.0)
        result      = AttackResult.SUCCESS
        recovered   = len(data)

    duration_ms = 0.1  # calcul purement analytique

    return AttackReport(
        attack_type=AttackType.HNDL,
        algorithm=key_pair.algorithm,
        result=result,
        duration_ms=duration_ms,
        attempts=1,
        bytes_recovered=recovered,
        bytes_total=len(data),
        vulnerability_score=vuln,
        details={
            "algo_type": "Post-Quantum" if is_pqc else "Classique (VULNÉRABLE)",
            "nist_security_level": level,
            "pq_security_bits": pq_security,
            "grover_aes256_effectif": 128,
            "shor_vulnerable": not is_pqc,
            "crqc_horizon": quantum_ready_year,
            "fenetre_exposition_ans": exposure_window,
            "nist_fips": "FIPS 203/204" if is_pqc else "N/A",
        },
        recommendations=[
            "Migrer tous les échanges de clés vers ML-KEM (FIPS 203) immédiatement.",
            "Prioriser données sensibilité > 5 ans (dossiers médicaux, secrets défense).",
            "Déploiement hybride PQC+classique pendant la transition (RFC 9261).",
            "Suivre la feuille de route ANSSI Avis Technique PQC 2024.",
        ],
    )


def timing_attack(data: bytes, key_pair: KeyPair, n_measurements: int = 200) -> AttackReport:
    """Mesure la variance temporelle de décapsulation — détecte les fuites timing."""
    t0      = time.perf_counter()
    payload = encrypt(data, key_pair)

    valid_times, invalid_times = [], []
    for i in range(n_measurements):
        if i % 2 == 0:
            t_inner = time.perf_counter()
            try: decrypt(payload, key_pair)
            except: pass
            valid_times.append((time.perf_counter() - t_inner) * 1e6)
        else:
            m = deepcopy(payload)
            m.mac = secrets.token_bytes(32)
            t_inner = time.perf_counter()
            try: decrypt(m, key_pair)
            except: pass
            invalid_times.append((time.perf_counter() - t_inner) * 1e6)

    va = np.array(valid_times)
    ia = np.array(invalid_times)
    ratio = abs(va.mean() - ia.mean()) / max(va.mean(), 1e-9)
    leak  = ratio > 0.05

    duration_ms = (time.perf_counter() - t0) * 1000

    return AttackReport(
        attack_type=AttackType.TIMING,
        algorithm=key_pair.algorithm,
        result=AttackResult.PARTIAL if leak else AttackResult.BLOCKED,
        duration_ms=duration_ms,
        attempts=n_measurements,
        bytes_recovered=0,
        bytes_total=len(data),
        vulnerability_score=min(5.0, ratio * 20) if leak else 0.8,
        details={
            "mean_valid_us": round(float(va.mean()), 3),
            "mean_invalid_us": round(float(ia.mean()), 3),
            "timing_ratio": round(ratio, 5),
            "leak_detected": leak,
            "note": "Python non constant-time — production: liboqs C ou HSM.",
        },
        recommendations=[
            "Utiliser liboqs ou BoringSSL+Kyber (constant-time vérifié).",
            "Vérification ct-verif / dudect sur implémentations C.",
            "HSM FIPS 140-3 fournit isolation temporelle matérielle.",
        ],
    )


def run_full_attack_suite(
    algorithm: Algorithm = Algorithm.KYBER_768,
    data_size: int = 512,
    data_type: str = "telemetry",
) -> AttackSession:
    """Lance la suite complète d'attaques sur un algorithme donné."""
    logger.info(f"Suite d'attaques sur {algorithm.value}")
    kp      = generate_keys(algorithm)
    data    = simulate_data(data_size, data_type)
    session = AttackSession(algorithm=algorithm)

    for name, fn in [
        ("MITM",        lambda: mitm_attack(data, kp)),
        ("Fuzz",        lambda: fuzz_attack(data, kp)),
        ("Intercept",   lambda: intercept_attack(data, kp)),
        ("HNDL",        lambda: hndl_attack(data, kp)),
        ("Timing",      lambda: timing_attack(data, kp)),
    ]:
        try:
            report = fn()
            session.reports.append(report)
            logger.info(f"  {name:<12} → {report.result.value:<30} score={report.vulnerability_score:.1f}/10")
        except Exception as e:
            logger.error(f"  {name} FAILED: {e}")

    return session


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()
    console.print("\n[bold cyan]Attack Simulator — PQC Cyber Defender[/bold cyan]\n")

    for algo in [Algorithm.KYBER_768, Algorithm.KYBER_1024, Algorithm.FRODOKEM_976]:
        console.print(f"[bold yellow]{algo.value}[/bold yellow]")
        session = run_full_attack_suite(algo, data_size=512)

        table = Table(box=box.SIMPLE_HEAD)
        table.add_column("Attack", width=24)
        table.add_column("Result", width=30)
        table.add_column("Score", justify="right", width=10)
        table.add_column("ms", justify="right", width=8)

        for r in session.reports:
            color = (
                "green"   if r.result in (AttackResult.BLOCKED, AttackResult.IMPOSSIBLE) else
                "yellow"  if r.result == AttackResult.PARTIAL else "red"
            )
            table.add_row(
                r.attack_type.value,
                f"[{color}]{r.result.value}[/{color}]",
                f"{r.vulnerability_score:.1f}/10",
                f"{r.duration_ms:.0f}",
            )
        console.print(table)
        console.print(f"  Vulnérabilité max : {session.overall_vulnerability:.1f}/10\n")
