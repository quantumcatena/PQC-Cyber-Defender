# PQC Cyber Defender

Post-Quantum Cryptography research platform — attack simulation, security scoring, interactive dashboard.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![NIST FIPS 203/204](https://img.shields.io/badge/NIST-FIPS%20203%2F204-green.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

This project demonstrates applied Post-Quantum Cryptography (PQC) across realistic threat scenarios. It covers the full stack from key generation to attack simulation and compliance reporting, using NIST-standardised algorithms (ML-KEM, ML-DSA) combined with AES-256-GCM in a hybrid construction.

The primary motivation is the **Harvest-Now-Decrypt-Later (HNDL)** threat: adversaries collecting encrypted traffic today to decrypt it once a cryptographically-relevant quantum computer (CRQC) becomes available. Estimates converge on a 2030–2035 horizon (ANSSI Avis Technique 2024, BSI TR-02102-1), which means migration to PQC is urgent for any data with a sensitivity horizon above 5 years — health records, financial transactions, defense communications.

This work grew out of doctoral research at Université de Toulon (FRSIT, 2020–2024) on the normative liability of operators under NIS2 and RGPD in the context of HNDL attacks.

---

## Architecture

```
Application layer
  Drone telemetry · Financial transactions · Medical records · TLS 1.3

PQC Key Encapsulation (KEM)
  ML-KEM-768 (Kyber-768)   — NIST FIPS 203 · recommended general-purpose
  FrodoKEM-976             — plain-LWE, conservative choice (ANSSI)

Hybrid symmetric layer
  AES-256-GCM + HKDF-SHA3-256 + HMAC-SHA3-256

Digital signatures
  ML-DSA-65 (Dilithium-3)  — NIST FIPS 204

Attack simulation
  MITM · Ciphertext fuzzing · Traffic interception · HNDL · Timing side-channel

Analysis & scoring
  CVSS v4.0-inspired weights + ANSSI/NIST priority matrix → score 0-100
```

Reference: RFC 9261 (Hybrid PQC KEM), IETF TLS 1.3 + Kyber, NIST SP 800-227.

---

## Algorithms

### Key Encapsulation (KEM)

| Algorithm | Standard | NIST Level | PK size | Use case |
|---|---|---|---|---|
| ML-KEM-512 (Kyber-512) | FIPS 203 | Cat. 1 | 800 B | IoT, constrained devices |
| ML-KEM-768 (Kyber-768) | FIPS 203 | Cat. 3 | 1,184 B | General purpose (recommended) |
| ML-KEM-1024 (Kyber-1024) | FIPS 203 | Cat. 5 | 1,568 B | Defense, critical infrastructure |
| FrodoKEM-640 | NIST PQC R3 | Cat. 1 | 9,616 B | Ultra-conservative |
| FrodoKEM-976 | NIST PQC R3 | Cat. 3 | 15,632 B | ANSSI conservative option |
| FrodoKEM-1344 | NIST PQC R3 | Cat. 5 | 21,520 B | Maximum security |

### Digital Signatures

| Algorithm | Standard | NIST Level | PK size | Signature |
|---|---|---|---|---|
| ML-DSA-44 (Dilithium-2) | FIPS 204 | Cat. 2 | 1,312 B | 2,420 B |
| ML-DSA-65 (Dilithium-3) | FIPS 204 | Cat. 3 | 1,952 B | 3,293 B |
| ML-DSA-87 (Dilithium-5) | FIPS 204 | Cat. 5 | 2,592 B | 4,595 B |

---

## Attack vectors

| Attack | Model | PQC result | Notes |
|---|---|---|---|
| MITM | Active, key substitution | BLOCKED | IND-CCA2 prevents decapsulation with wrong key |
| Ciphertext fuzzing | Malleability | BLOCKED | AES-GCM auth tag + HMAC-SHA3 |
| Traffic interception | Passive | PARTIAL | Size leakage — mitigated by padding |
| HNDL | Long-term, quantum adversary | INFEASIBLE | Not broken by Shor's algorithm |
| Timing side-channel | Microarchitectural | PARTIAL | Python not constant-time — production needs liboqs |
| Rogue command injection | UAV / IoT | BLOCKED | ML-DSA signature authentication |
| GPS spoofing | UAV / IoT | BLOCKED | AEAD prevents data injection |

---

## Installation

```bash
git clone https://github.com/your-username/PQC-Cyber-Defender.git
cd PQC-Cyber-Defender
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

**Optional — real PQC primitives (constant-time C):**
```bash
# Linux: sudo apt install liboqs-dev
# macOS: brew install liboqs
pip install liboqs-python
```

---

## Usage

```bash
# Core PQC demo (keygen, encrypt, decrypt, benchmark)
python pqc_module.py

# Attack simulation suite
python attack_simulator.py

# Full analysis + PDF/HTML report
python analyzer.py
# → reports/pqc_report_<ID>.pdf

# Drone/IoT network simulation
python drone_simulator.py

# Interactive dashboard
streamlit run dashboard.py
# → http://localhost:8501
```

---

## Sample output

```
Kyber-768  [Category 3 (AES-192 equivalent)]
  KeyGen : pk=1184B  sk=2400B  (0.84ms)
  Chiffr : 512B → 1921B  (0.31ms)
  Déchiffr : OK

Attack suite — Kyber-768
  MITM         → BLOCKED                       score=0.0/10
  Fuzz         → BLOCKED                       score=0.3/10
  Intercept    → PARTIAL_LEAK                  score=1.5/10
  HNDL         → COMPUTATIONALLY_INFEASIBLE    score=0.2/10
  Timing       → PARTIAL_LEAK                  score=1.8/10
  Vulnérabilité max : 1.8/10

Score global : 98.2/100  (A+)
```

---

## Project structure

```
PQC-Cyber-Defender/
├── pqc_module.py         # Core PQC engine — FIPS 203/204 parameter sets
├── attack_simulator.py   # MITM, fuzzing, interception, HNDL, timing
├── analyzer.py           # Security scoring + PDF/HTML report
├── dashboard.py          # Streamlit interactive dashboard
├── drone_simulator.py    # UAV/IoT mesh network simulation
├── requirements.txt
├── README.md
└── assets/
```

---

## Compliance

| Standard | Status |
|---|---|
| NIST FIPS 203 (ML-KEM) | Aligned — Kyber-512/768/1024 parameter sets |
| NIST FIPS 204 (ML-DSA) | Aligned — Dilithium-2/3/5 parameter sets |
| ANSSI Avis Technique PQC 2024 | Aligned — Cat. 3+ minimum enforced |
| NIS2 Directive Art. 21 | State-of-the-art cryptography requirement |
| RGPD Art. 32 | Appropriate technical measures |
| BSI TR-02102-1 | Hybrid PQC+classical construction |

---

## References

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM standard
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA standard
- [ANSSI Avis Technique PQC (2024)](https://www.ssi.gouv.fr)
- [NIST SP 800-227](https://doi.org/10.6028/NIST.SP.800-227.ipd) — PQC migration guidelines
- [RFC 9261](https://www.rfc-editor.org/rfc/rfc9261) — Hybrid PQC KEM
- [Open Quantum Safe / liboqs](https://openquantumsafe.org)

---

## License

MIT — see [LICENSE](LICENSE).
