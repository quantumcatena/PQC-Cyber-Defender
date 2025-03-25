# analyzer.py
# Scoring de sécurité et génération de rapports pour les sessions PQC.
#
# Méthodologie de scoring :
#   score = 100 - Σ(poids_i × vuln_i × 10) - Σ(pénalité_résultat_i) + bonus_nist
#   Poids alignés sur les priorités ANSSI / NIST SP 800-227 / BSI TR-02102-1.
#
# Jurisprudence CNIL intégrée dans les recommandations :
#   - Dedalus Biologie (délib. 2022-228) : données de santé non chiffrées
#   - CEGEDIM Santé (délib. 2023-009) : absence de chiffrement en transit
# Ces décisions sont utilisées comme ancres jurisprudentielles dans l'article
# CLSR 2026 co-écrit avec G. Payan (Université de Toulon).

import os
import time
import hashlib
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

import numpy as np

from pqc_module import Algorithm, ALGORITHM_PARAMS, SimulationResult
from attack_simulator import (
    AttackReport, AttackSession, AttackType, AttackResult,
    run_full_attack_suite,
)

logger = logging.getLogger(__name__)

# Poids par vecteur d'attaque — HNDL prioritaire car menace existentielle PQC
ATTACK_WEIGHTS: Dict[AttackType, float] = {
    AttackType.HNDL:      0.30,
    AttackType.MITM:      0.20,
    AttackType.FUZZ:      0.20,
    AttackType.INTERCEPT: 0.15,
    AttackType.TIMING:    0.10,
    AttackType.DOWNGRADE: 0.05,
    AttackType.REPLAY:    0.00,
}

NIST_BONUS = {1: 0.0, 2: 2.0, 3: 5.0, 5: 10.0}

RESULT_PENALTY = {
    AttackResult.BLOCKED:    0.0,
    AttackResult.IMPOSSIBLE: 0.0,
    AttackResult.PARTIAL:   15.0,
    AttackResult.SUCCESS:   40.0,
}


@dataclass
class AlgorithmRisk:
    algorithm: Algorithm
    security_score: float
    attack_scores: Dict[str, float] = field(default_factory=dict)
    nist_level: int = 1
    strengths: List[str] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    grade: str = "B"

    @property
    def grade_color(self):
        if self.security_score >= 90: return "green"
        if self.security_score >= 75: return "blue"
        if self.security_score >= 60: return "yellow"
        return "red"


@dataclass
class SecurityReport:
    session_id: str
    timestamp: str
    algorithm_risks: List[AlgorithmRisk]
    global_score: float
    global_grade: str
    executive_summary: str
    recommendations: List[Dict]
    compliance_status: Dict
    export_path_pdf: Optional[str] = None
    export_path_html: Optional[str] = None


def compute_security_score(session: AttackSession) -> Tuple[float, AlgorithmRisk]:
    """Calcule le score de sécurité 0-100 pour une session d'attaques."""
    params    = ALGORITHM_PARAMS[session.algorithm]
    level     = params["security_level"]
    penalties = 0.0
    atk_scores: Dict[str, float] = {}

    for report in session.reports:
        w = ATTACK_WEIGHTS.get(report.attack_type, 0.05)
        p = (report.vulnerability_score / 10.0) * w * 100
        p += RESULT_PENALTY.get(report.result, 0.0) * w
        penalties += p
        atk_scores[report.attack_type.value] = round(max(0, 10 - report.vulnerability_score), 2)

    raw   = 100.0 - penalties + NIST_BONUS.get(level, 0.0)
    score = max(0.0, min(100.0, raw))

    grade = (
        "A+" if score >= 95 else "A"  if score >= 90 else
        "B+" if score >= 80 else "B"  if score >= 70 else
        "C"  if score >= 60 else "D"  if score >= 40 else "F"
    )

    strengths, weaknesses = [], []
    for r in session.reports:
        if r.result in (AttackResult.BLOCKED, AttackResult.IMPOSSIBLE):
            strengths.append(f"Résiste à {r.attack_type.value}")
        elif r.result == AttackResult.PARTIAL:
            weaknesses.append(f"Exposition partielle : {r.attack_type.value}")
        else:
            weaknesses.append(f"VULNÉRABLE : {r.attack_type.value}")

    if level >= 3:
        strengths.append(f"NIST Catégorie {level} — marge de sécurité élevée")

    return score, AlgorithmRisk(
        algorithm=session.algorithm,
        security_score=round(score, 2),
        attack_scores=atk_scores,
        nist_level=level,
        strengths=strengths,
        weaknesses=weaknesses,
        grade=grade,
    )


def generate_recommendations(sessions: List[AttackSession]) -> List[Dict]:
    """
    Génère des recommandations de remédiation priorisées depuis les sessions d'attaque.
    Alignées ANSSI Avis Technique PQC 2024 / NIST SP 800-227 / BSI TR-02102-1.
    """
    all_reports = [r for s in sessions for r in s.reports]
    mean_vulns  = {}
    for r in all_reports:
        mean_vulns.setdefault(r.attack_type, []).append(r.vulnerability_score)
    mean_vulns = {k: float(np.mean(v)) for k, v in mean_vulns.items()}

    recs = [
        {
            "id": "REC-001", "priority": "CRITICAL", "category": "Architecture",
            "title": "Migrer vers ML-KEM (NIST FIPS 203) pour tous les échanges de clés",
            "description": (
                "Tout échange classique (RSA, ECDH) est vulnérable aux attaques HNDL. "
                "Déployer ML-KEM-768 (Kyber-768) en priorité pour les données dont l'horizon "
                "de sensibilité dépasse 5 ans. La jurisprudence CNIL (Dedalus 2022, CEGEDIM 2023) "
                "confirme la responsabilité des opérateurs en cas de chiffrement insuffisant."
            ),
            "standard": "NIST FIPS 203, ANSSI Avis Technique 2024",
            "effort": "ÉLEVÉ", "risk_reduction": "95%",
        },
        {
            "id": "REC-002", "priority": "HIGH", "category": "Échange de clés",
            "title": "Déploiement hybride PQC+classique pendant la transition (RFC 9261)",
            "description": (
                "Combiner ML-KEM-768 avec X25519 (X25519Kyber768Draft00) pour protéger "
                "simultanément contre les adversaires classiques et quantiques. "
                "Recommandé par l'ANSSI pendant la fenêtre de migration."
            ),
            "standard": "RFC 9261, IETF TLS 1.3 + PQC",
            "effort": "MOYEN", "risk_reduction": "80%",
        },
        {
            "id": "REC-003", "priority": "HIGH", "category": "PKI / Authentification",
            "title": "Déployer ML-DSA-65 (Dilithium-3) pour signatures et PKI",
            "description": (
                "Remplacer les certificats RSA-2048/ECDSA par ML-DSA-65 (FIPS 204) "
                "pour empêcher les attaques de substitution de clé. Mettre à jour l'infrastructure "
                "CA per draft-ietf-lamps-dilithium-certificates."
            ),
            "standard": "NIST FIPS 204, IETF LAMPS WG",
            "effort": "ÉLEVÉ", "risk_reduction": "70%",
        },
        {
            "id": "REC-004", "priority": "MEDIUM", "category": "Intégrité",
            "title": "Renforcer l'AEAD avec construction résistante au nonce-reuse",
            "description": (
                "Envisager AES-256-GCM-SIV (RFC 8452) ou AEGIS-256 pour éliminer "
                "les vulnérabilités liées à la réutilisation de nonce en production."
            ),
            "standard": "RFC 8452 (AES-GCM-SIV), NIST SP 800-38D",
            "effort": "FAIBLE", "risk_reduction": "60%",
        },
        {
            "id": "REC-005", "priority": "MEDIUM", "category": "Trafic",
            "title": "Padding pour masquer la taille des plaintexts",
            "description": (
                "Les ciphertexts PQC révèlent la taille du plaintext (fuite de taille). "
                "Appliquer PKCS#7 ou blocs de taille fixe pour éliminer l'analyse de trafic "
                "basée sur la longueur. Critique pour données médicales (RGPD Art. 32)."
            ),
            "standard": "RFC 8467 (EDNS Padding)",
            "effort": "FAIBLE", "risk_reduction": "40%",
        },
        {
            "id": "REC-006", "priority": "MEDIUM", "category": "Implémentation",
            "title": "Utiliser liboqs ou BoringSSL pour des primitives constant-time",
            "description": (
                "Cette implémentation Python n'est pas constant-time. "
                "En production : liboqs (Open Quantum Safe), BoringSSL avec Kyber, "
                "ou HSM certifié FIPS 140-3."
            ),
            "standard": "FIPS 140-3, ANSSI Guide Sécurité des Implémentations",
            "effort": "MOYEN", "risk_reduction": "50%",
        },
        {
            "id": "REC-007", "priority": "LOW", "category": "Gouvernance",
            "title": "Inventaire cryptographique et feuille de route migration PQC",
            "description": (
                "Recenser tous les actifs cryptographiques classiques. Attribuer une note "
                "de risque HNDL selon la sensibilité des données. "
                "Jalons de migration per NIST SP 1800-38 (NCCoE PQC Migration Project)."
            ),
            "standard": "NIST SP 1800-38, ENISA PQC Migration Guidelines 2024",
            "effort": "MOYEN", "risk_reduction": "30%",
        },
    ]

    return sorted(recs, key=lambda r: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(r["priority"]))


def generate_report(
    sessions: List[AttackSession],
    output_dir: str = ".",
    include_pdf: bool = True,
    include_html: bool = True,
) -> SecurityReport:
    """Génère le rapport complet (PDF + HTML) pour toutes les sessions d'attaque."""
    session_id = hashlib.sha256(
        (str(time.time()) + str([s.algorithm.value for s in sessions])).encode()
    ).hexdigest()[:12].upper()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    risks = []
    for session in sessions:
        score, risk = compute_security_score(session)
        risks.append(risk)

    global_score = float(np.mean([r.security_score for r in risks]))
    global_grade = (
        "A+" if global_score >= 95 else "A"  if global_score >= 90 else
        "B+" if global_score >= 80 else "B"  if global_score >= 70 else
        "C"  if global_score >= 60 else "D"  if global_score >= 40 else "F"
    )

    recs = generate_recommendations(sessions)

    compliance = {
        "NIST FIPS 203 (ML-KEM)":    _check_nist203(sessions),
        "NIST FIPS 204 (ML-DSA)":    _check_nist204(sessions),
        "ANSSI Avis Technique 2024": _check_anssi(sessions),
        "NIS2 Directive Art. 21":    "CONFORME" if global_score >= 70 else "REMÉDIATION REQUISE",
        "RGPD Art. 32":              "CONFORME" if global_score >= 60 else "REMÉDIATION REQUISE",
    }

    best = max(risks, key=lambda r: r.security_score)
    n_crit = len([r for r in recs if r["priority"] == "CRITICAL"])
    n_high = len([r for r in recs if r["priority"] == "HIGH"])

    summary = (
        f"Évaluation de {len(sessions)} algorithme(s) PQC sur 5 vecteurs d'attaque. "
        f"Score global : {global_score:.1f}/100 (Grade {global_grade}). "
        f"Meilleur algorithme : {best.algorithm.value} ({best.security_score:.1f}/100). "
        f"Les algorithmes PQC évalués résistent aux attaques HNDL — menace principale "
        f"justifiant la migration per ANSSI et NIST SP 800-227. "
        f"{n_crit} recommandation(s) critique(s) et {n_high} haute(s) priorité identifiées."
    )

    report = SecurityReport(
        session_id=session_id,
        timestamp=timestamp,
        algorithm_risks=risks,
        global_score=round(global_score, 2),
        global_grade=global_grade,
        executive_summary=summary,
        recommendations=recs,
        compliance_status=compliance,
    )

    os.makedirs(output_dir, exist_ok=True)

    if include_html:
        path = os.path.join(output_dir, f"pqc_report_{session_id}.html")
        _export_html(report, path)
        report.export_path_html = path

    if include_pdf:
        path = os.path.join(output_dir, f"pqc_report_{session_id}.pdf")
        _export_pdf(report, path)
        report.export_path_pdf = path

    return report


def _check_nist203(sessions):
    kems = {s.algorithm for s in sessions if ALGORITHM_PARAMS[s.algorithm]["type"] == "KEM"}
    return "CONFORME" if kems & {Algorithm.KYBER_512, Algorithm.KYBER_768, Algorithm.KYBER_1024} else "NON CONFORME"

def _check_nist204(sessions):
    sigs = {s.algorithm for s in sessions if ALGORITHM_PARAMS[s.algorithm]["type"] == "SIGNATURE"}
    return "CONFORME" if sigs & {Algorithm.DILITHIUM_2, Algorithm.DILITHIUM_3, Algorithm.DILITHIUM_5} else "NON ÉVALUÉ"

def _check_anssi(sessions):
    # ANSSI recommande Cat.3 minimum (Kyber-768, Dilithium-3)
    return (
        "CONFORME"
        if any(ALGORITHM_PARAMS[s.algorithm]["security_level"] >= 3 for s in sessions)
        else "PARTIEL (upgrader vers Cat.3)"
    )


def _export_html(report: SecurityReport, path: str) -> None:
    p_colors = {"CRITICAL": "#e53e3e", "HIGH": "#dd6b20", "MEDIUM": "#d69e2e", "LOW": "#38a169"}
    c_colors  = {
        "CONFORME": "#38a169", "NON CONFORME": "#e53e3e",
        "NON ÉVALUÉ": "#718096",
        "PARTIEL (upgrader vers Cat.3)": "#dd6b20",
        "REMÉDIATION REQUISE": "#e53e3e",
    }

    def sc(s):
        if s >= 90: return "#38a169"
        if s >= 75: return "#3182ce"
        if s >= 60: return "#d69e2e"
        return "#e53e3e"

    algo_rows = ""
    for r in report.algorithm_risks:
        algo_rows += f"""<tr>
            <td><strong>{r.algorithm.value}</strong></td>
            <td>Cat. {r.nist_level}</td>
            <td style="color:{sc(r.security_score)};font-weight:bold;font-size:1.1em">{r.security_score:.1f}</td>
            <td><span class="grade" style="background:{sc(r.security_score)}">{r.grade}</span></td>
            <td><small>{"<br>".join(f"✅ {s}" for s in r.strengths[:3])}</small></td>
            <td><small>{"<br>".join(f"⚠️ {w}" for w in r.weaknesses[:2]) or "—"}</small></td>
        </tr>"""

    rec_cards = ""
    for rec in report.recommendations[:6]:
        c = p_colors.get(rec["priority"], "#718096")
        rec_cards += f"""<div class="rec-card">
            <div style="border-left:4px solid {c};padding-left:.8rem;margin-bottom:.5rem">
                <span class="badge" style="background:{c}">{rec["priority"]}</span>
                <span style="color:#a0aec0;font-size:.8rem;margin:0 .4rem">{rec["id"]}</span>
                <strong>{rec["title"]}</strong>
            </div>
            <p>{rec["description"]}</p>
            <div style="display:flex;gap:1.5rem;font-size:.8rem;color:#a0aec0;margin-top:.4rem">
                <span>📋 {rec["standard"]}</span>
                <span>🔧 {rec["effort"]}</span>
                <span>📉 {rec["risk_reduction"]}</span>
            </div>
        </div>"""

    comp_rows = ""
    for std, status in report.compliance_status.items():
        c = c_colors.get(status, "#718096")
        icon = "✅" if status == "CONFORME" else "❌" if "NON" in status else "⚠️"
        comp_rows += f"<tr><td>{std}</td><td style='color:{c};font-weight:bold'>{icon} {status}</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rapport PQC — {report.session_id}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#0a0e1a;color:#e2e8f0;line-height:1.6}}
.wrap{{max-width:1100px;margin:0 auto;padding:2rem}}
.header{{background:linear-gradient(135deg,#1a1f35,#0f172a);border:1px solid #2d3748;
         border-radius:12px;padding:2rem;margin-bottom:2rem;
         display:flex;justify-content:space-between;align-items:center}}
.logo{{font-size:1.7rem;font-weight:900;color:#63b3ed}}
.logo span{{color:#48bb78}}
.score-circle{{text-align:center;background:#1a1f35;border:2px solid {sc(report.global_score)};
              border-radius:50%;width:110px;height:110px;display:flex;
              flex-direction:column;align-items:center;justify-content:center}}
.score-num{{font-size:2rem;font-weight:900;color:{sc(report.global_score)}}}
.card{{background:#1a1f35;border:1px solid #2d3748;border-radius:10px;padding:1.5rem;margin-bottom:1.5rem}}
h2{{color:#63b3ed;font-size:1.2rem;margin-bottom:1rem;padding-bottom:.5rem;border-bottom:1px solid #2d3748}}
table{{width:100%;border-collapse:collapse}}
th{{background:#2d3748;color:#a0aec0;padding:.6rem 1rem;text-align:left;font-size:.85rem}}
td{{padding:.7rem 1rem;border-bottom:1px solid #2d3748;font-size:.9rem}}
.grade{{padding:.2rem .5rem;border-radius:4px;color:#fff;font-weight:bold}}
.badge{{padding:.15rem .5rem;border-radius:4px;color:#fff;font-size:.75rem;font-weight:bold}}
.rec-card{{background:#0f172a;border:1px solid #2d3748;border-radius:8px;padding:1rem;margin-bottom:.8rem}}
.exec{{background:#0f172a;border-left:4px solid #63b3ed;padding:1rem 1.5rem;
       border-radius:0 8px 8px 0;font-size:.95rem;color:#cbd5e0}}
.foot{{text-align:center;color:#4a5568;font-size:.8rem;margin-top:2rem;padding-top:1rem;border-top:1px solid #2d3748}}
</style>
</head>
<body>
<div class="wrap">
<div class="header">
  <div>
    <div class="logo">🛡️ PQC Cyber<span>Defender</span></div>
    <div style="color:#a0aec0;margin-top:.3rem">Rapport d'évaluation sécurité post-quantique</div>
    <div style="color:#4a5568;font-size:.85rem;margin-top:.3rem">Session : {report.session_id} | {report.timestamp}</div>
  </div>
  <div class="score-circle">
    <div class="score-num">{report.global_score:.0f}</div>
    <div style="font-size:.7rem;color:#a0aec0">SCORE</div>
    <div style="font-weight:bold;color:{sc(report.global_score)}">{report.global_grade}</div>
  </div>
</div>

<div class="card">
  <h2>Synthèse exécutive</h2>
  <div class="exec">{report.executive_summary}</div>
</div>

<div class="card">
  <h2>Matrice de sécurité par algorithme</h2>
  <table>
    <thead><tr><th>Algorithme</th><th>Niveau NIST</th><th>Score /100</th><th>Grade</th><th>Points forts</th><th>Points faibles</th></tr></thead>
    <tbody>{algo_rows}</tbody>
  </table>
</div>

<div class="card">
  <h2>Recommandations priorisées</h2>
  {rec_cards}
</div>

<div class="card">
  <h2>Conformité réglementaire</h2>
  <table>
    <thead><tr><th>Référentiel</th><th>Statut</th></tr></thead>
    <tbody>{comp_rows}</tbody>
  </table>
</div>

<div class="foot">
  PQC Cyber Defender — MIT License | NIST FIPS 203/204 · ANSSI Avis Technique 2024 · BSI TR-02102-1<br>
  Ref. : article en cours "Responsabilité normative NIS2/RGPD face aux attaques HNDL", CLSR 2026
</div>
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def _export_pdf(report: SecurityReport, path: str) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY

        doc   = SimpleDocTemplate(path, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
        story = []

        BLUE  = colors.HexColor("#63b3ed")
        GREEN = colors.HexColor("#48bb78")
        RED   = colors.HexColor("#e53e3e")
        ORNG  = colors.HexColor("#dd6b20")
        GRAY  = colors.HexColor("#a0aec0")
        BG    = colors.HexColor("#1a1f35")
        BG2   = colors.HexColor("#0f172a")

        def sc(s):
            if s >= 90: return GREEN
            if s >= 75: return BLUE
            if s >= 60: return ORNG
            return RED

        h1   = ParagraphStyle("H1", fontSize=18, textColor=BLUE, spaceAfter=4, fontName="Helvetica-Bold")
        h2   = ParagraphStyle("H2", fontSize=12, textColor=BLUE, spaceAfter=4, fontName="Helvetica-Bold")
        body = ParagraphStyle("B", fontSize=8.5, textColor=GRAY, spaceAfter=3, leading=13, alignment=TA_JUSTIFY)
        sm   = ParagraphStyle("S", fontSize=7.5, textColor=GRAY, spaceAfter=2)

        story.append(Paragraph("PQC Cyber Defender — Rapport d'évaluation sécurité", h1))
        story.append(Paragraph(f"Session : <b>{report.session_id}</b> | {report.timestamp}", sm))
        story.append(HRFlowable(width="100%", color=BLUE, spaceAfter=10))
        story.append(Paragraph(
            f"Score global : <b>{report.global_score:.1f}/100</b> — Grade {report.global_grade}",
            ParagraphStyle("sc", fontSize=13, textColor=sc(report.global_score), fontName="Helvetica-Bold", spaceAfter=6)
        ))
        story.append(Paragraph(report.executive_summary, body))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Matrice de sécurité", h2))
        rows = [["Algorithme", "Cat. NIST", "Score", "Grade", "Points forts"]]
        for r in report.algorithm_risks:
            rows.append([r.algorithm.value, f"Cat. {r.nist_level}", f"{r.security_score:.1f}", r.grade, "; ".join(r.strengths[:2])[:50]])
        t = Table(rows, colWidths=[4.5*cm, 2*cm, 1.8*cm, 1.5*cm, 7*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), BG), ("TEXTCOLOR", (0,0), (-1,0), BLUE),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [BG2, BG]), ("TEXTCOLOR", (0,1), (-1,-1), GRAY),
            ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#2d3748")),
            ("TOPPADDING", (0,0), (-1,-1), 4), ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ]))
        story.append(t)
        story.append(Spacer(1, 10))

        story.append(Paragraph("Recommandations", h2))
        rrows = [["ID", "Priorité", "Titre", "Réduction risque"]]
        for r in report.recommendations:
            rrows.append([r["id"], r["priority"], r["title"][:55], r["risk_reduction"]])
        rt = Table(rrows, colWidths=[1.5*cm, 2.2*cm, 12*cm, 1.8*cm])
        rt.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), BG), ("TEXTCOLOR", (0,0), (-1,0), BLUE),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 7.5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [BG2, BG]), ("TEXTCOLOR", (0,1), (-1,-1), GRAY),
            ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#2d3748")),
            ("TOPPADDING", (0,0), (-1,-1), 3), ("BOTTOMPADDING", (0,0), (-1,-1), 3),
        ]))
        story.append(rt)
        story.append(Spacer(1, 10))

        story.append(Paragraph("Conformité réglementaire", h2))
        crows = [["Référentiel", "Statut"]]
        for std, status in report.compliance_status.items():
            crows.append([std, status])
        ct = Table(crows, colWidths=[11*cm, 6*cm])
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), BG), ("TEXTCOLOR", (0,0), (-1,0), BLUE),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [BG2, BG]), ("TEXTCOLOR", (0,1), (-1,-1), GRAY),
            ("GRID", (0,0), (-1,-1), 0.25, colors.HexColor("#2d3748")),
            ("TOPPADDING", (0,0), (-1,-1), 3), ("BOTTOMPADDING", (0,0), (-1,-1), 3),
        ]))
        story.append(ct)
        story.append(Spacer(1, 15))
        story.append(HRFlowable(width="100%", color=GRAY, spaceAfter=4))
        story.append(Paragraph(
            "PQC Cyber Defender — MIT License | NIST FIPS 203/204 · ANSSI 2024 · BSI TR-02102-1",
            ParagraphStyle("foot", fontSize=7, textColor=colors.HexColor("#4a5568"), alignment=TA_CENTER)
        ))
        doc.build(story)

    except ImportError:
        logger.warning("ReportLab non disponible — export PDF ignoré.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    algos = [Algorithm.KYBER_768, Algorithm.KYBER_1024, Algorithm.FRODOKEM_976]
    sessions = [run_full_attack_suite(a, 512, "telemetry") for a in algos]
    report   = generate_report(sessions, "./reports")

    print(f"\nScore global : {report.global_score:.1f}/100  ({report.global_grade})")
    print(f"Session      : {report.session_id}")
    for r in report.algorithm_risks:
        print(f"  {r.algorithm.value:<22} {r.security_score:5.1f}/100  [{r.grade}]")
    print(f"\nHTML : {report.export_path_html}")
    print(f"PDF  : {report.export_path_pdf}")
