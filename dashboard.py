# dashboard.py — PQC Cyber Defender
# Interface Streamlit interactive.
#
# Lancer : streamlit run dashboard.py
#
# TODO: ajouter export JSON des résultats bruts pour intégration CI/CD

import time
import logging
from pathlib import Path

import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import numpy as np

from pqc_module import (
    Algorithm, ALGORITHM_PARAMS, generate_keys, encrypt, decrypt,
    sign, verify, simulate_data, run_full_benchmark,
)
from attack_simulator import (
    AttackType, AttackResult, run_full_attack_suite,
    mitm_attack, fuzz_attack, intercept_attack, hndl_attack, timing_attack,
)
from analyzer import compute_security_score, generate_recommendations, generate_report
from drone_simulator import run_network_simulation

logging.basicConfig(level=logging.WARNING)

st.set_page_config(
    page_title="PQC Cyber Defender",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.main { background-color: #0a0e1a; }
.block-container { padding-top: 1rem; }
.metric-card {
    background: linear-gradient(135deg, #1a1f35, #0f172a);
    border: 1px solid #2d3748; border-radius: 10px;
    padding: 1.2rem; text-align: center;
}
.metric-value { font-size: 2.2rem; font-weight: 900; }
.metric-label { color: #a0aec0; font-size: 0.85rem; margin-top: 0.2rem; }
.stButton>button {
    background: linear-gradient(90deg, #2b6cb0, #3182ce);
    color: white; border: none; border-radius: 8px;
    font-weight: 600;
}
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## 🛡️ PQC Cyber Defender")
    st.caption("Post-Quantum Security Platform")
    st.divider()

    page = st.radio("Navigation", [
        "Vue d'ensemble",
        "Benchmark PQC",
        "Simulateur d'attaques",
        "Analyse & Scoring",
        "Réseau Drone/IoT",
        "Export rapport",
    ])

    st.divider()
    st.markdown("**Paramètres**")

    sel_name = st.selectbox(
        "Algorithme PQC",
        [a.value for a in Algorithm if ALGORITHM_PARAMS[a]["type"] == "KEM"],
        index=1,
    )
    selected = next(a for a in Algorithm if a.value == sel_name)

    data_size = st.slider("Taille données (bytes)", 64, 4096, 512, 64)
    data_type = st.selectbox("Type données", ["generic", "telemetry", "medical", "financial"], index=1)
    n_iter    = st.slider("Itérations / attaque", 20, 200, 50, 10)

    st.divider()
    st.caption("NIST FIPS 203/204 · ANSSI 2024 · BSI TR-02102")


def sc(s):
    if s >= 90: return "#48bb78"
    if s >= 75: return "#63b3ed"
    if s >= 60: return "#ed8936"
    return "#f56565"

def rc(r):
    return {"BLOCKED": "#48bb78", "COMPUTATIONALLY_INFEASIBLE": "#48bb78",
            "PARTIAL_LEAK": "#ed8936", "SUCCESS": "#f56565"}.get(r, "#a0aec0")

def ri(r):
    return {"BLOCKED": "🟢", "COMPUTATIONALLY_INFEASIBLE": "🟢",
            "PARTIAL_LEAK": "🟡", "SUCCESS": "🔴"}.get(r, "⚪")


# ─────────────────────────────────────────────────────────────────────────────

if page == "Vue d'ensemble":
    st.title("🛡️ PQC Cyber Defender")
    st.markdown("Plateforme de démonstration PQC — NIST FIPS 203/204 · ANSSI 2024 · Simulation d'attaques HNDL")
    st.divider()

    cols = st.columns(5)
    for col, (v, l, c) in zip(cols, [
        ("9", "Algorithmes PQC", "#63b3ed"),
        ("5", "Vecteurs d'attaque", "#f56565"),
        ("AES-256", "Couche symétrique", "#48bb78"),
        ("FIPS 203/204", "Standards NIST", "#ed8936"),
        ("MIT", "Licence", "#a0aec0"),
    ]):
        col.markdown(
            f'<div class="metric-card">'
            f'<div class="metric-value" style="color:{c}">{v}</div>'
            f'<div class="metric-label">{l}</div></div>',
            unsafe_allow_html=True,
        )

    st.divider()
    ca, cb = st.columns(2)

    with ca:
        st.subheader("Algorithmes supportés")
        df = pd.DataFrame([{
            "Algorithme": a.value, "Type": p["type"],
            "Sécurité": p["nist_category"],
            "PK (B)": p["pk_bytes"], "SK (B)": p["sk_bytes"],
        } for a, p in ALGORITHM_PARAMS.items()])
        st.dataframe(df, hide_index=True, use_container_width=True)

    with cb:
        st.subheader("Horizon risque HNDL")
        years = list(range(2025, 2036))
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=years, y=[min(100, (y-2025)*18) for y in years],
            name="Classique (RSA/ECDH)", fill="tozeroy",
            line=dict(color="#f56565", width=2), fillcolor="rgba(245,101,101,0.15)",
        ))
        fig.add_trace(go.Scatter(
            x=years, y=[max(2, 5-(y-2025)*0.3) for y in years],
            name="PQC (ML-KEM/ML-DSA)", fill="tozeroy",
            line=dict(color="#48bb78", width=2), fillcolor="rgba(72,187,120,0.15)",
        ))
        fig.add_vline(x=2030, line_dash="dash", line_color="#ed8936",
                      annotation_text="CRQC estimé 2030")
        fig.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.8)",
            xaxis_title="Année", yaxis_title="Score risque HNDL",
            legend=dict(orientation="h", y=-0.2), height=320, margin=dict(t=20, b=60),
        )
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Stack cryptographique")
    st.code("""
PQC Cyber Defender — Construction hybride

┌─────────────────────────────────────────────────┐
│  Couche Application                             │
│  (Télémétrie drone / Finance / Santé / TLS)     │
├─────────────────────────────────────────────────┤
│  KEM Post-Quantique                             │
│  ML-KEM-768 (Kyber)    — NIST FIPS 203          │
│  FrodoKEM-976          — LWE conservatif ANSSI  │
├─────────────────────────────────────────────────┤
│  Couche symétrique hybride                      │
│  AES-256-GCM + HKDF-SHA3-256 + HMAC-SHA3-256    │
├─────────────────────────────────────────────────┤
│  Authentification (Signatures)                  │
│  ML-DSA-65 (Dilithium) — NIST FIPS 204          │
└─────────────────────────────────────────────────┘
Ref : RFC 9261 · IETF TLS 1.3 + PQC Hybrid
    """, language="text")


elif page == "Benchmark PQC":
    st.title("Benchmark Algorithmes PQC")
    st.markdown(f"Test sur **{selected.value}** avec payload **{data_size} B**.")

    c1, c2 = st.columns([1, 2])
    run_one = c1.button("Tester cet algorithme", use_container_width=True)
    run_all = c2.button("Benchmark tous les KEM", use_container_width=True)

    if run_one:
        with st.spinner(f"Benchmark {selected.value}…"):
            kp   = generate_keys(selected)
            data = simulate_data(data_size, data_type)
            ep   = encrypt(data, kp)
            t0   = time.perf_counter()
            back = decrypt(ep, kp)
            dec_ms = (time.perf_counter() - t0) * 1000

        st.success(f"Déchiffrement : {'OK' if back == data else 'ECHEC'}")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("KeyGen", f"{kp.keygen_ms:.1f} ms")
        c2.metric("Chiffrement", f"{ep.encrypt_ms:.1f} ms")
        c3.metric("Déchiffrement", f"{dec_ms:.1f} ms")
        c4.metric("Overhead", f"{ep.total_size / data_size:.2f}×")

        with st.expander("Détails clés"):
            st.json({
                "Algorithme": selected.value,
                "Catégorie NIST": ALGORITHM_PARAMS[selected]["nist_category"],
                "Clé publique (B)": kp.public_key_size,
                "Clé privée (B)": kp.private_key_size,
                "Taille ciphertext (B)": ep.total_size,
            })

    if run_all:
        with st.spinner("Benchmark complet…"):
            results = run_full_benchmark(data_size=data_size)

        df = pd.DataFrame([{
            "Algorithme": r.algorithm.value,
            "KeyGen (ms)": round(r.keygen_ms, 2),
            "Chiffr. (ms)": round(r.encrypt_ms, 2),
            "Déchiffr. (ms)": round(r.decrypt_ms, 2),
            "Overhead": round(r.overhead_ratio, 2),
            "OK": "✅" if r.decryption_success else "❌",
        } for r in results])
        st.dataframe(df, hide_index=True, use_container_width=True)

        fig = go.Figure()
        for m, c in [("KeyGen (ms)", "#63b3ed"), ("Chiffr. (ms)", "#48bb78"), ("Déchiffr. (ms)", "#ed8936")]:
            fig.add_trace(go.Bar(name=m, x=df["Algorithme"], y=df[m], marker_color=c))
        fig.update_layout(
            template="plotly_dark", barmode="group",
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(15,23,42,0.8)",
            title="Latences (ms)", height=370, xaxis_tickangle=-30,
        )
        st.plotly_chart(fig, use_container_width=True)


elif page == "Simulateur d'attaques":
    st.title("Simulateur d'attaques PQC")
    st.markdown(f"Cible : **{selected.value}** · {n_iter} itérations par vecteur")

    c1, c2 = st.columns([1, 2])
    atk_sel  = c1.selectbox("Attaque unitaire", ["MITM", "Fuzzing", "Interception", "HNDL", "Timing"])
    run_one  = c1.button(f"Lancer {atk_sel}", use_container_width=True)
    run_all  = c2.button("Suite complète d'attaques", use_container_width=True)

    if run_one:
        kp   = generate_keys(selected)
        data = simulate_data(data_size, data_type)
        with st.spinner(f"Attaque {atk_sel}…"):
            fns = {
                "MITM": lambda: mitm_attack(data, kp, n_iter),
                "Fuzzing": lambda: fuzz_attack(data, kp, iterations_per_mode=n_iter),
                "Interception": lambda: intercept_attack(data, kp, n_iter),
                "HNDL": lambda: hndl_attack(data, kp),
                "Timing": lambda: timing_attack(data, kp, n_iter),
            }
            report = fns[atk_sel]()

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Résultat", f"{ri(report.result.value)} {report.result.value}")
        c2.metric("Score vuln.", f"{report.vulnerability_score:.1f}/10")
        c3.metric("Durée", f"{report.duration_ms:.0f} ms")
        c4.metric("Récupération", f"{report.recovery_rate*100:.2f}%")

        with st.expander("Rapport détaillé"): st.json(report.details)
        if report.recommendations:
            st.info("💡 " + " | ".join(report.recommendations[:2]))

    if run_all:
        with st.spinner(f"Suite complète sur {selected.value}…"):
            session = run_full_attack_suite(selected, data_size, data_type)

        df_atk = pd.DataFrame([{
            "Attaque": r.attack_type.value,
            "Résultat": f"{ri(r.result.value)} {r.result.value}",
            "Score vuln.": r.vulnerability_score,
            "Récup. %": round(r.recovery_rate * 100, 2),
            "Durée ms": round(r.duration_ms, 1),
        } for r in session.reports])
        st.dataframe(df_atk, hide_index=True, use_container_width=True)

        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=session.overall_vulnerability,
            title={"text": "Vulnérabilité max", "font": {"color": "white"}},
            gauge={
                "axis": {"range": [0, 10]},
                "bar": {"color": sc(100 - session.overall_vulnerability * 10)},
                "steps": [
                    {"range": [0, 3], "color": "rgba(72,187,120,0.2)"},
                    {"range": [3, 7], "color": "rgba(237,137,54,0.2)"},
                    {"range": [7, 10], "color": "rgba(245,101,101,0.2)"},
                ],
            },
            number={"font": {"color": "white"}, "suffix": "/10"},
        ))
        fig.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            height=280, margin=dict(t=40, b=20),
        )
        st.plotly_chart(fig, use_container_width=True)


elif page == "Analyse & Scoring":
    st.title("Analyse de sécurité & Scoring")

    opts = [a.value for a in Algorithm if ALGORITHM_PARAMS[a]["type"] == "KEM"]
    sel_algos = st.multiselect("Algorithmes à comparer", opts,
                                default=[Algorithm.KYBER_512.value, Algorithm.KYBER_768.value, Algorithm.KYBER_1024.value])

    if st.button("Lancer l'analyse complète") and sel_algos:
        algos = [a for a in Algorithm if a.value in sel_algos]
        sessions, prog = [], st.progress(0)
        for i, a in enumerate(algos):
            with st.spinner(f"Analyse {a.value}…"):
                sessions.append(run_full_attack_suite(a, data_size, data_type))
            prog.progress((i+1)/len(algos))
        prog.empty()

        risks = [compute_security_score(s)[1] for s in sessions]

        fig = go.Figure(go.Bar(
            x=[r.algorithm.value for r in risks],
            y=[r.security_score for r in risks],
            marker_color=[sc(r.security_score) for r in risks],
            text=[f"{r.security_score:.1f}" for r in risks],
            textposition="outside",
        ))
        fig.add_hline(y=70, line_dash="dash", line_color="#ed8936",
                      annotation_text="Seuil minimum ANSSI (Cat.3)")
        fig.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.8)",
            title="Score de sécurité par algorithme", yaxis=dict(range=[0, 105]),
            height=360, xaxis_tickangle=-30,
        )
        st.plotly_chart(fig, use_container_width=True)

        labels = [at.value for at in AttackType if at != AttackType.REPLAY]
        fig_r = go.Figure()
        for r in risks:
            vals = [r.attack_scores.get(l, 5.0) for l in labels]
            vals.append(vals[0])
            fig_r.add_trace(go.Scatterpolar(
                r=vals, theta=labels + [labels[0]],
                name=r.algorithm.value, fill="toself", opacity=0.4,
            ))
        fig_r.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
            polar=dict(radialaxis=dict(range=[0, 10])),
            title="Profil de résistance aux attaques (0-10, plus élevé = meilleur)",
            height=420,
        )
        st.plotly_chart(fig_r, use_container_width=True)

        recs = generate_recommendations(sessions)
        st.subheader("Recommandations priorisées")
        pc = {"CRITICAL": "#e53e3e", "HIGH": "#dd6b20", "MEDIUM": "#d69e2e", "LOW": "#38a169"}
        for rec in recs[:5]:
            c = pc.get(rec["priority"], "#718096")
            st.markdown(
                f"**{rec['id']}** — "
                f"<span style='color:{c};font-weight:bold'>[{rec['priority']}]</span> "
                f"**{rec['title']}**<br>"
                f"<small style='color:#a0aec0'>{rec['description']}</small>",
                unsafe_allow_html=True,
            )
            st.divider()


elif page == "Réseau Drone/IoT":
    st.title("Réseau Drone/IoT sécurisé PQC")

    c1, c2, c3 = st.columns(3)
    n_drones = c1.slider("Drones", 2, 8, 4)
    n_iot    = c2.slider("Capteurs IoT", 1, 6, 3)
    n_rounds = c3.slider("Rondes télémétrie", 1, 5, 3)

    if st.button("Lancer la simulation réseau", use_container_width=True):
        with st.spinner("Initialisation du réseau PQC…"):
            res = run_network_simulation(n_drones, n_iot, n_rounds, run_attacks=True)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Nœuds", res.n_nodes)
        c2.metric("Paquets", res.n_packets)
        c3.metric("Attaques bloquées", f"{res.attacks_blocked}/{res.n_attacks}")
        c4.metric("Score sécurité", f"{res.security_score:.1f}/100")

        df_n = pd.DataFrame([{
            "ID": n["id"], "Nom": n["name"], "Type": n["type"],
            "KEM": n["kem_algorithm"], "TX": n["packets_sent"],
            "RX": n["packets_received"], "Rejetés": n["packets_rejected"],
        } for n in res.node_summaries if "Adverse" not in n["type"]])
        st.dataframe(df_n, hide_index=True, use_container_width=True)

        if res.attack_events:
            df_e = pd.DataFrame([{
                "Attaque": e.attack_type, "Cible": e.target_id,
                "Résultat": e.outcome, "Détails": e.details[:60],
            } for e in res.attack_events])
            st.dataframe(df_e, hide_index=True, use_container_width=True)


elif page == "Export rapport":
    st.title("Export rapport de sécurité")

    opts = [a.value for a in Algorithm if ALGORITHM_PARAMS[a]["type"] == "KEM"]
    sel  = st.multiselect("Algorithmes", opts,
                           default=[Algorithm.KYBER_768.value, Algorithm.KYBER_1024.value])
    c1, c2 = st.columns(2)
    do_pdf  = c1.checkbox("PDF", value=True)
    do_html = c2.checkbox("HTML", value=True)

    if st.button("Générer le rapport", use_container_width=True) and sel:
        algos    = [a for a in Algorithm if a.value in sel]
        sessions = []
        prog     = st.progress(0)
        for i, a in enumerate(algos):
            with st.spinner(f"Suite d'attaques {a.value}…"):
                sessions.append(run_full_attack_suite(a, data_size, data_type))
            prog.progress((i+1)/len(algos))
        prog.empty()

        with st.spinner("Génération rapport…"):
            report = generate_report(sessions, "./reports", do_pdf, do_html)

        st.success(f"Rapport généré — Session {report.session_id}")
        c1, c2 = st.columns(2)
        c1.metric("Score global", f"{report.global_score:.1f}/100")
        c2.metric("Grade", report.global_grade)
        st.write(report.executive_summary)

        if do_pdf and report.export_path_pdf:
            st.download_button(
                "⬇️ Télécharger PDF",
                Path(report.export_path_pdf).read_bytes(),
                f"pqc_report_{report.session_id}.pdf",
                "application/pdf",
                use_container_width=True,
            )
        if do_html and report.export_path_html:
            st.download_button(
                "⬇️ Télécharger HTML",
                Path(report.export_path_html).read_bytes(),
                f"pqc_report_{report.session_id}.html",
                "text/html",
                use_container_width=True,
            )

        st.subheader("Conformité")
        st.dataframe(
            pd.DataFrame([{"Référentiel": k, "Statut": v} for k, v in report.compliance_status.items()]),
            hide_index=True, use_container_width=True,
        )
