import html
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from dashboard_api import analyze_message
from dashboard_utils import (
    average_risk,
    confidence_score,
    dashboard_kpis,
    dataset_quality_metrics,
    decision_reasons,
    geolocate_domains,
    history_csv_bytes,
    is_phishing,
    load_history,
    result_json_bytes,
    result_pdf_bytes,
    risk_score,
    save_history,
    top_domains,
    url_rows,
)


st.set_page_config(
    page_title="Phishing Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
)

COLORS = {
    "navy": "#0f172a",
    "blue": "#2563eb",
    "red": "#dc2626",
    "amber": "#d97706",
    "green": "#059669",
    "muted": "#64748b",
}

BASE_DIR = Path(__file__).resolve().parent
DATASET_CANDIDATES = [
    BASE_DIR / "dataset.csv",
    BASE_DIR / "dataset" / "dataset.csv",
    BASE_DIR.parent / "dataset.csv",
]
DATASET_PATH = next((path for path in DATASET_CANDIDATES if path.exists()), None)

st.markdown(
    """
<style>
.stApp { background: #f5f7fb; }
#MainMenu, footer { visibility: hidden; }
.block-container { padding: 1.8rem 2.8rem 3rem; max-width: 1400px; }
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #111c35 0%, #172554 100%);
    border-right: 1px solid #334d80;
}
section[data-testid="stSidebar"] > div {
    padding-top: 1.8rem;
    background: transparent !important;
}
section[data-testid="stSidebar"] [data-testid="stSidebarContent"],
section[data-testid="stSidebar"] [data-testid="stSidebarUserContent"],
section[data-testid="stSidebar"] [data-testid="stVerticalBlock"],
section[data-testid="stSidebar"] [data-testid="stVerticalBlockBorderWrapper"] {
    background: transparent !important;
    border: 0 !important;
    box-shadow: none !important;
}
.sidebar-title,
.sidebar-title * {
    color: #ffffff !important;
    opacity: 1 !important;
}
.sidebar-title { color: #ffffff; font-size: 24px; font-weight: 800; margin-bottom: 6px; }
.sidebar-subtitle {
    color: #e0f2fe !important;
    opacity: 1 !important;
    font-size: 14px;
    font-weight: 600;
    line-height: 1.5;
    margin-bottom: 24px;
}
.nav-title { color: #7dd3fc !important; font-size: 11px; font-weight: 900; letter-spacing: 1.2px;
    text-transform: uppercase; margin-bottom: 8px; }
section[data-testid="stSidebar"] div[data-testid="stRadio"],
section[data-testid="stSidebar"] div[role="radiogroup"] {
    background: transparent !important;
    border: 0 !important;
    gap: 8px;
}
section[data-testid="stSidebar"] label[data-baseweb="radio"] {
    width: 100%;
    background: #1e3158 !important;
    border: 1px solid #365486 !important;
    border-radius: 10px;
    padding: 11px 13px;
    margin-bottom: 3px;
    box-shadow: none !important;
}
section[data-testid="stSidebar"] label[data-baseweb="radio"] p {
    color: #f8fafc !important;
    font-size: 15px;
    font-weight: 700;
}
section[data-testid="stSidebar"] label[data-baseweb="radio"]:hover {
    background: #294775 !important;
    border-color: #60a5fa !important;
}
section[data-testid="stSidebar"] label[data-baseweb="radio"] > div:first-child { display: none; }
section[data-testid="stSidebar"] label[data-baseweb="radio"]:has(input:checked) {
    background: linear-gradient(90deg, #2563eb, #0284c7) !important;
    border-color: #7dd3fc !important;
    box-shadow: 0 5px 14px rgba(14, 165, 233, .25) !important;
}
section[data-testid="stSidebar"] label[data-baseweb="radio"]:has(input:checked) p {
    color: #ffffff !important;
}
.status-box {
    margin-top: 28px;
    padding: 13px 14px;
    border-radius: 10px;
    font-size: 14px;
    font-weight: 750;
    color: #ecfdf5;
    background: #087f5b;
    border: 1px solid #34d399;
    box-shadow: 0 5px 14px rgba(16, 185, 129, .18);
}
.page-header { background: linear-gradient(120deg, #fff 65%, #eff6ff); border: 1px solid #e2e8f0;
    border-left: 5px solid #2563eb; border-radius: 16px; padding: 22px 26px; margin-bottom: 20px; }
.page-title { color: #0f172a; font-size: 29px; font-weight: 850; margin-bottom: 5px; }
.page-subtitle { color: #64748b; font-size: 15px; line-height: 1.5; }
.section-title { color: #0f172a; font-size: 20px; font-weight: 800; margin: 12px 0 12px; }
.card { background: #fff; border: 1px solid #e2e8f0; border-radius: 14px;
    padding: 20px 22px; margin-bottom: 18px; box-shadow: 0 2px 10px rgba(15,23,42,.03); }
.card-title { color: #0f172a; font-size: 19px; font-weight: 800; margin-bottom: 6px; }
.card-text { color: #64748b; font-size: 14px; line-height: 1.6; }
.metric-card { min-height: 126px; background: #fff; border: 1px solid #e2e8f0;
    border-radius: 14px; padding: 18px 20px; box-shadow: 0 3px 12px rgba(15,23,42,.04); }
.metric-icon { font-size: 19px; margin-bottom: 9px; }
.metric-label { color: #64748b; font-size: 12px; font-weight: 800; letter-spacing: .5px;
    text-transform: uppercase; }
.metric-value { color: #0f172a; font-size: 28px; font-weight: 850; margin-top: 4px; }
.metric-blue { border-top: 4px solid #2563eb; }
.metric-red { border-top: 4px solid #dc2626; }
.metric-green { border-top: 4px solid #059669; }
.metric-amber { border-top: 4px solid #d97706; }
.notice { display: flex; align-items: center; gap: 10px; background: #fff; border: 1px solid #e2e8f0;
    border-radius: 11px; padding: 11px 14px; margin-bottom: 8px; color: #334155; font-weight: 650; }
.dot { width: 11px; height: 11px; border-radius: 50%; display: inline-block; }
.dot-red { background: #ef4444; box-shadow: 0 0 0 4px #fee2e2; }
.dot-amber { background: #f59e0b; box-shadow: 0 0 0 4px #fef3c7; }
.dot-green { background: #10b981; box-shadow: 0 0 0 4px #d1fae5; }
.risk-box { padding: 13px 15px; border-radius: 10px; font-weight: 700; margin: 10px 0 16px; }
.risk-critical, .risk-high { color: #991b1b; background: #fef2f2; border: 1px solid #fecaca; }
.risk-medium { color: #92400e; background: #fffbeb; border: 1px solid #fde68a; }
.risk-low { color: #065f46; background: #ecfdf5; border: 1px solid #a7f3d0; }
.reason { background: #f8fafc; border-left: 3px solid #2563eb; border-radius: 7px;
    padding: 9px 12px; margin-bottom: 7px; color: #334155; }
.stButton > button { background: #1d4ed8; color: #fff; border: 0; border-radius: 9px;
    padding: 10px 22px; font-weight: 750; }
.stButton > button:hover { background: #1e40af; color: #fff; }
.stDownloadButton > button { border-radius: 9px; font-weight: 700; width: 100%; }
div[data-testid="stVerticalBlockBorderWrapper"] { border-radius: 14px; background: #fff; }
section[data-testid="stSidebar"] div[data-testid="stVerticalBlockBorderWrapper"] {
    background: transparent !important;
}
textarea { border-radius: 10px !important; }
</style>
""",
    unsafe_allow_html=True,
)


def page_header(title, subtitle):
    st.markdown(
        f"""
        <div class="page-header">
            <div class="page-title">{html.escape(title)}</div>
            <div class="page-subtitle">{html.escape(subtitle)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label, value, icon, color):
    st.markdown(
        f"""
        <div class="metric-card metric-{color}">
            <div class="metric-icon">{icon}</div>
            <div class="metric-label">{html.escape(label)}</div>
            <div class="metric-value">{html.escape(str(value))}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def show_risk_alert(risk):
    score = risk_score(risk)
    if score >= 100:
        css, text = "risk-critical", "Risque critique : ce message est très dangereux."
    elif score >= 80:
        css, text = "risk-high", "Risque élevé : ce message présente des indicateurs forts."
    elif score >= 50:
        css, text = "risk-medium", "Risque moyen : une vérification est recommandée."
    else:
        css, text = "risk-low", "Risque faible : aucun indicateur fort de phishing."
    st.markdown(f'<div class="risk-box {css}">{text}</div>', unsafe_allow_html=True)


def render_notifications(history):
    latest = history.iloc[0] if not history.empty else None
    if latest is not None and is_phishing(latest["Classification"]):
        st.markdown(
            '<div class="notice"><span class="dot dot-red"></span>Nouvelle attaque détectée dans la dernière analyse</div>',
            unsafe_allow_html=True,
        )
    if average_risk(history) >= 50:
        st.markdown(
            '<div class="notice"><span class="dot dot-amber"></span>Le risque moyen nécessite une surveillance</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="notice"><span class="dot dot-green"></span>Système sécurisé, risque moyen sous contrôle</div>',
            unsafe_allow_html=True,
        )


def render_analysis_result(result, title="Résultat de l'analyse"):
    classification = result.get("classification", "N/A") or "N/A"
    risk_level = result.get("risk_level", "N/A") or "N/A"
    attack_type = result.get("attack_type", "N/A") or "N/A"
    confidence = confidence_score(result)

    st.markdown(f'<div class="section-title">{html.escape(title)}</div>', unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        metric_card("Classification", classification, "🔎", "blue")
    with col2:
        metric_card("Niveau de risque", risk_level, "⚠️", "red")
    with col3:
        metric_card("Type d'attaque", attack_type, "🎯", "amber")
    with col4:
        metric_card("Confiance IA", f"{confidence:.1f}%", "🤖", "green")

    show_risk_alert(risk_level)

    with st.container(border=True):
        st.subheader("Score de confiance IA")
        st.progress(confidence / 100)
        st.caption(f"Confiance estimée : {confidence:.1f}%")

    left, right = st.columns([1, 1])
    with left:
        with st.container(border=True):
            st.subheader("Raisons de la décision")
            reasons = decision_reasons(result)
            if reasons:
                for reason in reasons:
                    st.markdown(
                        f'<div class="reason">✓ {html.escape(reason)}</div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.info("Aucun indicateur détaillé n'a été retourné.")

    with right:
        with st.container(border=True):
            st.subheader("Explication")
            st.write(result.get("explanation") or "Aucune explication disponible.")
            st.subheader("Recommandations")
            recommendations = result.get("recommendations") or "Aucune recommandation."
            if isinstance(recommendations, list):
                for recommendation in recommendations:
                    st.write(f"• {recommendation}")
            else:
                st.write(recommendations)

    with st.container(border=True):
        st.subheader("Détection URL")
        urls = url_rows(result)
        if urls.empty:
            st.info("Aucune URL détectée dans ce message.")
        else:
            st.dataframe(urls, use_container_width=True, hide_index=True)
            st.caption(
                "L'âge du domaine et la blacklist nécessitent des services externes. "
                "Ils sont explicitement marqués comme non vérifiés."
            )

    retrieved = result.get("retrieved_documents") or []
    if retrieved:
        with st.expander("Documents similaires récupérés"):
            st.dataframe(pd.DataFrame(retrieved), use_container_width=True, hide_index=True)

    st.markdown('<div class="section-title">Exporter les résultats</div>', unsafe_allow_html=True)
    export1, export2, export3 = st.columns(3)
    with export1:
        st.download_button(
            "Exporter JSON",
            result_json_bytes(result),
            "analyse_phishing.json",
            "application/json",
        )
    with export2:
        st.download_button(
            "Exporter PDF",
            result_pdf_bytes(result),
            "rapport_phishing.pdf",
            "application/pdf",
        )
    with export3:
        one_row = pd.DataFrame(
            [
                {
                    "Classification": classification,
                    "Risque": risk_level,
                    "Type d'attaque": attack_type,
                    "Confiance": confidence,
                    "Message": result.get("input_message", ""),
                }
            ]
        )
        st.download_button(
            "Exporter CSV",
            one_row.to_csv(index=False).encode("utf-8-sig"),
            "analyse_phishing.csv",
            "text/csv",
        )


with st.sidebar:
    st.markdown(
        """
        <div class="sidebar-title">🛡️ Phishing AI</div>
        <div class="sidebar-subtitle">Centre de supervision et d'analyse des messages suspects.</div>
        <div class="nav-title">Navigation</div>
        """,
        unsafe_allow_html=True,
    )
    page = st.radio(
        "Navigation",
        ["Dashboard", "Analyse", "Statistiques", "Historique", "À propos"],
        label_visibility="collapsed",
    )
    st.markdown('<div class="status-box">● Système actif</div>', unsafe_allow_html=True)


history = load_history()
try:
    dataset = pd.read_csv(DATASET_PATH) if DATASET_PATH else pd.DataFrame()
except (FileNotFoundError, OSError, pd.errors.ParserError):
    dataset = pd.DataFrame()


if page == "Dashboard":
    page_header(
        "Tableau de bord",
        "Vue d'ensemble des détections, tendances et alertes de sécurité.",
    )
    kpis = dashboard_kpis(history, dataset)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        metric_card("Messages analysés", kpis["total"], "📨", "blue")
    with col2:
        metric_card("Phishing détectés", kpis["phishing"], "🚨", "red")
    with col3:
        metric_card("Messages légitimes", kpis["legitimate"], "✅", "green")
    with col4:
        metric_card("Taux de phishing", f"{kpis['phishing_rate']:.1f}%", "📈", "amber")

    st.markdown('<div class="section-title">Notifications</div>', unsafe_allow_html=True)
    render_notifications(history)

    chart1, chart2 = st.columns(2)
    with chart1:
        distribution = pd.DataFrame(
            {
                "Catégorie": ["Phishing", "Légitime"],
                "Nombre": [kpis["phishing"], kpis["legitimate"]],
            }
        )
        fig = px.pie(
            distribution,
            names="Catégorie",
            values="Nombre",
            hole=0.58,
            color="Catégorie",
            color_discrete_map={"Phishing": COLORS["red"], "Légitime": COLORS["green"]},
            title="Répartition du dataset : Phishing / Légitime",
        )
        fig.update_layout(margin=dict(l=20, r=20, t=55, b=20), legend_orientation="h")
        st.plotly_chart(fig, use_container_width=True)

    with chart2:
        if history.empty:
            st.info(
                "La courbe d'évolution apparaîtra après les premières analyses, "
                "car le dataset ne contient pas de dates."
            )
        else:
            daily = history.copy()
            daily["Jour"] = daily["Date"].dt.date
            daily["Phishing"] = daily["Classification"].map(is_phishing).astype(int)
            daily = daily.groupby("Jour", as_index=False)["Phishing"].sum()
            fig = px.line(
                daily,
                x="Jour",
                y="Phishing",
                markers=True,
                title="Évolution des attaques",
                color_discrete_sequence=[COLORS["blue"]],
            )
            fig.update_layout(margin=dict(l=20, r=20, t=55, b=20))
            st.plotly_chart(fig, use_container_width=True)

    attack_source = dataset if not dataset.empty and "attack_type" in dataset.columns else None
    if attack_source is not None:
        attacks = (
            attack_source["attack_type"]
            .fillna("Non classé")
            .replace("", "Non classé")
            .value_counts()
            .head(8)
            .rename_axis("Type d'attaque")
            .reset_index(name="Nombre")
        )
    else:
        attacks = (
            history["Type d'attaque"]
            .replace("", "Non classé")
            .value_counts()
            .head(8)
            .rename_axis("Type d'attaque")
            .reset_index(name="Nombre")
        )

    if not attacks.empty:
        fig = px.bar(
            attacks,
            x="Nombre",
            y="Type d'attaque",
            orientation="h",
            title="Types d'attaques détectés",
            color="Type d'attaque",
            text="Nombre",
            color_discrete_sequence=[
                "#1d4ed8",
                "#059669",
                "#d97706",
                "#dc2626",
                "#7c3aed",
                "#0891b2",
                "#be185d",
                "#475569",
            ],
        )
        fig.update_traces(
            textposition="outside",
            textfont={"color": "#0f172a", "size": 14},
            marker_line_color="#0f172a",
            marker_line_width=0.5,
            opacity=1,
        )
        fig.update_layout(
            margin=dict(l=20, r=20, t=55, b=20),
            yaxis={"categoryorder": "total ascending"},
            showlegend=False,
            paper_bgcolor="#ffffff",
            plot_bgcolor="#ffffff",
            font={"color": "#1e293b", "size": 13},
            xaxis={
                "gridcolor": "#cbd5e1",
                "zerolinecolor": "#94a3b8",
                "title": "Nombre de détections",
            },
            yaxis_title="Type d'attaque",
        )
        st.plotly_chart(fig, use_container_width=True)

    st.download_button(
        "Télécharger l'historique CSV",
        history_csv_bytes(history),
        "historique_analyses.csv",
        "text/csv",
    )


elif page == "Analyse":
    page_header(
        "Analyse détaillée",
        "Analysez un email, SMS ou message et obtenez une décision expliquée.",
    )
    st.markdown(
        """
        <div class="card">
            <div class="card-title">Nouveau message</div>
            <div class="card-text">
                Collez le contenu complet. Les URLs, formulations urgentes et demandes sensibles
                seront examinées avec le moteur RAG.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    message = st.text_area(
        "Message à analyser",
        height=180,
        placeholder="Exemple : Your bank account has been suspended. Click here...",
    )
    if st.button("Analyser le message", use_container_width=False):
        if not message.strip():
            st.warning("Veuillez entrer un message.")
        else:
            with st.spinner("Analyse en cours..."):
                result = analyze_message(message)
            save_history(message, result)
            st.session_state["last_analysis"] = result
            st.success("Analyse terminée et ajoutée à l'historique.")

    if st.session_state.get("last_analysis"):
        render_analysis_result(st.session_state["last_analysis"])


elif page == "Statistiques":
    page_header(
        "Statistiques avancées",
        "Domaines détectés, niveau de risque et aperçu du dataset.",
    )
    try:
        dataset = pd.read_csv(DATASET_PATH) if DATASET_PATH else pd.DataFrame()
    except (FileNotFoundError, OSError):
        dataset = pd.DataFrame()

    messages = list(history["Message"])
    if not dataset.empty and "text" in dataset.columns:
        messages.extend(dataset["text"].dropna().astype(str).tolist())

    st.subheader("Analyse du dataset")
    quality = dataset_quality_metrics(dataset)
    quality1, quality2, quality3, quality4 = st.columns(4)
    with quality1:
        metric_card("Messages analysés", quality["rows"], "📚", "blue")
    with quality2:
        metric_card("Textes uniques", quality["unique_texts"], "📝", "green")
    with quality3:
        metric_card("Taux de doublons", f"{quality['duplicate_rate']:.1f}%", "♻️", "amber")
    with quality4:
        attack_type_count = (
            int(dataset["attack_type"].nunique())
            if not dataset.empty and "attack_type" in dataset.columns
            else 0
        )
        metric_card("Types d'attaques", attack_type_count, "🎯", "red")

    st.info(
        "Le dataset contient plusieurs indicateurs exploitables : URLs détectées, "
        "mots-clés suspects, types d'attaques variés et plusieurs niveaux de risque."
    )

    col1, col2 = st.columns([1.35, 1])
    with col1:
        st.subheader("Top 10 domaines détectés")
        domains = top_domains(messages)
        if domains.empty:
            st.info("Aucun domaine trouvé dans les données.")
        else:
            st.dataframe(domains, use_container_width=True, hide_index=True)
            fig = px.bar(
                domains.sort_values("Occurrences"),
                x="Occurrences",
                y="Domaine",
                orientation="h",
                color="Occurrences",
                color_continuous_scale="Reds",
            )
            fig.update_layout(coloraxis_showscale=False, margin=dict(l=10, r=10, t=20, b=10))
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Risque moyen")
        score = average_risk(history)
        gauge = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=score,
                number={"suffix": "%"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": COLORS["blue"]},
                    "steps": [
                        {"range": [0, 35], "color": "#d1fae5"},
                        {"range": [35, 70], "color": "#fef3c7"},
                        {"range": [70, 100], "color": "#fee2e2"},
                    ],
                    "threshold": {
                        "line": {"color": COLORS["red"], "width": 4},
                        "thickness": 0.75,
                        "value": score,
                    },
                },
            )
        )
        gauge.update_layout(height=300, margin=dict(l=25, r=25, t=35, b=10))
        st.plotly_chart(gauge, use_container_width=True)

    if not dataset.empty:
        st.subheader("Répartition des données")
        chart_language, chart_source, chart_risk = st.columns(3)

        with chart_language:
            language_counts = (
                dataset["language"]
                .value_counts()
                .rename_axis("Langue")
                .reset_index(name="Messages")
            )
            fig = px.bar(
                language_counts,
                x="Langue",
                y="Messages",
                color="Langue",
                text="Messages",
                title="Messages par langue",
                color_discrete_sequence=["#2563eb", "#059669", "#d97706"],
            )
            fig.update_layout(showlegend=False, margin=dict(l=10, r=10, t=50, b=10))
            st.plotly_chart(fig, use_container_width=True)

        with chart_source:
            source_counts = (
                dataset["source_type"]
                .value_counts()
                .rename_axis("Canal")
                .reset_index(name="Messages")
            )
            fig = px.pie(
                source_counts,
                names="Canal",
                values="Messages",
                hole=0.45,
                title="Répartition par canal",
                color_discrete_sequence=px.colors.qualitative.Bold,
            )
            fig.update_layout(margin=dict(l=10, r=10, t=50, b=10))
            st.plotly_chart(fig, use_container_width=True)

        with chart_risk:
            risk_order = ["low", "medium", "high", "critical"]
            risk_counts = (
                dataset["risk_level"]
                .value_counts()
                .reindex(risk_order, fill_value=0)
                .rename_axis("Risque")
                .reset_index(name="Messages")
            )
            fig = px.bar(
                risk_counts,
                x="Risque",
                y="Messages",
                color="Risque",
                text="Messages",
                title="Niveaux de risque",
                color_discrete_map={
                    "low": "#059669",
                    "medium": "#d97706",
                    "high": "#ea580c",
                    "critical": "#dc2626",
                },
            )
            fig.update_layout(showlegend=False, margin=dict(l=10, r=10, t=50, b=10))
            st.plotly_chart(fig, use_container_width=True)

        st.subheader("Relation entre attaques et niveaux de risque")
        attack_risk = pd.crosstab(dataset["attack_type"], dataset["risk_level"])
        attack_risk = attack_risk.reindex(columns=risk_order, fill_value=0)
        heatmap = px.imshow(
            attack_risk,
            text_auto=True,
            aspect="auto",
            color_continuous_scale="YlOrRd",
            labels={
                "x": "Niveau de risque",
                "y": "Type d'attaque",
                "color": "Messages",
            },
        )
        heatmap.update_layout(height=470, margin=dict(l=20, r=20, t=20, b=20))
        st.plotly_chart(heatmap, use_container_width=True)

    st.subheader("Carte réelle des serveurs hébergeant les domaines")
    st.caption(
        "La position correspond à l'adresse IP publique du serveur du domaine. "
        "Elle ne représente pas nécessairement la localisation de l'attaquant."
    )
    refresh_geo = st.button("Actualiser la carte réelle", type="secondary")
    if refresh_geo:
        with st.spinner("Résolution DNS et géolocalisation GeoIP des principaux domaines..."):
            geo_data, geo_failures = geolocate_domains(
                messages,
                limit=10,
                refresh=True,
                lookup_missing=True,
            )
        st.session_state["geo_data"] = geo_data
        st.session_state["geo_failures"] = geo_failures
    else:
        geo_data, geo_failures = geolocate_domains(
            messages,
            limit=10,
            lookup_missing=False,
        )
        if not geo_data.empty:
            st.session_state["geo_data"] = geo_data
            st.session_state["geo_failures"] = geo_failures

    geo_data = st.session_state.get("geo_data", geo_data)
    geo_failures = st.session_state.get("geo_failures", geo_failures)

    if geo_data.empty:
        st.info(
            "Cliquez sur « Actualiser la carte réelle » pour résoudre et "
            "géolocaliser les 10 domaines les plus fréquents."
        )
    else:
        map_col, table_col = st.columns([2, 1])
        with map_col:
            fig = px.scatter_geo(
                geo_data,
                lat="Latitude",
                lon="Longitude",
                size="Occurrences",
                color="Occurrences",
                hover_name="Domaine",
                hover_data={
                    "Pays": True,
                    "Ville": True,
                    "IP": True,
                    "Organisation": True,
                    "Latitude": False,
                    "Longitude": False,
                },
                projection="natural earth",
                color_continuous_scale="Reds",
                size_max=32,
                title="Localisation GeoIP des serveurs résolus",
            )
            fig.update_layout(height=430, margin=dict(l=0, r=0, t=50, b=0))
            st.plotly_chart(fig, use_container_width=True)
        with table_col:
            st.dataframe(
                geo_data[
                    ["Domaine", "IP", "Pays", "Ville", "Occurrences"]
                ],
                use_container_width=True,
                hide_index=True,
            )
            if geo_failures:
                st.caption(
                    f"{geo_failures} domaine(s) non affiché(s), car leur DNS ou "
                    "leur géolocalisation n'a pas pu être résolu."
                )

    if not dataset.empty:
        with st.expander("Aperçu du dataset"):
            st.dataframe(dataset.head(20), use_container_width=True, hide_index=True)


elif page == "Historique":
    page_header(
        "Historique des analyses",
        "Consultez les messages analysés et ouvrez le détail d'une détection.",
    )
    if history.empty:
        st.info("Aucune analyse enregistrée pour le moment.")
    else:
        filters1, filters2 = st.columns(2)
        with filters1:
            classification_filter = st.selectbox(
                "Classification",
                ["Toutes"] + sorted(history["Classification"].unique().tolist()),
            )
        with filters2:
            risk_filter = st.selectbox(
                "Niveau de risque",
                ["Tous"] + sorted(history["Risque"].unique().tolist()),
            )

        filtered = history.copy()
        if classification_filter != "Toutes":
            filtered = filtered[filtered["Classification"] == classification_filter]
        if risk_filter != "Tous":
            filtered = filtered[filtered["Risque"] == risk_filter]

        display = filtered.copy()
        display["Date"] = display["Date"].dt.strftime("%Y-%m-%d %H:%M:%S")
        st.dataframe(display, use_container_width=True, hide_index=True)
        st.download_button(
            "Exporter la sélection CSV",
            history_csv_bytes(filtered),
            "historique_filtre.csv",
            "text/csv",
        )

        if not filtered.empty:
            options = {
                f"{row.Date:%Y-%m-%d %H:%M} | {row.Classification} | {row.Message[:70]}": index
                for index, row in filtered.iterrows()
            }
            selected = st.selectbox("Ouvrir une analyse", list(options))
            row = filtered.loc[options[selected]]
            historical_result = {
                "input_message": row["Message"],
                "classification": row["Classification"],
                "risk_level": row["Risque"],
                "attack_type": row["Type d'attaque"],
                "detected_elements": [],
                "url_analysis": [],
                "explanation": (
                    "Les indicateurs ci-dessous ont été reconstruits automatiquement "
                    "à partir du texte conservé dans l'historique."
                ),
                "recommendations": (
                    "Ne cliquez pas sur les liens suspects, ne communiquez aucune donnée "
                    "sensible et vérifiez la demande depuis le site officiel."
                ),
            }
            render_analysis_result(historical_result, "Détail du message sélectionné")


else:
    page_header(
        "À propos",
        "Architecture et périmètre du système de détection.",
    )
    st.markdown(
        """
        <div class="card">
            <div class="card-title">Phishing Detection Dashboard</div>
            <div class="card-text">
                Cette application combine recherche de documents similaires, génération assistée
                par IA, détection heuristique d'URLs et visualisation des résultats. Le dashboard
                présente les KPI, les tendances, les raisons de décision et les exports nécessaires
                à une démonstration ou une soutenance.
                <br><br>
                Les informations externes telles que l'âge exact d'un domaine, sa présence sur une
                blacklist ou sa géolocalisation IP ne sont pas inventées : elles restent indiquées
                comme non vérifiées tant qu'aucun service externe n'est connecté.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown("**Composants :** Streamlit, Plotly, FastAPI, moteur RAG et analyseur d'URLs.")
    st.markdown(f"**Fichier d'historique :** `{Path('results/analysis_history.csv')}`")
