"""
app.py — Tableau de bord de supervision (Zero-Touch)

Lit la base SQLite alimentée par device_connector.py et build_database.py :
  - Vue d'ensemble : état actuel de chaque équipement, anomalies par règle et par risque
  - Avant / Après : effet d'une correction automatique (scan SSH -> scan post-correction)
  - Correctifs : suivi de chaque correctif (en attente, appliqué, vérifié, rejeté...)
  - Détail d'un scan : anomalies, correctifs suggérés, exports
  - Test hors-ligne : analyse d'un fichier de config sans connexion SSH

Usage (depuis src/) :
    python -m streamlit run app.py
"""

import contextlib
import io
import os
import sqlite3
import tempfile

import pandas as pd
import streamlit as st

from parser import parse_config
from rule_engine import load_rules, analyze_config

try:
    import ml_model
except Exception:  # scikit-learn absent ou module introuvable : la colonne reste vide
    ml_model = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(BASE_DIR, "..", "rules", "rules.yaml")
DB_PATH = os.path.join(BASE_DIR, "..", "pfe_database.db")

RISK_ICON = {"High": "🔴", "Medium": "🟠", "Low": "🟡"}
LABEL_TEXT = {"secure": "🟢 secure", "weak": "🔴 weak"}
STATUS_TEXT = {
    "verified": "✅ vérifié (disparu au re-scan)",
    "unverified": "⚠️ accepté, anomalie toujours détectée",
    "applied": "🟦 appliqué (non vérifié)",
    "failed": "❌ rejeté par l'équipement",
    "pending": "⏳ en attente",
}

st.set_page_config(page_title="Supervision — Anomalies de configuration", layout="wide")


# ---------------------------------------------------------------------------
# Accès à la base (ne crée jamais de fichier vide si la base n'existe pas)
# ---------------------------------------------------------------------------

def query(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    try:
        return pd.read_sql_query(sql, conn, params=params)
    finally:
        conn.close()


def device_key(filename, source):
    """Nom de l'équipement : pour les scans SSH, le nom sans suffixe de scan."""
    if source in ("ssh", "ssh_post_fix"):
        return filename.replace("_ssh_scan_post_fix", "").replace("_ssh_scan", "")
    return filename


def ml_atypia(raw_config):
    """Atypie statistique d'une configuration (None si aucun modèle n'est disponible)."""
    if ml_model is None or not isinstance(raw_config, str):
        return None
    try:
        return ml_model.score_config_text(raw_config)
    except Exception:
        return None


def date_text(value):
    return value if isinstance(value, str) and value else "date inconnue"


def has_text(series):
    return series.fillna("").astype(str).str.strip() != ""


# ---------------------------------------------------------------------------
# Affichage commun : tableau d'anomalies + correctifs + exports
# ---------------------------------------------------------------------------

def render_findings(df, file_stem, key):
    """df : colonnes rule_id, risk_level, description, detail, recommendation, code_fix
    (+ confidence, auto_apply en option)."""
    if df.empty:
        st.success("Aucune anomalie détectée sur cette configuration. ✓")
        return

    view = df.copy()
    view["Risque"] = view["risk_level"].map(RISK_ICON).fillna("") + " " + view["risk_level"]
    columns = ["rule_id", "Risque", "description", "detail", "recommendation"]
    names = {"rule_id": "Règle", "description": "Description", "detail": "Détail",
             "recommendation": "Recommandation"}
    if "confidence" in view.columns:
        columns.append("confidence")
        names["confidence"] = "Confiance"
    if "auto_apply" in view.columns:
        view["auto_apply"] = view["auto_apply"].map({True: "oui", False: "non"})
        columns.append("auto_apply")
        names["auto_apply"] = "Auto-applicable"
    st.dataframe(view[columns].rename(columns=names), hide_index=True)

    with_fix = df[has_text(df["code_fix"])]
    lines = [f"! Correctifs suggérés pour {file_stem}",
             "! Généré automatiquement — À RELIRE avant toute application", "!"]
    for _, a in with_fix.iterrows():
        lines += [f"! {a['rule_id']} — {a['description']}", a["code_fix"].replace("\\n", "\n"), "!"]

    col_csv, col_fix = st.columns(2)
    with col_csv:
        st.download_button("📥 Rapport (CSV)",
                           view[columns].rename(columns=names).to_csv(index=False).encode("utf-8-sig"),
                           file_name=f"rapport_{file_stem}.csv", mime="text/csv",
                           key=f"csv_{key}")
    with col_fix:
        st.download_button("🛠️ Correctifs suggérés (.txt)", "\n".join(lines).encode("utf-8"),
                           file_name=f"correctifs_{file_stem}.txt", mime="text/plain",
                           key=f"fix_{key}")

    if with_fix.empty:
        st.caption("Aucun correctif enregistré pour ce scan (scan antérieur à l'ajout des correctifs en base).")
        return
    st.markdown("**🛠️ Correctifs suggérés** (à valider avant application)")
    for _, a in with_fix.iterrows():
        with st.expander(f"{RISK_ICON.get(a['risk_level'], '')} {a['rule_id']} — {a['description']}"):
            st.write(f"**Détail :** {a['detail']}")
            st.code(a["code_fix"].replace("\\n", "\n"), language="text")


# ---------------------------------------------------------------------------
# Barre latérale : scan SSH à la demande (scan seul, aucune modification)
# ---------------------------------------------------------------------------

st.title("🔍 Supervision des anomalies de configuration")
st.caption("Pipeline Zero-Touch : scan SSH → analyse → correction → vérification → base de données")

st.sidebar.header("Actions")
if st.sidebar.button("🔄 Lancer un scan SSH", type="primary"):
    try:
        import device_connector
    except ImportError as e:
        st.sidebar.error(f"device_connector.py introuvable ou Netmiko manquant : {e}")
    else:
        buffer = io.StringIO()
        with st.spinner("Scan en cours..."):
            try:
                with contextlib.redirect_stdout(buffer):
                    device_connector.run_pipeline(apply_fixes=False)
            except Exception as e:
                buffer.write(f"\nERREUR : {e}\n")
        st.session_state["last_scan_log"] = buffer.getvalue()
        st.rerun()
st.sidebar.caption("Scan seul : lit et analyse la configuration, n'envoie aucune modification à l'équipement. "
                   "Le VPN doit être connecté.")
if "last_scan_log" in st.session_state:
    with st.sidebar.expander("Journal du dernier scan"):
        st.code(st.session_state["last_scan_log"], language="text")

if not os.path.exists(DB_PATH):
    st.error(f"Base de données introuvable : {os.path.abspath(DB_PATH)}. "
             f"Lance d'abord build_database.py ou device_connector.py.")
    st.stop()

configs = query("SELECT id, filename, device_type, hostname, anomaly_count, label, scanned_at, host, source "
                "FROM configs ORDER BY id")
if configs.empty:
    st.info("La base ne contient aucune configuration. Lance build_database.py ou device_connector.py.")
    st.stop()
configs["device"] = [device_key(f, s) for f, s in zip(configs["filename"], configs["source"])]

tab_over, tab_ba, tab_fix, tab_scan, tab_off = st.tabs([
    "📊 Vue d'ensemble", "🔁 Avant / Après correction", "🛠️ Correctifs",
    "🔍 Détail d'un scan", "🧪 Test hors-ligne",
])

# ===========================================================================
# 1. Vue d'ensemble
# ===========================================================================
with tab_over:
    latest = configs.sort_values("id").groupby("device").tail(1)
    n_secure = int((latest["label"] == "secure").sum())

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Équipements / configs suivis", len(latest))
    c2.metric("Scans en base", len(configs))
    c3.metric("Scans SSH", int((configs["source"] != "file").sum()))
    c4.metric("Configs 'secure' (dernier état)", f"{n_secure} / {len(latest)}")

    st.subheader("Dernier état de chaque équipement")
    state = latest.sort_values("anomaly_count", ascending=False).copy()
    state["Statut"] = state["label"].map(LABEL_TEXT)
    state["scanned_at"] = state["scanned_at"].fillna("—")
    _ids = [int(i) for i in state["id"]]
    _raw = query("SELECT id, raw_config FROM configs WHERE id IN (%s)" % ",".join("?" * len(_ids)), tuple(_ids))
    _raw_by_id = dict(zip(_raw["id"], _raw["raw_config"]))
    _ml = [ml_atypia(_raw_by_id.get(i)) for i in _ids]
    state["Atypie (ML)"] = [f"{r['atypical_share']:.0%}" if r else "—" for r in _ml]
    st.dataframe(
        state[["device", "device_type", "hostname", "anomaly_count", "Statut", "Atypie (ML)", "source", "scanned_at"]]
        .rename(columns={"device": "Équipement / fichier", "device_type": "Type", "hostname": "Hostname",
                         "anomaly_count": "Anomalies", "source": "Source", "scanned_at": "Date du scan"}),
        hide_index=True,
    )
    st.caption("Atypie (ML) : part des configurations de référence jugées plus normales (Isolation Forest). "
               "Indicateur complémentaire des règles, pas une preuve de faille ; « — » si aucun modèle n'est sauvegardé.")
    st.caption("Le label 'weak' est attribué dès qu'une anomalie confirmée existe (risque High, ou Medium "
               "issu d'une règle à confiance élevée). Les constats d'hygiène ne le modifient pas.")

    ids = [int(i) for i in latest["id"]]
    placeholders = ",".join("?" * len(ids))
    findings = query(f"SELECT config_id, rule_id, risk_level FROM anomalies WHERE config_id IN ({placeholders})",
                     tuple(ids))
    if findings.empty:
        st.success("Aucune anomalie dans le dernier état des équipements.")
    else:
        left, right = st.columns(2)
        with left:
            st.subheader("Anomalies par règle")
            st.bar_chart(findings.groupby("rule_id").size().sort_index())
        with right:
            st.subheader("Anomalies par niveau de risque")
            st.bar_chart(findings["risk_level"].value_counts().reindex(["High", "Medium", "Low"], fill_value=0))

# ===========================================================================
# 2. Avant / Après correction
# ===========================================================================
with tab_ba:
    after_scans = configs[configs["source"] == "ssh_post_fix"].sort_values("id", ascending=False)
    if after_scans.empty:
        st.info("Aucun scan post-correction en base. Il est créé par "
                "'python device_connector.py --full-auto' sur un équipement avec auto_fix: true.")
    else:
        options = {f"#{r.id} — {r.device} ({date_text(r.scanned_at)})": int(r.id)
                   for r in after_scans.itertuples()}
        choice = st.selectbox("Correction à examiner :", list(options.keys()))
        after_id = options[choice]
        after_row = configs[configs["id"] == after_id].iloc[0]

        candidates = configs[(configs["source"] == "ssh") & (configs["device"] == after_row["device"])
                             & (configs["id"] < after_id)].sort_values("id")
        if candidates.empty:
            st.warning("Aucun scan 'avant correction' trouvé pour cet équipement.")
        else:
            before_id = int(candidates.iloc[-1]["id"])
            before = query("SELECT rule_id, risk_level, description, detail FROM anomalies WHERE config_id = ?",
                           (before_id,))
            after = query("SELECT rule_id, detail FROM anomalies WHERE config_id = ?", (after_id,))
            still = set(zip(after["rule_id"], after["detail"]))
            before["Après correction"] = ["⚠️ toujours détectée" if (r, d) in still else "✅ disparue"
                                          for r, d in zip(before["rule_id"], before["detail"])]
            fixes = query("SELECT rule_id, status, code_fix FROM fixes WHERE config_id = ? ORDER BY id",
                          (before_id,))

            st.caption(f"Scan avant : #{before_id} · scan après : #{after_id}")
            m1, m2, m3 = st.columns(3)
            m1.metric("Anomalies avant", len(before))
            m2.metric("Anomalies après", len(after), delta=len(after) - len(before), delta_color="inverse")
            m3.metric("Disparues", int((before["Après correction"] == "✅ disparue").sum()))

            counts = fixes["status"].value_counts().to_dict() if not fixes.empty else {}
            if counts:
                st.markdown("**Statut des correctifs de ce scan :** " + " · ".join(
                    f"{STATUS_TEXT.get(s, s)} : {n}" for s, n in counts.items()))
            if "applied" in counts:
                st.caption("🟦 'appliqué' = accepté par l'équipement, sans vérification automatique "
                           "(enregistrement antérieur à la vérification par re-scan). "
                           "Le tableau ci-dessous montre quelles anomalies ont réellement disparu.")

            st.subheader("Anomalies du scan avant correction")
            before["Risque"] = before["risk_level"].map(RISK_ICON).fillna("") + " " + before["risk_level"]
            st.dataframe(before[["rule_id", "Risque", "description", "detail", "Après correction"]]
                         .rename(columns={"rule_id": "Règle", "description": "Description", "detail": "Détail"}),
                         hide_index=True)

            if not fixes.empty:
                st.subheader("Correctifs de ce scan")
                shown = fixes.copy()
                shown["Statut"] = shown["status"].map(STATUS_TEXT).fillna(shown["status"])
                shown["Commandes"] = shown["code_fix"].fillna("").str.replace("\\n", " ⏎ ", regex=False) \
                    .str.replace("\n", " ⏎ ", regex=False)
                st.dataframe(shown[["rule_id", "Statut", "Commandes"]].rename(columns={"rule_id": "Règle"}),
                             hide_index=True)

# ===========================================================================
# 3. Correctifs
# ===========================================================================
with tab_fix:
    all_fixes = query("""SELECT f.id, f.config_id, f.rule_id, f.status, f.code_fix, f.created_at, f.updated_at,
                                c.filename, c.source
                         FROM fixes f JOIN configs c ON c.id = f.config_id ORDER BY f.id DESC""")
    if all_fixes.empty:
        st.info("Aucun correctif enregistré. Ils sont créés à chaque scan SSH.")
    else:
        all_fixes["device"] = [device_key(f, s) for f, s in zip(all_fixes["filename"], all_fixes["source"])]
        only_current = st.checkbox("Masquer les correctifs en attente des anciens scans (doublons)", value=True)
        if only_current:
            latest_cfg = all_fixes.groupby("device")["config_id"].transform("max")
            all_fixes = all_fixes[(all_fixes["status"] != "pending") | (all_fixes["config_id"] == latest_cfg)]
        counts = all_fixes["status"].value_counts()
        columns = st.columns(len(STATUS_TEXT))
        for col, (status, text) in zip(columns, STATUS_TEXT.items()):
            col.metric(text.split(" (")[0].split(",")[0], int(counts.get(status, 0)))

        wanted = st.multiselect("Filtrer par statut :", list(STATUS_TEXT.keys()),
                                default=list(STATUS_TEXT.keys()),
                                format_func=lambda s: STATUS_TEXT[s])
        view = all_fixes[all_fixes["status"].isin(wanted)].copy()
        view["Statut"] = view["status"].map(STATUS_TEXT).fillna(view["status"])
        view["Commandes"] = view["code_fix"].fillna("").str.replace("\\n", " ⏎ ", regex=False) \
            .str.replace("\n", " ⏎ ", regex=False)
        view["updated_at"] = view["updated_at"].fillna("—")
        st.dataframe(view[["id", "device", "rule_id", "Statut", "Commandes", "updated_at"]]
                     .rename(columns={"id": "N°", "device": "Équipement", "rule_id": "Règle",
                                      "updated_at": "Dernière mise à jour"}),
                     hide_index=True)
        st.caption("⏳ en attente : correctif jamais appliqué automatiquement (placeholder à renseigner, règle "
                   "non autorisée en automatique, ou aucun correctif exécutable).")

# ===========================================================================
# 4. Détail d'un scan
# ===========================================================================
with tab_scan:
    options = {f"#{r.id} — {r.filename} · {r.source} · {date_text(r.scanned_at)}": int(r.id)
               for r in configs.sort_values("id", ascending=False).itertuples()}
    choice = st.selectbox("Scan à inspecter :", list(options.keys()), key="scan_choice")
    scan_id = options[choice]
    scan_row = configs[configs["id"] == scan_id].iloc[0]

    st.markdown(f"**{scan_row['device']}** — type : {scan_row['device_type']} — "
                f"{LABEL_TEXT.get(scan_row['label'], scan_row['label'])} — "
                f"{int(scan_row['anomaly_count'])} anomalie(s)")
    _r = query("SELECT raw_config FROM configs WHERE id = ?", (scan_id,))
    _m = ml_atypia(_r.iloc[0]["raw_config"]) if not _r.empty else None
    if _m:
        st.caption(f"Atypie statistique (Isolation Forest) : plus atypique que {_m['atypical_share']:.0%} des "
                   f"{_m['n_ref']} configurations de référence (score {_m['score']:+.3f}). Indicateur complémentaire des règles.")
    detail = query("SELECT rule_id, risk_level, description, detail, recommendation, code_fix "
                   "FROM anomalies WHERE config_id = ?", (scan_id,))
    render_findings(detail, f"scan{scan_id}", key=f"scan{scan_id}")

    raw = query("SELECT raw_config FROM configs WHERE id = ?", (scan_id,))
    if not raw.empty and isinstance(raw.iloc[0]["raw_config"], str):
        with st.expander("Voir la configuration brute"):
            st.code(raw.iloc[0]["raw_config"], language="text")

# ===========================================================================
# 5. Test hors-ligne
# ===========================================================================
with tab_off:
    st.caption("Analyse un fichier de config sans connexion SSH (mode de secours / démonstration). "
               "Rien n'est enregistré en base.")
    uploaded = st.file_uploader("Dépose un fichier de configuration Cisco (.cfg, .txt, .ios, .conf)",
                                type=None, key="offline_upload")
    if uploaded is None:
        st.info("👆 Dépose un fichier pour lancer l'analyse.")
    else:
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".cfg", delete=False) as tmp:
            tmp.write(uploaded.getvalue())
            tmp_path = tmp.name
        try:
            found = analyze_config(parse_config(tmp_path), load_rules(RULES_PATH))
        finally:
            os.remove(tmp_path)
        columns = ["rule_id", "risk_level", "description", "detail", "recommendation",
                   "code_fix", "confidence", "auto_apply"]
        offline_df = pd.DataFrame(found, columns=columns)
        st.subheader(f"{len(offline_df)} anomalie(s) détectée(s)")
        render_findings(offline_df, os.path.splitext(uploaded.name)[0], key="offline")
        with st.expander("Voir la configuration brute analysée"):
            st.code(uploaded.getvalue().decode("utf-8", errors="ignore"), language="text")