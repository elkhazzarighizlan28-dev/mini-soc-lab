"""
Mini SOC Dashboard v2 — version renforcée.

Sécurité :
  - Authentification (PBKDF2 + comparaison à temps constant), verrouillage
    temporaire après échecs, expiration de session, fail-closed
  - Chemin du rapport figé, refus des liens symboliques, taille/lignes limitées
  - Regex bornées (anti-ReDoS) + validation stricte des IP (module ipaddress)
  - Aucun HTML non fiable rendu (pas de unsafe_allow_html)
  - Export CSV protégé contre l'injection de formules
  - Journal d'audit (connexions, exports) sans mot de passe
  - Empreinte SHA-256 du rapport affichée (contrôle d'intégrité)

Configuration du mot de passe : voir le README ci-dessous (SOC_PASSWORD_HASH).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = (BASE_DIR / "reports").resolve()
REPORT_NAME = "security_report.txt"
LOG_DIR = BASE_DIR / "logs"

MAX_REPORT_BYTES = 5 * 1024 * 1024   # 5 Mo
MAX_LINES = 100_000
MAX_LINE_LEN = 500
RAW_VIEW_LINES = 1_000

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 120
SESSION_TIMEOUT = 15 * 60            # 15 min d'inactivité
MAX_PASSWORD_LEN = 128

RISK_ORDER = ["Low", "Medium", "High", "Critical"]
RISK_COLORS = ["#2e7d32", "#f9a825", "#ef6c00", "#c62828"]

st.set_page_config(page_title="Mini SOC Dashboard", page_icon="🛡️", layout="wide")


# --------------------------------------------------------------------------
# Journal d'audit
# --------------------------------------------------------------------------
@st.cache_resource
def get_audit_logger() -> logging.Logger:
    LOG_DIR.mkdir(exist_ok=True)
    logger = logging.getLogger("soc_dashboard_audit")
    if not logger.handlers:
        handler = logging.FileHandler(LOG_DIR / "dashboard_audit.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


audit = get_audit_logger()


# --------------------------------------------------------------------------
# Authentification
# --------------------------------------------------------------------------
def _get_stored_hash() -> str | None:
    """Hash attendu : 'pbkdf2_sha256$iterations$salt_hex$hash_hex'."""
    try:
        value = st.secrets.get("SOC_PASSWORD_HASH")
        if value:
            return str(value)
    except Exception:
        pass
    return os.environ.get("SOC_PASSWORD_HASH")


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        derived = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(derived.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def require_auth() -> None:
    stored = _get_stored_hash()
    if not stored:
        st.error("🔒 Authentification non configurée : accès refusé (fail-closed).")
        st.caption("Définis SOC_PASSWORD_HASH dans .streamlit/secrets.toml ou en variable d'environnement.")
        st.stop()

    now = time.time()
    if st.session_state.get("auth_ok"):
        if now - st.session_state.get("last_active", 0) < SESSION_TIMEOUT:
            st.session_state["last_active"] = now
            return
        st.session_state["auth_ok"] = False
        audit.info("Session expirée")
        st.warning("Session expirée, reconnecte-toi.")

    if now < st.session_state.get("locked_until", 0):
        remaining = int(st.session_state["locked_until"] - now)
        st.error(f"Trop de tentatives. Réessaie dans {remaining} s.")
        st.stop()

    st.title("🛡️ Mini SOC — Login")
    with st.form("login_form"):
        password = st.text_input("Password", type="password", max_chars=MAX_PASSWORD_LEN)
        submitted = st.form_submit_button("Sign in")

    if submitted:
        time.sleep(0.5)  # ralentit le brute force
        if _verify_password(password, stored):
            st.session_state.update(auth_ok=True, last_active=now, failed_logins=0)
            audit.info("Connexion réussie")
            st.rerun()
        else:
            fails = st.session_state.get("failed_logins", 0) + 1
            st.session_state["failed_logins"] = fails
            audit.warning("Échec de connexion (%d)", fails)
            if fails >= MAX_LOGIN_ATTEMPTS:
                st.session_state["locked_until"] = now + LOCKOUT_SECONDS
                st.session_state["failed_logins"] = 0
                audit.warning("Verrouillage temporaire déclenché")
            st.error("Identifiants invalides.")
    st.stop()


# --------------------------------------------------------------------------
# Lecture sécurisée + parsing
# --------------------------------------------------------------------------
TOTAL_HEADER = "=== TOTAL FAILED ATTEMPTS ==="
ALERT_HEADER = "=== TIME-BASED ALERTS ==="

TOTAL_RE = re.compile(r"IP:\s*(\S{2,45})\s*\|\s*Failed attempts:\s*(\d{1,9})")
ALERT_RE = re.compile(
    r"\[(MEDIUM|HIGH)\]\s*IP:\s*(\S{2,45})\s*\|\s*"
    r"(\d{1,9})\s+failed attempts in\s+(\d{1,9})\s+seconds"
    r"(?:\s*\|\s*Last attempt:\s*(.{0,100}))?"
)


def safe_report_path() -> Path:
    candidate = REPORTS_DIR / REPORT_NAME
    if candidate.is_symlink():
        raise PermissionError("Les liens symboliques sont refusés.")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(REPORTS_DIR):
        raise PermissionError("Chemin hors du dossier reports/.")
    return resolved


def valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def ip_scope(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if ip.is_loopback:
        return "Loopback"
    if ip.is_private:
        return "Private"
    if ip.is_multicast or ip.is_reserved or ip.is_link_local:
        return "Special"
    return "Public"


def risk_level(score: int) -> str:
    if score >= 100:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


@st.cache_data(show_spinner=False)
def load_report(path_str: str, mtime: float, size: int):
    """Mis en cache selon (chemin, mtime, taille) : se recharge si le fichier change."""
    raw = Path(path_str).read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()[:MAX_LINES]

    ip_rows, alert_rows = [], []
    skipped = 0
    section = None

    for line in lines:
        line = line[:MAX_LINE_LEN]
        if TOTAL_HEADER in line:
            section = "totals"
            continue
        if ALERT_HEADER in line:
            section = "alerts"
            continue

        if section == "totals":
            m = TOTAL_RE.search(line)
            if m:
                ip = valid_ip(m.group(1))
                if ip:
                    ip_rows.append({"IP Address": ip, "Failed Attempts": int(m.group(2))})
                else:
                    skipped += 1

        elif section == "alerts" and line.startswith("["):
            m = ALERT_RE.search(line)
            if m:
                ip = valid_ip(m.group(2))
                if ip:
                    alert_rows.append({
                        "Severity": m.group(1),
                        "IP Address": ip,
                        "Attempts in Window": int(m.group(3)),
                        "Window (seconds)": int(m.group(4)),
                        "Last Attempt": (m.group(5) or "N/A").strip(),
                    })
                else:
                    skipped += 1

    ip_df = pd.DataFrame(ip_rows, columns=["IP Address", "Failed Attempts"])
    alerts_df = pd.DataFrame(
        alert_rows,
        columns=["Severity", "IP Address", "Attempts in Window", "Window (seconds)", "Last Attempt"],
    )

    if not ip_df.empty:  # agrège les doublons éventuels
        ip_df = ip_df.groupby("IP Address", as_index=False)["Failed Attempts"].sum()

    if not alerts_df.empty:
        alerts_df["Last Attempt (parsed)"] = pd.to_datetime(
            alerts_df["Last Attempt"], errors="coerce"
        )

    return "\n".join(lines[:RAW_VIEW_LINES]), ip_df, alerts_df, skipped, sha256, len(lines)


def build_ip_table(ip_df: pd.DataFrame, alerts_df: pd.DataFrame) -> pd.DataFrame:
    if ip_df.empty:
        return pd.DataFrame(columns=[
            "IP Address", "Failed Attempts", "HIGH", "MEDIUM", "Scope", "Risk Score", "Risk Level"
        ])
    df = ip_df.copy()
    if alerts_df.empty:
        df["HIGH"], df["MEDIUM"] = 0, 0
    else:
        counts = (
            alerts_df.groupby(["IP Address", "Severity"]).size().unstack(fill_value=0)
            .reindex(columns=["HIGH", "MEDIUM"], fill_value=0).reset_index()
        )
        df = df.merge(counts, on="IP Address", how="left").fillna({"HIGH": 0, "MEDIUM": 0})
        df[["HIGH", "MEDIUM"]] = df[["HIGH", "MEDIUM"]].astype(int)
    df["Scope"] = df["IP Address"].map(ip_scope)
    df["Risk Score"] = df["Failed Attempts"] + 25 * df["HIGH"] + 10 * df["MEDIUM"]
    df["Risk Level"] = df["Risk Score"].map(risk_level)
    return df.sort_values("Risk Score", ascending=False).reset_index(drop=True)


def csv_safe(df: pd.DataFrame) -> pd.DataFrame:
    """Neutralise l'injection de formules Excel/CSV."""
    def clean(v):
        if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
            return "'" + v
        return v
    return df.apply(lambda col: col.map(clean) if col.dtype == object else col)


# --------------------------------------------------------------------------
# Application
# --------------------------------------------------------------------------
require_auth()

st.title("🛡️ Mini SOC — Security Monitoring Dashboard")
st.caption("Security monitoring | Failed login attempts | Blue Team")

try:
    report_path = safe_report_path()
except PermissionError as exc:
    audit.error("Chemin refusé : %s", exc)
    st.error(f"Accès refusé : {exc}")
    st.stop()

if not report_path.is_file():
    st.warning("Aucun rapport trouvé. Lance d'abord le programme principal.")
    st.code("python main.py", language="bash")
    st.stop()

stat = report_path.stat()
if stat.st_size > MAX_REPORT_BYTES:
    st.error(f"Rapport trop volumineux ({stat.st_size / 1_048_576:.1f} Mo, max 5 Mo).")
    st.stop()

raw_text, ip_df, alerts_df, skipped, sha256, n_lines = load_report(
    str(report_path), stat.st_mtime, stat.st_size
)
ip_table = build_ip_table(ip_df, alerts_df)

# ---- Sidebar : filtres & actions -----------------------------------------
with st.sidebar:
    st.header("⚙️ Filters")
    severities = st.multiselect("Alert severity", ["HIGH", "MEDIUM"], default=["HIGH", "MEDIUM"])
    min_attempts = st.number_input("Min. failed attempts", min_value=0, value=0, step=1)
    scopes = st.multiselect(
        "IP scope", ["Public", "Private", "Loopback", "Special"],
        default=["Public", "Private", "Loopback", "Special"],
    )
    ip_search = st.text_input("Search IP (prefix)", max_chars=45).strip()
    top_n = st.slider("Top N IPs in chart", 5, 50, 15)

    st.divider()
    if st.button("🔄 Reload report"):
        load_report.clear()
        st.rerun()
    if st.button("🚪 Logout"):
        audit.info("Déconnexion")
        st.session_state.clear()
        st.rerun()

# ---- Application des filtres ---------------------------------------------
view = ip_table[
    (ip_table["Failed Attempts"] >= min_attempts) & (ip_table["Scope"].isin(scopes))
]
if ip_search:
    view = view[view["IP Address"].str.startswith(ip_search)]

alerts_view = alerts_df[alerts_df["Severity"].isin(severities)] if not alerts_df.empty else alerts_df
if not alerts_view.empty:
    alerts_view = alerts_view[alerts_view["IP Address"].isin(view["IP Address"])]

# ---- Métriques ------------------------------------------------------------
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Failed Login Attempts", int(view["Failed Attempts"].sum()) if not view.empty else 0)
c2.metric("Unique IPs", len(view))
c3.metric("Total Alerts", len(alerts_view))
c4.metric("High Severity", int((alerts_view["Severity"] == "HIGH").sum()) if not alerts_view.empty else 0)
c5.metric("Critical IPs", int((view["Risk Level"] == "Critical").sum()) if not view.empty else 0)

st.divider()

# ---- Graphiques -----------------------------------------------------------
left, right = st.columns([3, 2])

with left:
    st.subheader("📊 Top IPs by failed attempts")
    if view.empty:
        st.info("Aucune donnée pour ces filtres.")
    else:
        chart = (
            alt.Chart(view.head(top_n))
            .mark_bar()
            .encode(
                x=alt.X("Failed Attempts:Q", title="Failed attempts"),
                y=alt.Y("IP Address:N", sort="-x", title=None),
                color=alt.Color(
                    "Risk Level:N",
                    scale=alt.Scale(domain=RISK_ORDER, range=RISK_COLORS),
                    legend=alt.Legend(title="Risk"),
                ),
                tooltip=["IP Address", "Failed Attempts", "HIGH", "MEDIUM", "Risk Score", "Risk Level", "Scope"],
            )
            .properties(height=max(200, 26 * min(top_n, len(view))))
        )
        st.altair_chart(chart, use_container_width=True)

with right:
    st.subheader("🧭 Risk distribution")
    if view.empty:
        st.info("—")
    else:
        dist = view["Risk Level"].value_counts().reindex(RISK_ORDER, fill_value=0).reset_index()
        dist.columns = ["Risk Level", "IPs"]
        dist_chart = (
            alt.Chart(dist)
            .mark_bar()
            .encode(
                x=alt.X("Risk Level:N", sort=RISK_ORDER, title=None),
                y=alt.Y("IPs:Q"),
                color=alt.Color(
                    "Risk Level:N",
                    scale=alt.Scale(domain=RISK_ORDER, range=RISK_COLORS),
                    legend=None,
                ),
                tooltip=["Risk Level", "IPs"],
            )
            .properties(height=250)
        )
        st.altair_chart(dist_chart, use_container_width=True)

# ---- Tableau des IP -------------------------------------------------------
st.subheader("📋 IP Statistics")
if view.empty:
    st.info("Aucune IP à afficher.")
else:
    st.dataframe(
        view,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Risk Score": st.column_config.ProgressColumn(
                "Risk Score", min_value=0, max_value=int(max(view["Risk Score"].max(), 1)), format="%d"
            ),
        },
    )
    if st.download_button(
        "⬇️ Export IP table (CSV)",
        data=csv_safe(view).to_csv(index=False).encode("utf-8"),
        file_name=f"ip_stats_{datetime.now():%Y%m%d_%H%M%S}.csv",
        mime="text/csv",
    ):
        audit.info("Export CSV des statistiques IP")

# ---- Alertes --------------------------------------------------------------
st.subheader("🚨 Security Alerts")
if alerts_view.empty:
    st.success("No time-based security alerts detected for the current filters.")
else:
    display_cols = ["Severity", "IP Address", "Attempts in Window", "Window (seconds)", "Last Attempt"]

    high_df = alerts_view[alerts_view["Severity"] == "HIGH"]
    medium_df = alerts_view[alerts_view["Severity"] == "MEDIUM"]

    if not high_df.empty:
        st.error(f"🔴 HIGH: {len(high_df)} high-severity alert(s)")
        st.dataframe(high_df[display_cols], use_container_width=True, hide_index=True)
    if not medium_df.empty:
        st.warning(f"🟠 MEDIUM: {len(medium_df)} medium-severity alert(s)")
        st.dataframe(medium_df[display_cols], use_container_width=True, hide_index=True)

    timeline = alerts_view.dropna(subset=["Last Attempt (parsed)"])
    if not timeline.empty:
        st.subheader("🕒 Alert timeline")
        tl_chart = (
            alt.Chart(timeline)
            .mark_circle(size=120)
            .encode(
                x=alt.X("Last Attempt (parsed):T", title="Last attempt"),
                y=alt.Y("IP Address:N", title=None),
                color=alt.Color(
                    "Severity:N",
                    scale=alt.Scale(domain=["MEDIUM", "HIGH"], range=["#ef6c00", "#c62828"]),
                ),
                tooltip=["IP Address", "Severity", "Attempts in Window", "Last Attempt"],
            )
        )
        st.altair_chart(tl_chart, use_container_width=True)

# ---- Intégrité & rapport brut --------------------------------------------
with st.expander("🔐 Report integrity & parsing info"):
    st.write(f"**File:** `{report_path.name}` — {stat.st_size:,} bytes — {n_lines:,} lines")
    st.write(f"**Last modified:** {datetime.fromtimestamp(stat.st_mtime):%Y-%m-%d %H:%M:%S}")
    st.write("**SHA-256:**")
    st.code(sha256, language="text")
    if skipped:
        st.warning(f"{skipped} ligne(s) ignorée(s) (adresse IP invalide).")

with st.expander("📄 View raw security report"):
    st.caption(f"Affichage limité aux {RAW_VIEW_LINES} premières lignes.")
    st.text(raw_text)  # st.text n'interprète ni HTML ni Markdown

st.caption("Mini SOC Lab | Educational use | Local log analysis")