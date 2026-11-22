"""
build_database.py — Base SQLite : schéma, migration, insertion des scans
"""

import os
import re
import sqlite3
from datetime import datetime

from parser import parse_config
from rule_engine import load_rules, analyze_config

CONFIGS_DIR = "../configs"
RULES_PATH = "../rules/rules.yaml"
DB_PATH = "../pfe_database.db"


# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------

def guess_device_type(parsed):
    text = "\n".join(parsed["global_lines"]).lower()
    has_switchport = any(
        "switchport" in "\n".join(sublines).lower()
        for sublines in parsed["interfaces"].values()
    )
    has_dot1q_subinterface = any(
        "encapsulation dot1q" in "\n".join(sublines).lower()
        for sublines in parsed["interfaces"].values()
    )
    if has_switchport:
        return "switch"
    if has_dot1q_subinterface or "router ospf" in text or "router eigrp" in text or "router bgp" in text:
        return "router"
    return "unknown"


def extract_hostname(parsed):
    for line in parsed["global_lines"]:
        m = re.match(r"^hostname\s+(\S+)", line)
        if m:
            return m.group(1)
    return None


def compute_label(anomalies):
    """
    'weak' si au moins une anomalie confirmée : risque High, ou risque Medium
    issu d'une règle à confiance 'high'. Les constats d'hygiène (règles à
    confiance medium/low, risque Low) sont enregistrés mais ne changent pas le label.
    """
    for a in anomalies:
        if a["risk_level"] == "High":
            return "weak"
        if a["risk_level"] == "Medium" and a.get("confidence", "medium") == "high":
            return "weak"
    return "secure"


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Schéma + migration
# ---------------------------------------------------------------------------

def _columns(conn, table):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _backup_database(conn):
    """Copie de sécurité de la base ouverte (API de backup SQLite)."""
    db_file = conn.execute("PRAGMA database_list").fetchone()[2]
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base, ext = os.path.splitext(db_file)
    backup_path = f"{base}_backup_{stamp}{ext}"
    dest = sqlite3.connect(backup_path)
    conn.backup(dest)
    dest.close()
    return backup_path


def create_schema(conn):
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    needs_migration = "configs" in tables and (
        not {"scanned_at", "host", "source"} <= _columns(conn, "configs")
        or ("anomalies" in tables and "code_fix" not in _columns(conn, "anomalies"))
    )
    if needs_migration:
        backup_path = _backup_database(conn)
        print(f"[DB] Migration du schéma — sauvegarde créée : {backup_path}")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            device_type TEXT,
            hostname TEXT,
            raw_config TEXT,
            anomaly_count INTEGER,
            label TEXT,
            scanned_at TEXT,
            host TEXT,
            source TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            config_id INTEGER,
            rule_id TEXT,
            description TEXT,
            risk_level TEXT,
            detail TEXT,
            recommendation TEXT,
            code_fix TEXT,
            FOREIGN KEY (config_id) REFERENCES configs(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fixes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            anomaly_id INTEGER NOT NULL,
            config_id INTEGER NOT NULL,
            rule_id TEXT,
            code_fix TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT,
            updated_at TEXT,
            device_output TEXT,
            FOREIGN KEY (anomaly_id) REFERENCES anomalies(id),
            FOREIGN KEY (config_id) REFERENCES configs(id)
        )
    """)

    # Ajout des colonnes manquantes sur une ancienne base
    for col in ("scanned_at", "host", "source"):
        if col not in _columns(conn, "configs"):
            conn.execute(f"ALTER TABLE configs ADD COLUMN {col} TEXT")
    if "code_fix" not in _columns(conn, "anomalies"):
        conn.execute("ALTER TABLE anomalies ADD COLUMN code_fix TEXT")

    # Rattrapage de la colonne 'source' pour les anciennes lignes (ordre important)
    conn.execute("UPDATE configs SET source='ssh_post_fix' "
                 "WHERE source IS NULL AND instr(filename, '_ssh_scan_post_fix') > 0")
    conn.execute("UPDATE configs SET source='ssh' "
                 "WHERE source IS NULL AND instr(filename, '_ssh_scan') > 0")
    conn.execute("UPDATE configs SET source='file' WHERE source IS NULL")
    conn.commit()


# ---------------------------------------------------------------------------
# Insertion d'un scan (utilisée aussi par device_connector.py)
# ---------------------------------------------------------------------------

def insert_scan(conn, filename, device_type, hostname, raw_config, anomalies,
                source, host=None, create_fixes=False):
    """
    Insère une config + ses anomalies. Si create_fixes=True, crée aussi une ligne
    'pending' dans la table fixes pour chaque anomalie qui a un code_fix, et
    ajoute la clé 'fix_id' au dict de l'anomalie.
    Retourne (config_id, label).
    """
    label = compute_label(anomalies)
    cur = conn.execute(
        """INSERT INTO configs (filename, device_type, hostname, raw_config,
                                anomaly_count, label, scanned_at, host, source)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (filename, device_type, hostname, raw_config, len(anomalies), label,
         now_iso(), host, source),
    )
    config_id = cur.lastrowid

    for a in anomalies:
        acur = conn.execute(
            """INSERT INTO anomalies (config_id, rule_id, description, risk_level,
                                      detail, recommendation, code_fix)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (config_id, a["rule_id"], a["description"], a["risk_level"],
             a["detail"], a["recommendation"], a.get("code_fix", "")),
        )
        a["anomaly_id"] = acur.lastrowid
        if create_fixes and a.get("code_fix"):
            ts = now_iso()
            fcur = conn.execute(
                """INSERT INTO fixes (anomaly_id, config_id, rule_id, code_fix,
                                      status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 'pending', ?, ?)""",
                (a["anomaly_id"], config_id, a["rule_id"], a["code_fix"], ts, ts),
            )
            a["fix_id"] = fcur.lastrowid
    conn.commit()
    return config_id, label


# ---------------------------------------------------------------------------
# Import des fichiers de config statiques
# ---------------------------------------------------------------------------

def build_database():
    rules = load_rules(RULES_PATH)
    conn = sqlite3.connect(DB_PATH)
    create_schema(conn)

    # On ne supprime QUE les configs importées depuis des fichiers (régénérables).
    # Les scans SSH (preuves de démonstration) sont conservés.
    conn.execute("DELETE FROM anomalies WHERE config_id IN "
                 "(SELECT id FROM configs WHERE source='file')")
    conn.execute("DELETE FROM configs WHERE source='file'")
    conn.commit()

    config_files = [
        f for f in os.listdir(CONFIGS_DIR)
        if os.path.isfile(os.path.join(CONFIGS_DIR, f))
    ]
    print(f"{len(config_files)} fichier(s) de config trouvé(s) dans {CONFIGS_DIR}\n")

    for filename in sorted(config_files):
        filepath = os.path.join(CONFIGS_DIR, filename)
        try:
            parsed = parse_config(filepath)
        except Exception as e:
            print(f"  [ERREUR] Impossible de parser {filename}: {e}")
            continue

        anomalies = analyze_config(parsed, rules)
        device_type = guess_device_type(parsed)
        hostname = extract_hostname(parsed)

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            raw_config = f.read()

        _, label = insert_scan(conn, filename, device_type, hostname, raw_config,
                               anomalies, source="file")

        print(f"  {filename:30s} | type={device_type:8s} | hostname={str(hostname):10s} | "
              f"{len(anomalies)} anomalie(s) | label={label}")

    n_ssh = conn.execute("SELECT COUNT(*) FROM configs WHERE source LIKE 'ssh%'").fetchone()[0]
    conn.close()
    print(f"\nBase de données mise à jour : {DB_PATH}")
    print(f"Scans SSH conservés : {n_ssh}")


if __name__ == "__main__":
    build_database()