"""
device_connector.py — Pipeline Zero-Touch avec garde-fous

Scan SSH -> analyse -> stockage -> (optionnel) correction automatique.

Règles de sécurité appliquées avant toute modification :
  - le correctif doit venir d'une règle marquée auto_apply: true
  - aucun correctif contenant un <placeholder> n'est jamais poussé
  - le mode --apply-fixes exclut en plus les anomalies High (validation humaine)
  - l'équipement doit avoir auto_fix: true dans devices.yaml
  - la config est sauvegardée dans ../backups/ avant toute modification
  - la réponse de l'équipement est vérifiée ; au premier rejet on s'arrête
    et on NE sauvegarde PAS (pas de write memory)
Chaque correctif est enregistré dans la table fixes avec son statut :
  pending     : jamais appliqué
  applied     : accepté par l'équipement (anciens enregistrements)
  verified    : accepté ET l'anomalie a disparu au re-scan
  unverified  : accepté MAIS l'anomalie est toujours détectée au re-scan
  failed      : rejeté par l'équipement
"""

import argparse
import os
import re
import sqlite3
import tempfile
from datetime import datetime

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

from parser import parse_config
from rule_engine import load_rules, analyze_config
from build_database import (create_schema, guess_device_type, extract_hostname,
                            insert_scan, now_iso)

DEVICES_PATH = "../devices.yaml"
RULES_PATH = "../rules/rules.yaml"
DB_PATH = "../pfe_database.db"
BACKUP_DIR = "../backups"

# Garde-fou supplémentaire, indépendant de devices.yaml : jamais de correction
# automatique sur ces hôtes (ressource partagée DevNet Always-On).
FORBIDDEN_AUTO_APPLY_HOSTS = ["devnetsandboxiosxec8k.cisco.com"]

PLACEHOLDER_RE = re.compile(r"<[^>\n]+>")
DEVICE_ERROR_MARKERS = ("% invalid input", "% incomplete command",
                        "% ambiguous command", "% unknown command")


# ---------------------------------------------------------------------------
# Chargement des équipements
# ---------------------------------------------------------------------------

def _resolve(value):
    """'env:NOM_VARIABLE' -> valeur de la variable d'environnement, sinon valeur telle quelle."""
    if isinstance(value, str) and value.startswith("env:"):
        var = value[4:]
        if var not in os.environ:
            raise RuntimeError(f"variable d'environnement manquante : {var}")
        return os.environ[var]
    return value


def load_devices():
    with open(DEVICES_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)["devices"]


def _conn_params(device):
    password = _resolve(device["password"])
    return {
        "device_type": device.get("device_type", "cisco_ios"),
        "host": device["host"],
        "username": _resolve(device["username"]),
        "password": password,
        "secret": _resolve(device.get("secret", device["password"])),
        "conn_timeout": 20,
    }


# ---------------------------------------------------------------------------
# Accès SSH
# ---------------------------------------------------------------------------

def fetch_config_via_ssh(device):
    connection = ConnectHandler(**_conn_params(device))
    try:
        connection.enable()
        return connection.send_command("show running-config")
    finally:
        connection.disconnect()


def push_fixes_via_ssh(device, fixes):
    """
    fixes : liste de dicts {"fix_id", "commands": [...]}.
    Applique un correctif à la fois et vérifie la réponse de l'équipement.
    S'arrête au premier rejet et ne sauvegarde pas dans ce cas.
    Retourne (results, saved) ; results = [{"fix_id", "ok", "output"}].
    """
    connection = ConnectHandler(**_conn_params(device))
    results = []
    saved = False
    try:
        connection.enable()
        for fix in fixes:
            output = connection.send_config_set(fix["commands"])
            ok = not any(m in output.lower() for m in DEVICE_ERROR_MARKERS)
            results.append({"fix_id": fix["fix_id"], "ok": ok, "output": output})
            if not ok:
                break
        if results and all(r["ok"] for r in results):
            connection.save_config()
            saved = True
    finally:
        connection.disconnect()
    return results, saved


# ---------------------------------------------------------------------------
# Décision : quels correctifs peut-on appliquer ?
# ---------------------------------------------------------------------------

def fix_commands(code_fix):
    """Lignes de commande d'un correctif (sans lignes vides ni commentaires '!')."""
    lines = code_fix.replace("\\n", "\n").split("\n")
    return [l for l in lines if l.strip() and not l.strip().startswith("!")]


def classify_fix(anomaly, full_auto):
    """Retourne 'apply' ou la raison pour laquelle le correctif reste en attente."""
    code_fix = anomaly.get("code_fix") or ""
    if not fix_commands(code_fix):
        return "no_fix"
    if PLACEHOLDER_RE.search(code_fix):
        return "placeholder"
    if not anomaly.get("auto_apply", False):
        return "manual"
    if not full_auto and anomaly["risk_level"] == "High":
        return "high_risk"
    return "apply"


REASON_LABELS = {
    "no_fix": "aucun correctif exécutable",
    "placeholder": "contient un <placeholder> à renseigner",
    "manual": "règle non autorisée en application automatique",
    "high_risk": "risque High (mode semi-auto)",
}


# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------

def _parse_text(raw_config):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False,
                                     encoding="utf-8") as tmp:
        tmp.write(raw_config)
        path = tmp.name
    try:
        return parse_config(path)
    finally:
        os.remove(path)


def _analyze_text(raw_config, rules):
    return analyze_config(_parse_text(raw_config), rules)


def _backup_config(name, raw_config):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    path = os.path.join(BACKUP_DIR, f"{safe}_{stamp}.cfg")
    with open(path, "w", encoding="utf-8") as f:
        f.write(raw_config)
    return path


def _set_fix_status(conn, fix_id, status, output=None):
    conn.execute(
        "UPDATE fixes SET status = ?, updated_at = ?, device_output = ? WHERE id = ?",
        (status, now_iso(), (output or "")[:2000], fix_id),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_pipeline(apply_fixes=False, full_auto=False):
    devices = load_devices()
    rules = load_rules(RULES_PATH)

    conn = sqlite3.connect(DB_PATH)
    create_schema(conn)

    mode = ("Zero-Touch (High risk inclus si la règle l'autorise)" if full_auto else
            "Semi-automatique (High risk exclu)" if apply_fixes else "Scan seul")
    print(f"Pipeline démarré — mode : {mode} — {len(devices)} équipement(s)\n")

    for device in devices:
        name = device.get("name", device["host"])
        host = device["host"]
        print(f"[{name}] Connexion SSH à {host}...")

        try:
            raw_config = fetch_config_via_ssh(device)
        except NetmikoAuthenticationException:
            print(f"[{name}] ÉCHEC — authentification refusée")
            continue
        except NetmikoTimeoutException:
            print(f"[{name}] ÉCHEC — timeout (équipement injoignable, VPN actif ?)")
            continue
        except Exception as e:
            print(f"[{name}] ÉCHEC — {e}")
            continue

        parsed = _parse_text(raw_config)
        anomalies = analyze_config(parsed, rules)
        device_type = guess_device_type(parsed)
        hostname = extract_hostname(parsed) or name
        config_id, label = insert_scan(conn, f"{name}_ssh_scan", device_type, hostname,
                                       raw_config, anomalies, source="ssh", host=host,
                                       create_fixes=True)
        print(f"[{name}] Config récupérée ({len(raw_config)} caractères) — "
              f"{len(anomalies)} anomalie(s), label={label}")

        if not (apply_fixes and anomalies):
            print()
            continue

        # --- Garde-fous au niveau de l'équipement ---
        if host in FORBIDDEN_AUTO_APPLY_HOSTS:
            print(f"[{name}] BLOQUÉ — {host} est une ressource partagée protégée.\n")
            continue
        if not device.get("auto_fix", False):
            print(f"[{name}] Correction ignorée — auto_fix n'est pas activé pour cet "
                  f"équipement dans devices.yaml. Correctifs laissés en attente.\n")
            continue

        # --- Tri des correctifs ---
        to_apply, skipped = [], {}
        for a in anomalies:
            if not a.get("fix_id"):
                continue
            verdict = classify_fix(a, full_auto)
            if verdict == "apply":
                to_apply.append(a)
            else:
                skipped.setdefault(verdict, []).append(a["rule_id"])
        for reason, ids in skipped.items():
            print(f"[{name}] En attente ({REASON_LABELS[reason]}) : {sorted(set(ids))}")

        if not to_apply:
            print(f"[{name}] Aucun correctif applicable automatiquement.\n")
            continue

        backup_path = _backup_config(name, raw_config)
        print(f"[{name}] Sauvegarde de la config : {backup_path}")
        print(f"[{name}] Application de {len(to_apply)} correctif(s)...")

        payload = [{"fix_id": a["fix_id"], "commands": fix_commands(a["code_fix"])}
                   for a in to_apply]
        try:
            results, saved = push_fixes_via_ssh(device, payload)
        except Exception as e:
            print(f"[{name}] ÉCHEC pendant l'application — {e}\n")
            continue

        for r in results:
            _set_fix_status(conn, r["fix_id"], "applied" if r["ok"] else "failed", r["output"])
        n_ok = sum(1 for r in results if r["ok"])
        n_failed = sum(1 for r in results if not r["ok"])
        print(f"[{name}] {n_ok} appliqué(s), {n_failed} rejeté(s) par l'équipement.")

        if not saved:
            print(f"[{name}] ATTENTION — rien n'a été sauvegardé (pas de write memory). "
                  f"La config en cours peut contenir des changements partiels ; "
                  f"un rechargement de l'équipement les annulerait. "
                  f"Sauvegarde d'origine : {backup_path}\n")
            continue
        print(f"[{name}] Configuration sauvegardée (write memory).")

        # --- Re-scan de vérification ---
        new_raw = fetch_config_via_ssh(device)
        new_anomalies = _analyze_text(new_raw, rules)
        insert_scan(conn, f"{name}_ssh_scan_post_fix", device_type, hostname, new_raw,
                    new_anomalies, source="ssh_post_fix", host=host)

        # --- Vérification de chaque correctif : l'anomalie a-t-elle disparu ? ---
        remaining = {(a["rule_id"], a["detail"]) for a in new_anomalies}
        n_verified = n_unverified = 0
        for a in to_apply:
            r = next((x for x in results if x["fix_id"] == a["fix_id"]), None)
            if r and r["ok"]:
                still_there = (a["rule_id"], a["detail"]) in remaining
                _set_fix_status(conn, a["fix_id"],
                                "unverified" if still_there else "verified", r["output"])
                if still_there:
                    n_unverified += 1
                else:
                    n_verified += 1

        print(f"[{name}] Correctifs vérifiés par le re-scan : {n_verified} ; "
              f"acceptés mais anomalie toujours détectée : {n_unverified}")
        print(f"[{name}] Anomalies avant : {len(anomalies)} -> après : {len(new_anomalies)}\n")

    conn.close()
    print("Pipeline terminé.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Pipeline Zero-Touch : scan SSH et correction automatique")
    ap.add_argument("--apply-fixes", action="store_true",
                    help="Applique les correctifs autorisés (anomalies High exclues)")
    ap.add_argument("--full-auto", action="store_true",
                    help="Applique aussi les correctifs High autorisés par leur règle (implique --apply-fixes)")
    args = ap.parse_args()
    run_pipeline(apply_fixes=args.apply_fixes or args.full_auto, full_auto=args.full_auto)