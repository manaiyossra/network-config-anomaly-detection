"""
scan_folder.py — Analyse d'un dossier de configurations et revue de la précision

1) Analyse tous les fichiers d'un dossier (par défaut ../configs) :
   - un tableau par fichier (taille, durée d'analyse, anomalies par risque)
   - un bilan par règle (dans combien de fichiers elle se déclenche)
   - un fichier ../revue_detections.csv : un échantillon de détections à relire à la main

2) Après relecture, calcule la précision par règle :
   - ouvrir ../revue_detections.csv, remplir la colonne « verdict » avec VP (vraie anomalie)
     ou FP (fausse alerte), enregistrer en CSV
   - puis :  python scan_folder.py --score ../revue_detections.csv

Usage (depuis src/) :
    python scan_folder.py                    # dossier ../configs, 4 détections relues par règle
    python scan_folder.py ../autres_configs  # un autre dossier
    python scan_folder.py --sample 6         # 6 détections relues par règle
    python scan_folder.py --score ../revue_detections.csv
"""

import argparse
import csv
import os
import random
import re
import time
from collections import Counter, defaultdict

from parser import parse_config
from rule_engine import load_rules, analyze_config

RULES_PATH = "../rules/rules.yaml"
REVIEW_PATH = "../revue_detections.csv"
EXTENSIONS = (".conf", ".cfg", ".ios", ".txt")
RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def independent_hint(raw_text, rule, anomaly):
    """Indice de relecture obtenu par une recherche de texte indépendante du moteur."""
    pattern = rule.get("pattern")
    if rule["check_type"] in ("absence", "presence_substring") and pattern:
        key = pattern[3:] if pattern.startswith("no ") else pattern
        hits = [l.strip() for l in raw_text.splitlines() if key in l]
        if hits:
            return "le texte « %s » apparaît dans le fichier : %s" % (key, hits[0][:60])
        return "le texte « %s » n'apparaît nulle part dans le fichier" % key
    return ""


def scan(folder, sample, big_kb):
    rules = load_rules(RULES_PATH)
    by_id = {r["rule_id"]: r for r in rules}
    files = sorted(f for f in os.listdir(folder)
                   if f.lower().endswith(EXTENSIONS) and os.path.isfile(os.path.join(folder, f)))
    if not files:
        print("Aucun fichier de configuration dans", os.path.abspath(folder))
        return

    big = {x for x in files if os.path.getsize(os.path.join(folder, x)) / 1024 > big_kb}
    n_stats = len(files) - len(big)
    print(f"\n{len(files)} fichier(s) dans {os.path.abspath(folder)}\n")
    print(f"{'Fichier':32} {'Ko':>6} {'ms':>6} {'Total':>6} {'High':>5} {'Med.':>5} {'Low':>5}")
    print("-" * 72)

    per_rule_files = defaultdict(set)
    per_rule_hits = Counter()
    all_hits = []  # (fichier, règle, anomalie, texte brut)
    times = []
    for f in files:
        path = os.path.join(folder, f)
        raw = open(path, encoding="utf-8", errors="ignore").read()
        t0 = time.perf_counter()
        anomalies = analyze_config(parse_config(path), rules)
        dt = (time.perf_counter() - t0) * 1000
        times.append(dt)
        risk = Counter(a["risk_level"] for a in anomalies)
        print(f"{f[:32]:32} {os.path.getsize(path) / 1024:6.1f} {dt:6.0f} {len(anomalies):6d} "
              f"{risk['High']:5d} {risk['Medium']:5d} {risk['Low']:5d}")
        if f in big:
            continue  # fichier volumineux : chronométré mais exclu des statistiques
        for a in anomalies:
            per_rule_files[a["rule_id"]].add(f)
            per_rule_hits[a["rule_id"]] += 1
            all_hits.append((f, a, raw))
    print("-" * 72)
    if big:
        print(f"Fichiers de plus de {big_kb} Ko (chronométrés, exclus du bilan par règle et de la revue) : "
              + ", ".join(sorted(big)))
    print(f"Temps d'analyse : moyenne {sum(times) / len(times):.0f} ms, maximum {max(times):.0f} ms par fichier")

    print(f"\n{'Règle':8} {'Fichiers touchés':>18} {'Détections':>11}  Description")
    print("-" * 72)
    for r in rules:
        rid = r["rule_id"]
        print(f"{rid:8} {len(per_rule_files[rid]):>10}/{n_stats:<7} {per_rule_hits[rid]:>11}  {r['description'][:42]}")

    # --- Échantillon à relire --------------------------------------------
    rng = random.Random(42)
    rows = []
    for r in rules:
        rid = r["rule_id"]
        hits = [h for h in all_hits if h[1]["rule_id"] == rid]
        rng.shuffle(hits)
        for f, a, raw in hits[:sample]:
            rows.append([f, rid, a["risk_level"], a.get("confidence", ""), a["detail"],
                         independent_hint(raw, r, a), ""])
    with open(REVIEW_PATH, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["fichier", "règle", "risque", "confiance", "détail", "indice", "verdict"])
        w.writerows(rows)
    print(f"\n{len(rows)} détections à relire écrites dans {os.path.abspath(REVIEW_PATH)}")
    print("Ouvre ce fichier, ouvre chaque configuration au besoin, et remplis la colonne « verdict » :")
    print("  VP = vraie anomalie   FP = fausse alerte")
    print("Puis lance :  python scan_folder.py --score ../revue_detections.csv")


def score(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh, delimiter=";"))
    per = defaultdict(lambda: [0, 0])
    unk = 0
    for r in rows:
        v = (r.get("verdict") or "").strip().upper()
        if v == "VP":
            per[r["règle"]][0] += 1
        elif v == "FP":
            per[r["règle"]][1] += 1
        else:
            unk += 1
    print(f"\n{'Règle':8} {'VP':>4} {'FP':>4} {'Précision':>10}")
    print("-" * 30)
    tvp = tfp = 0
    for rid in sorted(per):
        vp, fp = per[rid]
        tvp += vp; tfp += fp
        print(f"{rid:8} {vp:4d} {fp:4d} {vp / (vp + fp):10.0%}")
    print("-" * 30)
    if tvp + tfp:
        print(f"{'Global':8} {tvp:4d} {tfp:4d} {tvp / (tvp + tfp):10.0%}")
    if unk:
        print(f"\n{unk} ligne(s) sans verdict (ignorées).")
    print("\nAttention : seule la précision est mesurée ici (parmi les alertes, combien sont justes).")
    print("Le rappel (anomalies manquées) n'est pas mesurable sans une liste établie indépendamment.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Analyse un dossier de configurations et aide à la revue")
    ap.add_argument("folder", nargs="?", default="../configs")
    ap.add_argument("--sample", type=int, default=4, help="détections relues par règle (défaut 4)")
    ap.add_argument("--big-kb", type=int, default=200, help="au-delà, un fichier est exclu des statistiques (défaut 200 Ko)")
    ap.add_argument("--score", metavar="CSV", help="calcule la précision à partir d'un CSV relu")
    args = ap.parse_args()
    if args.score:
        score(args.score)
    else:
        scan(args.folder, args.sample, args.big_kb)