"""
ml_model.py — Détection statistique par Isolation Forest

Jeu de référence : configurations réelles ou de laboratoire (jamais les variantes générées).
Trois représentations d'une configuration sont comparées :
  - hand  : 13 caractéristiques construites à la main (nombre d'ACL, présence de Telnet, etc.)
  - tfidf : « forme » des commandes (deux premiers mots de chaque ligne) pondérée par TF-IDF, réduite par SVD
  - both  : les deux ensemble

Usage (depuis src/) :
    python ml_model.py evaluate          # compare les représentations par injection de fautes
    python ml_model.py train             # entraîne et sauvegarde ../models/isolation_forest.joblib
    python ml_model.py score <fichier>   # score d'une configuration avec le modèle sauvegardé
"""

import hashlib
import os
import re
import sys
import tempfile

import joblib
import numpy as np
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

from parser import parse_config

REFERENCE_FOLDERS = ["../configs_externes", "../configs_reference"]
EXTRA_FILES = ["../configs/R1.cfg", "../configs/SW1.cfg"]
EXTENSIONS = (".conf", ".cfg", ".ios", ".txt")
MAX_KB = 200
MODEL_PATH = "../models/isolation_forest.joblib"
MODES = ("hand", "tfidf", "both")


# ---------------------------------------------------------------------------
# Jeu de référence
# ---------------------------------------------------------------------------
def load_reference():
    paths = []
    for folder in REFERENCE_FOLDERS:
        if os.path.isdir(folder):
            for f in sorted(os.listdir(folder)):
                if f.lower().endswith(EXTENSIONS):
                    paths.append(os.path.join(folder, f))
    paths += [p for p in EXTRA_FILES if os.path.exists(p)]
    seen, out = set(), []
    for p in paths:
        name = os.path.basename(p)
        if "_variant_" in name or os.path.getsize(p) / 1024 > MAX_KB:
            continue
        text = open(p, encoding="utf-8", errors="ignore").read().replace("\r", "")
        h = hashlib.md5(text.encode()).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        out.append((name, text))
    return out


def parse_text(text):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False, encoding="utf-8") as tmp:
        tmp.write(text)
        path = tmp.name
    try:
        return parse_config(path)
    finally:
        os.remove(path)


# ---------------------------------------------------------------------------
# Représentations
# ---------------------------------------------------------------------------
FEATURE_COLUMNS = [
    "n_interfaces", "n_acls", "n_vlans", "n_trunk_ports", "n_trunk_unrestricted",
    "has_telnet", "has_ssh_only", "has_password_encryption", "has_aaa",
    "has_banner", "has_weak_snmp", "has_http_server", "has_https",
]


def hand_features(text):
    parsed = parse_text(text)
    g = "\n".join(parsed["global_lines"]).lower()
    n_trunk = n_unres = 0
    for subs in parsed["interfaces"].values():
        t = "\n".join(subs).lower()
        if "switchport mode trunk" in t:
            n_trunk += 1
            if "switchport trunk allowed vlan" not in t:
                n_unres += 1
    has_telnet = has_ssh_only = 0
    for name, subs in parsed["lines"].items():
        if "vty" not in name:
            continue
        t = "\n".join(subs).lower()
        if "transport input telnet" in t or "transport input all" in t:
            has_telnet = 1
        if "transport input ssh" in t and "telnet" not in t and "all" not in t:
            has_ssh_only = 1
    return [
        len(parsed["interfaces"]), len(parsed["access_lists"]),
        g.count("\nvlan ") + (1 if g.startswith("vlan ") else 0), n_trunk, n_unres,
        has_telnet, has_ssh_only,
        1 if ("service password-encryption" in g and "no service password-encryption" not in g) else 0,
        1 if "aaa new-model" in g else 0, 1 if "banner login" in g else 0,
        1 if ("snmp-server community public" in g or "snmp-server community private" in g) else 0,
        1 if re.search(r"(^|\n)ip http server", g) else 0, 1 if "ip http secure-server" in g else 0,
    ]


def shape_doc(text):
    toks = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("!"):
            continue
        key = re.sub(r"[^a-z0-9_\-]", "", "_".join(s.split()[:2]).lower())
        toks.append(("b_" if line.startswith(" ") else "g_") + key)
    return " ".join(toks)


class Detector:
    """Isolation Forest sur la représentation choisie. Score plus bas = configuration plus atypique."""

    def __init__(self, mode="both", seed=42):
        self.mode, self.seed = mode, seed

    def _matrix(self, texts, fit):
        parts = []
        if self.mode in ("hand", "both"):
            H = np.array([hand_features(t) for t in texts], dtype=float)
            if fit:
                self.scaler = StandardScaler().fit(H)
            parts.append(self.scaler.transform(H))
        if self.mode in ("tfidf", "both"):
            docs = [shape_doc(t) for t in texts]
            if fit:
                self.tfidf = TfidfVectorizer(token_pattern=r"\S+", min_df=2, sublinear_tf=True).fit(docs)
                dim = max(2, min(8, len(docs) - 1, len(self.tfidf.vocabulary_) - 1))
                self.svd = TruncatedSVD(n_components=dim, random_state=self.seed).fit(self.tfidf.transform(docs))
            parts.append(self.svd.transform(self.tfidf.transform(docs)))
        return np.hstack(parts)

    def fit(self, texts):
        X = self._matrix(texts, fit=True)
        self.forest = IsolationForest(n_estimators=200, random_state=self.seed).fit(X)
        return self

    def score(self, texts):
        return self.forest.decision_function(self._matrix(texts, fit=False))


# ---------------------------------------------------------------------------
# Injection de fautes (pour l'évaluation)
# ---------------------------------------------------------------------------
def _set_vty_telnet(text):
    lines = text.splitlines()
    out, in_vty, done = [], False, False
    for l in lines:
        if re.match(r"^line vty", l):
            in_vty = True
            out.append(l)
            out.append(" transport input telnet")
            done = True
            continue
        if in_vty and l.startswith(" "):
            if l.strip().startswith("transport input"):
                continue
            out.append(l)
            continue
        in_vty = False
        out.append(l)
    if not done:
        out += ["line vty 0 4", " transport input telnet"]
    return "\n".join(out) + "\n"


def f_telnet(t): return _set_vty_telnet(t)
def f_snmp(t): return t.rstrip("\n") + "\nsnmp-server community public RW\n"
def f_noenc(t):
    kept = [l for l in t.splitlines() if l.strip() != "service password-encryption"]
    return "\n".join(kept) + "\nno service password-encryption\n"
def f_http(t):
    kept = [l for l in t.splitlines() if l.strip() != "no ip http server"]
    return "\n".join(kept) + "\nip http server\n"
def f_enablepw(t): return t.rstrip("\n") + "\nenable password cisco123\n"
def f_multi(t): return f_enablepw(f_http(f_snmp(f_telnet(t))))


FAULTS = [("Telnet sur VTY", f_telnet), ("SNMP public en écriture", f_snmp),
          ("Chiffrement des mots de passe désactivé", f_noenc), ("HTTP sans HTTPS", f_http),
          ("enable password", f_enablepw), ("Quatre fautes cumulées", f_multi)]


def prevalence(texts):
    n = len(texts)
    rx = {"Telnet sur VTY": r"transport input (telnet|all)", "SNMP public": r"snmp-server community (public|private)",
          "ip http server": r"(?m)^ip http server", "enable password": r"(?m)^enable password",
          "service password-encryption": r"(?m)^service password-encryption"}
    out = {}
    for k, r in rx.items():
        out[k] = sum(1 for t in texts if re.search(r, t)) / n
    return out


def evaluate(n_folds=5, seeds=(1, 2, 3, 4, 5)):
    ref = load_reference()
    names = [n for n, _ in ref]
    texts = [t for _, t in ref]
    n = len(texts)
    print(f"\nJeu de référence : {n} configurations (variantes générées exclues)")
    print("Part des configurations de référence qui présentent déjà l'état « fautif » :")
    for k, v in prevalence(texts).items():
        print(f"  {k:32} {v:5.0%}")

    wins = {m: {f: [] for f, _ in FAULTS} for m in MODES}
    for seed in seeds:
        order = np.random.RandomState(seed).permutation(n)
        folds = np.array_split(order, n_folds)
        for k in range(n_folds):
            test_idx = set(folds[k].tolist())
            train = [texts[i] for i in range(n) if i not in test_idx]
            for mode in MODES:
                det = Detector(mode, seed).fit(train)
                for i in test_idx:
                    base = det.score([texts[i]])[0]
                    for fname, fn in FAULTS:
                        faulty = det.score([fn(texts[i])])[0]
                        wins[mode][fname].append(1.0 if faulty < base - 1e-9 else 0.5 if abs(faulty - base) <= 1e-9 else 0.0)

    print(f"\nTaux de victoire : part des cas où la version FAUTIVE est jugée plus atypique que l'originale")
    print("(égalité de score = 0,5 : le modèle ne voit aucune différence)")
    print(f"(validation croisée {n_folds} blocs x {len(seeds)} graines ; 50 % = hasard)\n")
    print(f"{'Faute injectée':42}" + "".join(f"{m:>9}" for m in MODES))
    print("-" * 69)
    for fname, _ in FAULTS:
        print(f"{fname:42}" + "".join(f"{np.mean(wins[m][fname]):9.0%}" for m in MODES))
    print("-" * 69)
    print(f"{'Moyenne':42}" + "".join(f"{np.mean([np.mean(v) for v in wins[m].values()]):9.0%}" for m in MODES))
    print(f"\nObservations par cellule : {len(wins['hand'][FAULTS[0][0]])}")


# ---------------------------------------------------------------------------
# Entraînement, sauvegarde et scoring
# ---------------------------------------------------------------------------
def train(mode="both"):
    ref = load_reference()
    texts = [t for _, t in ref]
    det = Detector(mode, 42).fit(texts)
    train_scores = det.score(texts)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump({"detector": det, "train_scores": train_scores, "n": len(texts), "mode": mode}, MODEL_PATH)
    print(f"Modèle « {mode} » entraîné sur {len(texts)} configurations, sauvegardé : {os.path.abspath(MODEL_PATH)}")


_CACHE = {}


def score_config_text(text):
    """Retourne None si aucun modèle n'est sauvegardé, sinon score et rang d'atypie."""
    if "m" not in _CACHE:
        if not os.path.exists(MODEL_PATH):
            return None
        _CACHE["m"] = joblib.load(MODEL_PATH)
    m = _CACHE["m"]
    s = float(m["detector"].score([text.replace("\r", "")])[0])
    # part des configurations de référence MOINS atypiques (score plus élevé) que celle-ci
    share = float(np.mean(m["train_scores"] > s))
    return {"score": s, "atypical_share": share, "n_ref": m["n"], "mode": m["mode"]}


if __name__ == "__main__":
    # On passe par l'import du module pour que les objets sauvegardés portent le nom « ml_model »
    # (et non « __main__ »), ce qui les rend relisibles depuis le tableau de bord.
    import ml_model as _m

    cmd = sys.argv[1] if len(sys.argv) > 1 else "evaluate"
    if cmd == "evaluate":
        _m.evaluate()
    elif cmd == "train":
        _m.train(sys.argv[2] if len(sys.argv) > 2 else "both")
    elif cmd == "score" and len(sys.argv) > 2:
        r = _m.score_config_text(open(sys.argv[2], encoding="utf-8", errors="ignore").read())
        if r is None:
            print("Aucun modèle sauvegardé : lance d'abord « python ml_model.py train ».")
        else:
            print(f"Score : {r['score']:+.3f} (plus bas = plus atypique) ; plus atypique que {r['atypical_share']:.0%} "
                  f"des {r['n_ref']} configurations de référence")
    else:
        print(__doc__)