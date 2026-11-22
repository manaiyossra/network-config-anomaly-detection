"""
rule_engine.py — Moteur de détection d'anomalies de sécurité
"""

import re

import yaml


def load_rules(rules_path):
    with open(rules_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data["rules"]


def _global_text(parsed):
    return "\n".join(parsed["global_lines"])


def _line_active(parsed, pattern):
    """
    Vrai si une ligne globale est égale au motif ou commence par le motif
    suivi d'un espace. Une ligne 'no <motif>' n'est donc PAS considérée
    comme active.
    """
    for line in parsed["global_lines"]:
        stripped = line.strip()
        if stripped == pattern or stripped.startswith(pattern + " "):
            return True
    return False


def _check_line_contains(parsed, rule):
    findings = []
    if "vty" in rule["section"] or "line" in rule["section"]:
        for line_name, sublines in parsed["lines"].items():
            if "vty" not in line_name:
                continue
            for subline in sublines:
                if rule["pattern"] in subline:
                    for bad in rule["bad_values"]:
                        if bad in subline:
                            findings.append({
                                "context": line_name,
                                "detail": f"line {line_name}: '{subline}'",
                            })
                            break
    else:
        for line in parsed["global_lines"]:
            if rule["pattern"] in line:
                for bad in rule["bad_values"]:
                    if bad in line:
                        findings.append({"context": "", "detail": f"'{line}'"})
                        break
    return findings


def _check_absence(parsed, rule):
    """
    Vérifie qu'une commande attendue est bien active dans la config.
    Gère 3 cas : absente, présente mais désactivée ('no <commande>'), ou active.
    Une ligne est considérée active si elle est égale au pattern OU commence
    par le pattern suivi d'un espace (ex: 'banner login ^C ... ^C').
    """
    pattern = rule["pattern"]
    for line in parsed["global_lines"]:
        stripped = line.strip()
        if stripped == pattern or stripped.startswith(pattern + " "):
            return []
        if stripped == f"no {pattern}":
            return [{"context": "", "detail": f"'{pattern}' est explicitement désactivé ('no {pattern}')"}]
    return [{"context": "", "detail": f"'{pattern}' absent de la configuration"}]


def _check_interface_trunk(parsed, rule):
    findings = []
    for iface_name, sublines in parsed["interfaces"].items():
        text = "\n".join(sublines)
        if rule["pattern"] in text:
            if rule["required_pattern"] not in text:
                findings.append({
                    "context": iface_name,
                    "detail": f"interface {iface_name}: trunk sans VLAN autorisé restreint",
                })
    return findings


def _acl_deny_fix(acl_name):
    """Correctif adapté au type d'ACL (déduit du numéro), ou commentaire si inconnu."""
    if acl_name.isdigit():
        n = int(acl_name)
        if 1 <= n <= 99 or 1300 <= n <= 1999:        # ACL standard
            return f"access-list {acl_name} deny any"
        if 100 <= n <= 199 or 2000 <= n <= 2699:     # ACL étendue
            return f"access-list {acl_name} deny ip any any"
    return (f"! ACL '{acl_name}' : type (standard/étendue) inconnu, "
            f"vérifier avant d'ajouter un deny final")


def _check_acl(parsed, rule):
    findings = []
    for acl_name, entries in parsed["access_lists"].items():
        text = " ".join(entries).lower()
        if "deny" not in text:
            findings.append({
                "context": acl_name,
                "detail": f"ACL '{acl_name}': aucun 'deny' trouvé (pas de default-deny explicite)",
                "code_fix": _acl_deny_fix(acl_name),
            })
    return findings


def _check_pair(parsed, rule):
    """Si 'pattern' est actif, 'required_pattern' doit l'être aussi (lignes actives, hors 'no ...')."""
    findings = []
    if _line_active(parsed, rule["pattern"]) and not _line_active(parsed, rule["required_pattern"]):
        findings.append({
            "context": "",
            "detail": f"'{rule['pattern']}' présent sans '{rule['required_pattern']}'",
        })
    return findings


def _check_presence_substring(parsed, rule):
    """
    Vérifie qu'une commande (avec ou sans arguments) est active dans la config.
    Des formes équivalentes peuvent être listées dans 'alt_patterns'
    (ex: 'sntp server' pour la synchronisation horaire).
    """
    patterns = [rule["pattern"]] + list(rule.get("alt_patterns", []))
    if not any(_line_active(parsed, p) for p in patterns):
        return [{"context": "", "detail": f"'{rule['pattern']}' absent de la configuration"}]
    return []


def _check_vty_missing_command(parsed, rule):
    """
    Vérifie que chaque bloc 'line vty' contient une commande donnée
    (ex: 'exec-timeout'), indépendamment de sa valeur exacte.
    (Plus utilisé par SEC018 depuis le passage à vty_exact_line, conservé
    pour d'éventuelles règles futures.)
    """
    findings = []
    for line_name, sublines in parsed["lines"].items():
        if "vty" not in line_name:
            continue
        text = "\n".join(sublines)
        if rule["required_pattern"] not in text:
            findings.append({
                "context": line_name,
                "detail": f"line {line_name}: '{rule['required_pattern']}' absent",
            })
    return findings


def _check_forbidden_line(parsed, rule):
    """
    Signale une commande qui ne devrait PAS être présente (ex: 'service
    tcp-small-servers' explicitement activé). Contrairement à _check_absence,
    l'absence de la ligne n'est pas une anomalie : sur les IOS récents ces
    services sont désactivés par défaut et rien n'est affiché.
    """
    pattern = rule["pattern"]
    for line in parsed["global_lines"]:
        stripped = line.strip()
        if stripped == pattern or stripped.startswith(pattern + " "):
            return [{"context": "", "detail": f"'{stripped}' est activé"}]
    return []


def _check_vty_exact_line(parsed, rule):
    """
    Signale, dans chaque bloc 'line vty', une ligne EXACTEMENT égale à l'une
    des valeurs de rule['bad_lines'] (ex: 'exec-timeout 0 0'). Comparaison
    exacte : 'exec-timeout 10 0' ne doit pas être confondu avec 'exec-timeout 0 0'.
    """
    findings = []
    for line_name, sublines in parsed["lines"].items():
        if "vty" not in line_name:
            continue
        for subline in sublines:
            if subline.strip() in rule["bad_lines"]:
                findings.append({
                    "context": line_name,
                    "detail": f"line {line_name}: '{subline.strip()}'",
                })
    return findings


def _check_regex_line(parsed, rule):
    """Signale chaque ligne globale qui correspond à l'expression régulière rule['regex']."""
    findings = []
    rx = re.compile(rule["regex"])
    for line in parsed["global_lines"]:
        stripped = line.strip()
        if rx.search(stripped):
            findings.append({"context": "", "detail": f"'{stripped}'"})
    return findings


def _check_forbidden_lines(parsed, rule):
    """Comme forbidden_line, pour une liste de commandes (rule['patterns']). Correctif : 'no <commande>'."""
    findings = []
    for pattern in rule["patterns"]:
        for line in parsed["global_lines"]:
            stripped = line.strip()
            if stripped == pattern or stripped.startswith(pattern + " "):
                findings.append({"context": pattern, "detail": f"'{stripped}' est activé",
                                 "code_fix": f"no {pattern}"})
                break
    return findings


def _line_blocks(parsed, rule):
    """Blocs 'line' dont le type (vty, con, aux) figure dans rule['blocks']."""
    wanted = rule.get("blocks", ["vty"])
    for line_name, sublines in parsed["lines"].items():
        if line_name.split()[0] in wanted:
            yield line_name, sublines


def _check_line_exact_line(parsed, rule):
    """Une ligne EXACTEMENT égale à rule['bad_lines'] dans un bloc line (vty, con, aux)."""
    findings = []
    for line_name, sublines in _line_blocks(parsed, rule):
        for subline in sublines:
            if subline.strip() in rule["bad_lines"]:
                findings.append({"context": line_name, "detail": f"line {line_name}: '{subline.strip()}'"})
    return findings


def _check_line_regex(parsed, rule):
    """Une ligne qui correspond à rule['regex'] dans un bloc line (vty, con, aux)."""
    findings = []
    rx = re.compile(rule["regex"])
    for line_name, sublines in _line_blocks(parsed, rule):
        for subline in sublines:
            if rx.search(subline.strip()):
                findings.append({"context": line_name, "detail": f"line {line_name}: '{subline.strip()}'"})
    return findings


def _check_vty_missing_regex(parsed, rule):
    """Chaque bloc 'line vty' doit contenir une ligne qui correspond à rule['regex']."""
    findings = []
    rx = re.compile(rule["regex"])
    for line_name, sublines in _line_blocks(parsed, rule):
        if not any(rx.search(s.strip()) for s in sublines):
            findings.append({"context": line_name, "detail": f"line {line_name}: aucune ligne « {rule['label']} »"})
    return findings


def _check_interface_forbidden_line(parsed, rule):
    """Une commande interdite (rule['patterns']) activée sur une interface. Correctif : 'no <commande>'."""
    findings = []
    for iface_name, sublines in parsed["interfaces"].items():
        for pattern in rule["patterns"]:
            for subline in sublines:
                s = subline.strip()
                if s == pattern or s.startswith(pattern + " "):
                    findings.append({"context": iface_name, "detail": f"interface {iface_name}: '{s}'",
                                     "code_fix": f"interface {iface_name}\n no {pattern}"})
                    break
    return findings


_CHECK_DISPATCH = {
    "line_contains": _check_line_contains,
    "absence": _check_absence,
    "interface_trunk_check": _check_interface_trunk,
    "acl_check": _check_acl,
    "pair_check": _check_pair,
    "presence_substring": _check_presence_substring,
    "vty_missing_command": _check_vty_missing_command,
    "forbidden_line": _check_forbidden_line,
    "vty_exact_line": _check_vty_exact_line,
    "regex_line": _check_regex_line,
    "forbidden_lines": _check_forbidden_lines,
    "line_exact_line": _check_line_exact_line,
    "line_regex": _check_line_regex,
    "vty_missing_regex": _check_vty_missing_regex,
    "interface_forbidden_line": _check_interface_forbidden_line,
}


def analyze_config(parsed, rules):
    anomalies = []
    for rule in rules:
        check_fn = _CHECK_DISPATCH.get(rule["check_type"])
        if not check_fn:
            continue
        findings = check_fn(parsed, rule)
        for finding in findings:
            if finding.get("code_fix"):
                # correctif fourni directement par la vérification (ex: ACL)
                code_fix = finding["code_fix"]
            else:
                template = rule.get("code_fix", "")
                try:
                    code_fix = template.format(context=finding["context"]) if template else ""
                except (KeyError, IndexError):
                    code_fix = template

            anomalies.append({
                "rule_id": rule["rule_id"],
                "description": rule["description"],
                "risk_level": rule["risk_level"],
                "detail": finding["detail"],
                "recommendation": rule["recommendation"],
                "code_fix": code_fix,
                "confidence": rule.get("confidence", "medium"),
                "auto_apply": rule.get("auto_apply", False),
            })
    return anomalies


def print_report(filename, anomalies):
    print(f"\n{'='*70}")
    print(f"RAPPORT D'ANALYSE — {filename}")
    print(f"{'='*70}")
    if not anomalies:
        print("Aucune anomalie détectée. ✓")
        return
    print(f"{len(anomalies)} anomalie(s) détectée(s) :\n")
    for a in anomalies:
        print(f"[{a['risk_level'].upper()}] {a['rule_id']} — {a['description']}")
        print(f"    -> {a['detail']}")
        print(f"    Recommandation : {a['recommendation']}")
        if a.get("code_fix"):
            fix_lines = a["code_fix"].replace("\\n", "\n").split("\n")
            print(f"    Correctif suggéré :")
            for line in fix_lines:
                print(f"        {line}")
        print()


if __name__ == "__main__":
    import sys
    from parser import parse_config

    if len(sys.argv) < 2:
        print("Usage: python rule_engine.py <fichier_config>")
        sys.exit(1)

    rules = load_rules("../rules/rules.yaml")
    parsed = parse_config(sys.argv[1])
    anomalies = analyze_config(parsed, rules)
    print_report(sys.argv[1], anomalies)