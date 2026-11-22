"""
evaluate_rules.py — Évaluation des règles par injection de fautes

Pour chaque règle, on construit à la main :
  - des configurations FAUTIVES (la règle doit se déclencher),
  - des configurations SAINES (la règle doit rester silencieuse),
puis, pour chaque configuration fautive dont le correctif est exécutable, on
simule l'application du correctif sur le texte et on vérifie que l'anomalie
disparaît.

Ce test mesure la LOGIQUE de chaque règle, indépendamment de tout équipement.
Il ne dit rien du réalisme des configurations réelles (voir scan_folder.py).

Usage (depuis src/) :
    python evaluate_rules.py
Sorties : tableau dans le terminal + ../evaluation_regles.csv
"""

import csv
import os
import re
import tempfile
import time

from parser import parse_config
from rule_engine import load_rules, analyze_config

RULES_PATH = "../rules/rules.yaml"
CSV_PATH = "../evaluation_regles.csv"

BASE = "hostname EVAL\n!\n"
VTY_OK = "line vty 0 4\n transport input ssh\n exec-timeout 10 0\n!\n"


def cfg(*parts):
    return BASE + "".join(parts)


# ---------------------------------------------------------------------------
# Cas de test : (règle, nom du cas, texte, doit_se_déclencher)
# ---------------------------------------------------------------------------
CASES = []


def add(rule, name, text, should_fire):
    CASES.append((rule, name, text, should_fire))


# SEC001 — Telnet sur VTY
add("SEC001", "transport input telnet", cfg("line vty 0 4\n transport input telnet\n!\n"), True)
add("SEC001", "transport input all", cfg("line vty 0 4\n transport input all\n!\n"), True)
add("SEC001", "transport input telnet ssh", cfg("line vty 0 4\n transport input telnet ssh\n!\n"), True)
add("SEC001", "transport input ssh", cfg("line vty 0 4\n transport input ssh\n!\n"), False)
add("SEC001", "telnet sur la console (hors VTY)", cfg("line con 0\n transport input telnet\n!\n", VTY_OK), False)

# SEC002 — SNMP faible
add("SEC002", "community public", cfg("snmp-server community public RO\n", VTY_OK), True)
add("SEC002", "community private", cfg("snmp-server community private RW\n", VTY_OK), True)
add("SEC002", "community dérivée (publicstrang)", cfg("snmp-server community publicstrang RO\n", VTY_OK), True)
add("SEC002", "community robuste", cfg("snmp-server community Zk9-xQ4-77b RO\n", VTY_OK), False)
add("SEC002", "SNMP absent", cfg(VTY_OK), False)

# SEC003 — chiffrement des mots de passe
add("SEC003", "commande absente", cfg(VTY_OK), True)
add("SEC003", "no service password-encryption", cfg("no service password-encryption\n", VTY_OK), True)
add("SEC003", "service password-encryption", cfg("service password-encryption\n", VTY_OK), False)

# SEC004 — AAA
add("SEC004", "aaa absent", cfg(VTY_OK), True)
add("SEC004", "no aaa new-model", cfg("no aaa new-model\n", VTY_OK), True)
add("SEC004", "aaa new-model", cfg("aaa new-model\n", VTY_OK), False)

# SEC005 — trunk non restreint
add("SEC005", "trunk sans liste de VLAN", cfg("interface GigabitEthernet0/1\n switchport mode trunk\n!\n", VTY_OK), True)
add("SEC005", "trunk avec liste de VLAN", cfg("interface GigabitEthernet0/1\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n!\n", VTY_OK), False)
add("SEC005", "port d'accès", cfg("interface FastEthernet0/1\n switchport mode access\n switchport access vlan 10\n!\n", VTY_OK), False)

# SEC006 — bannière
add("SEC006", "bannière absente", cfg(VTY_OK), True)
add("SEC006", "bannière motd seule", cfg("banner motd ^C test ^C\n", VTY_OK), True)
add("SEC006", "banner login ^C ... ^C", cfg("banner login ^C Acces reserve ^C\n", VTY_OK), False)
add("SEC006", "banner login # ... #", cfg("banner login # Acces reserve #\n", VTY_OK), False)

# SEC007 — ACL sans deny final
add("SEC007", "ACL étendue numérotée sans deny", cfg("access-list 100 permit ip any any\n", VTY_OK), True)
add("SEC007", "ACL standard numérotée sans deny", cfg("access-list 11 permit 10.0.0.0 0.0.0.255\n", VTY_OK), True)
add("SEC007", "ACL nommée sans deny", cfg("ip access-list extended WEB\n permit tcp any any eq 80\n!\n", VTY_OK), True)
add("SEC007", "ACL numérotée avec deny", cfg("access-list 100 permit ip 10.0.0.0 0.0.0.255 any\naccess-list 100 deny ip any any\n", VTY_OK), False)
add("SEC007", "ACL nommée avec deny", cfg("ip access-list extended WEB\n permit tcp any any eq 80\n deny ip any any\n!\n", VTY_OK), False)

# SEC008 — HTTP sans HTTPS
add("SEC008", "ip http server seul", cfg("ip http server\n", VTY_OK), True)
add("SEC008", "http et https actifs", cfg("ip http server\nip http secure-server\n", VTY_OK), False)
add("SEC008", "no ip http server (HTTP désactivé)", cfg("no ip http server\n", VTY_OK), False)
add("SEC008", "https seul", cfg("ip http secure-server\n", VTY_OK), False)
add("SEC008", "no ip http server + https", cfg("no ip http server\nip http secure-server\n", VTY_OK), False)

# SEC009 / SEC010 / SEC011 / SEC012 / SEC015 — lignes « no ... » attendues
for rid, on, off in (("SEC009", "no ip source-route", "ip source-route"),
                     ("SEC010", "no cdp run", "cdp run"),
                     ("SEC011", "no ip bootp server", "ip bootp server"),
                     ("SEC012", "no service pad", "service pad")):
    add(rid, "ligne absente", cfg(VTY_OK), True)
    add(rid, f"« {off} » explicitement activé", cfg(off + "\n", VTY_OK), True)
    add(rid, f"« {on} » présent", cfg(on + "\n", VTY_OK), False)
add("SEC015", "keepalives absents", cfg(VTY_OK), True)
add("SEC015", "service tcp-keepalives-in", cfg("service tcp-keepalives-in\n", VTY_OK), False)

# SEC013 / SEC014 — petits services explicitement activés
add("SEC013", "service tcp-small-servers", cfg("service tcp-small-servers\n", VTY_OK), True)
add("SEC013", "absent (désactivé par défaut)", cfg(VTY_OK), False)
add("SEC013", "no service tcp-small-servers", cfg("no service tcp-small-servers\n", VTY_OK), False)
add("SEC014", "service udp-small-servers", cfg("service udp-small-servers\n", VTY_OK), True)
add("SEC014", "absent (désactivé par défaut)", cfg(VTY_OK), False)
add("SEC014", "no service udp-small-servers", cfg("no service udp-small-servers\n", VTY_OK), False)

# SEC016 — journalisation locale
add("SEC016", "logging absent", cfg(VTY_OK), True)
add("SEC016", "no logging buffered", cfg("no logging buffered\n", VTY_OK), True)
add("SEC016", "journalisation distante (logging host)", cfg("logging host 10.0.0.5\n", VTY_OK), False)
add("SEC016", "logging buffered 64000 informational", cfg("logging buffered 64000 informational\n", VTY_OK), False)

# SEC017 — NTP
add("SEC017", "ntp absent", cfg(VTY_OK), True)
add("SEC017", "sntp server (synchronisation SNTP)", cfg("sntp server 10.0.0.1\n", VTY_OK), False)
add("SEC017", "ntp server configuré", cfg("ntp server 10.0.0.1\n", VTY_OK), False)

# SEC018 — exec-timeout 0 sur VTY
add("SEC018", "exec-timeout 0 0 sur VTY", cfg("line vty 0 4\n transport input ssh\n exec-timeout 0 0\n!\n"), True)
add("SEC018", "exec-timeout 0 sur VTY", cfg("line vty 0 4\n transport input ssh\n exec-timeout 0\n!\n"), True)
add("SEC018", "exec-timeout 10 0 sur VTY", cfg("line vty 0 4\n transport input ssh\n exec-timeout 10 0\n!\n"), False)
add("SEC018", "exec-timeout 0 0 sur la console (hors VTY)", cfg("line con 0\n exec-timeout 0 0\n!\n", VTY_OK), False)
add("SEC018", "pas d'exec-timeout (défaut)", cfg("line vty 0 4\n transport input ssh\n!\n"), False)


# ---------------------------------------------------------------------------
# Règles SEC019 à SEC028 (configurations explicitement mauvaises)
# ---------------------------------------------------------------------------
# SEC019 — enable password
add("SEC019", "enable password en clair", cfg("enable password cisco123\n", VTY_OK), True)
add("SEC019", "enable password 7 ...", cfg("enable password 7 0822455D0A16\n", VTY_OK), True)
add("SEC019", "enable secret", cfg("enable secret 5 $1$LabEx$abc\n", VTY_OK), False)
add("SEC019", "aucun mot de passe enable défini", cfg(VTY_OK), False)

# SEC020 — utilisateur local avec password
add("SEC020", "username ... password", cfg("username admin password cisco\n", VTY_OK), True)
add("SEC020", "username ... privilege 15 password 7 ...", cfg("username admin privilege 15 password 7 0822455D0A16\n", VTY_OK), True)
add("SEC020", "username ... secret 5", cfg("username admin privilege 15 secret 5 $1$LabEx$abc\n", VTY_OK), False)
add("SEC020", "username ... secret 9", cfg("username admin secret 9 $9$abc\n", VTY_OK), False)

# SEC021 — SNMP en écriture
add("SEC021", "community RW", cfg("snmp-server community Zk9-xQ4 RW\n", VTY_OK), True)
add("SEC021", "community avec vue, RW", cfg("snmp-server community Zk9-xQ4 view iso RW\n", VTY_OK), True)
add("SEC021", "community RO", cfg("snmp-server community Zk9-xQ4 RO\n", VTY_OK), False)
add("SEC021", "nom de communauté contenant RW", cfg("snmp-server community RWx-team RO\n", VTY_OK), False)

# SEC022 — SSH v1
add("SEC022", "ip ssh version 1", cfg("ip ssh version 1\n", VTY_OK), True)
add("SEC022", "ip ssh version 2", cfg("ip ssh version 2\n", VTY_OK), False)
add("SEC022", "version SSH non précisée", cfg(VTY_OK), False)

# SEC023 — VTY sans access-class
add("SEC023", "vty sans access-class", cfg("line vty 0 4\n transport input ssh\n!\n"), True)
add("SEC023", "ipv6 access-class seul (IPv4 non restreint)", cfg("line vty 0 4\n ipv6 access-class V6 in\n!\n"), True)
add("SEC023", "access-class 10 in", cfg("line vty 0 4\n access-class 10 in\n transport input ssh\n!\n"), False)
add("SEC023", "console sans access-class (hors VTY)", cfg("line con 0\n logging synchronous\n!\n", "line vty 0 4\n access-class 10 in\n!\n"), False)

# SEC024 — no login
add("SEC024", "vty : no login", cfg("line vty 0 4\n no login\n!\n"), True)
add("SEC024", "console : no login", cfg("line con 0\n no login\n!\n", VTY_OK), True)
add("SEC024", "login local", cfg("line vty 0 4\n login local\n!\n"), False)
add("SEC024", "login", cfg("line vty 0 4\n login\n!\n"), False)

# SEC025 — mot de passe de ligne en clair
add("SEC025", "console : password en clair", cfg("line con 0\n password cisco\n!\n", VTY_OK), True)
add("SEC025", "vty : password 0 ...", cfg("line vty 0 4\n password 0 cisco\n!\n"), True)
add("SEC025", "vty : password 7 ...", cfg("line vty 0 4\n password 7 0822455D0A16\n!\n"), False)
add("SEC025", "aucun mot de passe de ligne", cfg(VTY_OK), False)

# SEC026 — services hérités
add("SEC026", "service finger", cfg("service finger\n", VTY_OK), True)
add("SEC026", "ip identd", cfg("ip identd\n", VTY_OK), True)
add("SEC026", "ip rcmd rsh-enable", cfg("ip rcmd rsh-enable\n", VTY_OK), True)
add("SEC026", "no service finger", cfg("no service finger\n", VTY_OK), False)
add("SEC026", "aucun service hérité", cfg(VTY_OK), False)

# SEC027 — ip directed-broadcast
add("SEC027", "ip directed-broadcast", cfg("interface GigabitEthernet0/0\n ip directed-broadcast\n!\n", VTY_OK), True)
add("SEC027", "ip directed-broadcast 101 (avec ACL)", cfg("interface GigabitEthernet0/0\n ip directed-broadcast 101\n!\n", VTY_OK), True)
add("SEC027", "no ip directed-broadcast", cfg("interface GigabitEthernet0/0\n no ip directed-broadcast\n!\n", VTY_OK), False)

# SEC028 — AAA avec repli none
add("SEC028", "login : group tacacs+ none", cfg("aaa authentication login default group tacacs+ none\n", VTY_OK), True)
add("SEC028", "enable : default none", cfg("aaa authentication enable default none\n", VTY_OK), True)
add("SEC028", "liste nommée : none", cfg("aaa authentication login CONSOLE none\n", VTY_OK), True)
add("SEC028", "login : group tacacs+ local", cfg("aaa authentication login default group tacacs+ local\n", VTY_OK), False)
add("SEC028", "login : local", cfg("aaa authentication login default local\n", VTY_OK), False)


# ---------------------------------------------------------------------------
# Simulation de l'application d'un correctif sur du texte de configuration
# ---------------------------------------------------------------------------
BLOCK_RE = re.compile(r"^(line |interface |ip access-list )")


def apply_fix(text, code_fix):
    lines = text.splitlines()
    block = None  # en-tête du bloc courant (ligne non indentée)
    for raw in code_fix.replace("\\n", "\n").splitlines():
        cmd = raw.rstrip()
        if not cmd.strip() or cmd.strip().startswith("!"):
            continue
        indented = raw.startswith(" ")
        if not indented and BLOCK_RE.match(cmd):
            block = cmd
            if block not in lines:
                lines += [block]
            continue
        if indented and block and cmd.strip().startswith("no "):
            start = lines.index(block)
            end = start + 1
            while end < len(lines) and lines[end].startswith(" "):
                end += 1
            target = cmd.strip()[3:]
            kept = [l for l in lines[start + 1:end] if not (l.strip() == target or l.strip().startswith(target + " "))]
            if cmd.strip() not in [l.strip() for l in kept]:
                kept.append(" " + cmd.strip())
            lines[start + 1:end] = kept
            continue
        if indented and block:
            start = lines.index(block)
            end = start + 1
            while end < len(lines) and lines[end].startswith(" "):
                end += 1
            key = " ".join(cmd.split()[:2]) if cmd.split()[0] == "transport" else cmd.split()[0]
            # une commande positive annule sa forme négative (ex : « login local » remplace « no login »)
            negs = {"no " + cmd.strip(), "no " + cmd.split()[0]}
            kept = [l for l in lines[start + 1:end] if l.strip() not in negs]
            lines[start + 1:end] = kept
            end = start + 1 + len(kept)
            for i in range(start + 1, end):
                if lines[i].strip().startswith(key):
                    lines[i] = " " + cmd.strip()
                    break
            else:
                lines.insert(end, " " + cmd.strip())
            continue
        block = None
        stripped = cmd.strip()
        if stripped.startswith("no "):
            lines = [l for l in lines if l.strip() != stripped[3:]]
            if stripped not in [l.strip() for l in lines]:
                lines.append(stripped)
        else:
            if re.match(r"^ip ssh version \d$", stripped):  # commande qui remplace la valeur précédente
                lines = [l for l in lines if not l.strip().startswith("ip ssh version ")]
            lines = [l for l in lines if l.strip() != "no " + stripped]
            if stripped not in [l.strip() for l in lines]:
                lines.append(stripped)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
def analyze_text(text, rules):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False, encoding="utf-8") as tmp:
        tmp.write(text)
        path = tmp.name
    try:
        return analyze_config(parse_config(path), rules)
    finally:
        os.remove(path)


def main():
    rules = load_rules(RULES_PATH)
    rule_ids = [r["rule_id"] for r in rules]
    stats = {rid: dict(fire_ok=0, fire_n=0, quiet_ok=0, quiet_n=0, fix_ok=0, fix_n=0, fix_na=0) for rid in rule_ids}
    failures = []
    t0 = time.perf_counter()

    for rid, name, text, should_fire in CASES:
        found = [a for a in analyze_text(text, rules) if a["rule_id"] == rid]
        fired = bool(found)
        s = stats[rid]
        if should_fire:
            s["fire_n"] += 1
            s["fire_ok"] += fired
            if not fired:
                failures.append((rid, name, "NON DÉTECTÉ (faux négatif)"))
            else:
                # efficacité du correctif simulé
                a = found[0]
                fix = a.get("code_fix", "")
                if (not fix.strip() or re.search(r"<[^>\n]+>", fix)
                        or all(l.strip().startswith("!") or not l.strip() for l in fix.splitlines())):
                    s["fix_na"] += 1
                else:
                    s["fix_n"] += 1
                    after = analyze_text(apply_fix(text, fix), rules)
                    gone = not any(b["rule_id"] == rid and b["detail"] == a["detail"] for b in after)
                    s["fix_ok"] += gone
                    if not gone:
                        failures.append((rid, name, "CORRECTIF INEFFICACE (l'anomalie persiste après le correctif)"))
        else:
            s["quiet_n"] += 1
            s["quiet_ok"] += (not fired)
            if fired:
                failures.append((rid, name, "DÉCLENCHÉ À TORT (faux positif)"))
    elapsed = time.perf_counter() - t0

    # --- Tableau -----------------------------------------------------------
    print(f"\n{'Règle':7} {'Détection':>10} {'Silence':>9} {'Correctif':>18}")
    print("-" * 48)
    rows = []
    for rid in rule_ids:
        s = stats[rid]
        det = f"{s['fire_ok']}/{s['fire_n']}"
        sil = f"{s['quiet_ok']}/{s['quiet_n']}"
        if s["fix_n"]:
            fx = f"{s['fix_ok']}/{s['fix_n']}"
            if s["fix_na"]:
                fx += f" (+{s['fix_na']} n/a)"
        else:
            fx = "non applicable"
        print(f"{rid:7} {det:>10} {sil:>9} {fx:>18}")
        rows.append([rid, det, sil, fx])

    tot = lambda k: sum(stats[r][k] for r in rule_ids)
    print("-" * 48)
    print(f"Détection         : {tot('fire_ok')}/{tot('fire_n')} cas fautifs détectés")
    print(f"Silence           : {tot('quiet_ok')}/{tot('quiet_n')} cas sains sans alerte "
          f"(faux positifs : {tot('quiet_n') - tot('quiet_ok')})")
    print(f"Correctif simulé  : {tot('fix_ok')}/{tot('fix_n')} correctifs efficaces "
          f"({tot('fix_na')} cas sans correctif exécutable)")
    print(f"Cas de test       : {len(CASES)} en {elapsed * 1000:.0f} ms au total")

    if failures:
        print("\nCas en échec à examiner :")
        for rid, name, why in failures:
            print(f"  {rid} — {name} : {why}")
    else:
        print("\nAucun cas en échec.")

    with open(CSV_PATH, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Règle", "Détection (fautif)", "Silence (sain)", "Correctif simulé"])
        w.writerows(rows)
    print(f"\nTableau enregistré : {CSV_PATH}")


if __name__ == "__main__":
    main()