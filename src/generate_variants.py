"""
generate_variants.py — Génère des variantes "cassées" de R1.cfg / SW1.cfg

Prend les configs propres (durcies) comme base, et retire UNE protection
à la fois pour créer des paires quasi-identiques secure/weak. Ça aide le
modèle ML à isoler ce qui compte vraiment (plutôt que d'apprendre sur des
configs trop différentes entre elles sur 10 points à la fois).

Usage:
    python generate_variants.py
"""

import os

CONFIGS_DIR = "../configs"


def read_config(filename):
    with open(os.path.join(CONFIGS_DIR, filename), "r", encoding="utf-8") as f:
        return f.read()


def write_config(filename, content):
    with open(os.path.join(CONFIGS_DIR, filename), "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  Créé : {filename}")


def main():
    print("Génération de variantes cassées à partir de R1.cfg et SW1.cfg\n")

    # --- Variantes de R1 (routeur) ---
    r1_base = read_config("R1.cfg")

    # Variante 1 : réintroduction de Telnet (retire "ssh only" -> "telnet ssh")
    r1_telnet = r1_base.replace(
        " transport input ssh",
        " transport input telnet ssh"
    )
    write_config("R1_variant_telnet.cfg", r1_telnet)

    # Variante 2 : AAA désactivé
    r1_noaaa = r1_base.replace("aaa new-model\n!\n", "")
    r1_noaaa = r1_noaaa.replace("aaa authentication login default local \n!\n", "")
    write_config("R1_variant_noaaa.cfg", r1_noaaa)

    # Variante 3 : chiffrement des mots de passe désactivé
    r1_noenc = r1_base.replace(
        "service password-encryption",
        "no service password-encryption"
    )
    write_config("R1_variant_noenc.cfg", r1_noenc)

    # --- Variantes de SW1 (switch) ---
    sw1_base = read_config("SW1.cfg")

    # Variante 1 : réintroduction de Telnet sur les deux plages VTY
    sw1_telnet = sw1_base.replace(
        " transport input ssh",
        " transport input telnet ssh"
    )
    write_config("SW1_variant_telnet.cfg", sw1_telnet)

    # Variante 2 : trunk non restreint (retire la liste de VLANs autorisés)
    sw1_notrunk = sw1_base.replace(
        " switchport trunk allowed vlan 10,20,30,99\n", ""
    )
    write_config("SW1_variant_notrunkrestrict.cfg", sw1_notrunk)

    # Variante 3 : SNMP faible ajouté
    sw1_weaksnmp = sw1_base.replace(
        "hostname SW1\n",
        "hostname SW1\nsnmp-server community public RO\n"
    )
    write_config("SW1_variant_weaksnmp.cfg", sw1_weaksnmp)

    print("\n6 variantes générées avec succès.")


if __name__ == "__main__":
    main()
