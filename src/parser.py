"""
parser.py — Parseur de fichiers de configuration Cisco IOS
"""

import re


def parse_config(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        raw_lines = [line.rstrip("\n") for line in f]

    result = {
        "raw_lines": raw_lines,
        "global_lines": [],
        "interfaces": {},
        "lines": {},
        "access_lists": {},
    }

    current_block_type = None
    current_block_name = None

    for line in raw_lines:
        stripped = line.strip()

        if not stripped or stripped == "!":
            current_block_type = None
            current_block_name = None
            continue

        m_iface = re.match(r"^interface\s+(\S.*)$", stripped)
        if m_iface:
            current_block_type = "interface"
            current_block_name = m_iface.group(1).strip()
            result["interfaces"].setdefault(current_block_name, [])
            continue

        m_line = re.match(r"^line\s+(\S.*)$", stripped)
        if m_line:
            current_block_type = "line"
            current_block_name = m_line.group(1).strip()
            result["lines"].setdefault(current_block_name, [])
            continue

        m_acl_single = re.match(r"^access-list\s+(\S+)\s+(.*)$", stripped)
        if m_acl_single and not line.startswith(" "):
            acl_name = m_acl_single.group(1)
            acl_rule = m_acl_single.group(2)
            result["access_lists"].setdefault(acl_name, []).append(acl_rule)
            current_block_type = None
            current_block_name = None
            continue

        m_acl_block = re.match(r"^ip access-list\s+(standard|extended)\s+(\S+)$", stripped)
        if m_acl_block:
            current_block_type = "acl"
            current_block_name = m_acl_block.group(2)
            result["access_lists"].setdefault(current_block_name, [])
            continue

        if line.startswith(" ") and current_block_type:
            if current_block_type == "interface":
                result["interfaces"][current_block_name].append(stripped)
            elif current_block_type == "line":
                result["lines"][current_block_name].append(stripped)
            elif current_block_type == "acl":
                result["access_lists"][current_block_name].append(stripped)
            continue

        current_block_type = None
        current_block_name = None
        result["global_lines"].append(stripped)

    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python parser.py <fichier_config>")
        sys.exit(1)

    parsed = parse_config(sys.argv[1])
    print(f"--- Résumé du parsing de {sys.argv[1]} ---")
    print(f"Lignes globales : {len(parsed['global_lines'])}")
    print(f"Interfaces trouvées : {len(parsed['interfaces'])} -> {list(parsed['interfaces'].keys())}")
    print(f"Blocs 'line' trouvés : {list(parsed['lines'].keys())}")
    print(f"ACLs trouvées : {list(parsed['access_lists'].keys())}")
