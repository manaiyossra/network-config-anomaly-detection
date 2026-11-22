"""
Test hors-ligne du connecteur avec un équipement SIMULÉ.
N'utilise ni SSH, ni ta vraie base : tout est écrit dans un dossier temporaire.
Usage (depuis src/) : python test_connector_offline.py
"""
import os
import sqlite3
import tempfile
from unittest.mock import patch

import device_connector as dc

BEFORE = """hostname LAB
snmp-server community public RO
!
interface GigabitEthernet0/1
 switchport mode trunk
!
access-list 100 permit ip any any
!
line vty 0 4
 transport input telnet ssh
!
end
"""
AFTER = (BEFORE.replace("transport input telnet ssh", "transport input ssh")
         + "service password-encryption\nbanner login ^C Acces ^C\n")

tmp = tempfile.mkdtemp()
devices_file = os.path.join(tmp, "devices.yaml")
with open(devices_file, "w", encoding="utf-8") as f:
    f.write("devices:\n"
            "  - name: LabSimule\n    host: 10.10.20.48\n    username: u\n    password: p\n    auto_fix: true\n"
            "  - name: SansAutoFix\n    host: 10.0.0.9\n    username: u\n    password: p\n")

calls = {}


def fake_fetch(device):
    n = calls.get(device["host"], 0)
    calls[device["host"]] = n + 1
    return BEFORE if n == 0 else AFTER


def fake_push(device, fixes):
    print("   >> commandes envoyées à l'équipement simulé :", [f["commands"] for f in fixes])
    return [{"fix_id": f["fix_id"], "ok": True, "output": ""} for f in fixes], True


with patch.object(dc, "DEVICES_PATH", devices_file), \
     patch.object(dc, "DB_PATH", os.path.join(tmp, "test.db")), \
     patch.object(dc, "BACKUP_DIR", os.path.join(tmp, "backups")), \
     patch.object(dc, "fetch_config_via_ssh", fake_fetch), \
     patch.object(dc, "push_fixes_via_ssh", fake_push):
    dc.run_pipeline(apply_fixes=True, full_auto=True)

c = sqlite3.connect(os.path.join(tmp, "test.db"))
print("\nStatut des correctifs (équipement simulé) :")
for rule_id, status in c.execute(
        "SELECT f.rule_id, f.status FROM fixes f JOIN configs c ON c.id = f.config_id "
        "WHERE c.host = '10.10.20.48' ORDER BY f.id"):
    print("  ", rule_id, status)
c.close()
print("\nDossier temporaire de ce test :", tmp)