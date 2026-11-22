# Network Config Anomaly Detection & Safe Auto-Remediation (Cisco IOS)

A prototype built during an 8-week internship in the cybersecurity department of an industrial group.
It reads Cisco IOS / IOS XE configurations (from files or over SSH), checks them against a catalogue of
28 security rules, generates fix commands, and can apply the permitted ones automatically behind
several safeguards. An Isolation Forest model adds an exploratory statistical score.

> Prototype for study purposes. Not production software. Never run auto-fix on production or shared devices.

## Features
- **Parser and rule engine**: 28 YAML rules in 7 families (access, SNMP, encryption, services, logging, ...), each with a risk level, a confidence level, a fix and an `auto_apply` flag.
- **SQLite storage** of configurations, anomalies and fixes.
- **SSH connector (Netmiko)**: collect, back up, apply fixes, then re-scan to verify.
- **Streamlit dashboard**: 5 tabs to browse devices, anomalies and fixes.
- **Evaluation by fault injection**: known faults are injected into clean configs to measure detection and fix coverage.
- **Isolation Forest** (optional): exploratory anomaly score, complements the rules and does not replace them.

## Safety of the automatic correction
No fix is sent if it contains a field to fill in, if its rule is not marked `auto_apply`, or if the device
does not have `auto_fix: true` in `devices.yaml`. The configuration is backed up to `backups/` before any
change, and at the first rejection by the device processing stops and nothing is saved.

## Installation
```
pip install -r requirements.txt
```
Run all commands from the `src/` folder.

## Usage
```
python build_database.py                  # import ../configs into the database
python -m streamlit run app.py            # dashboard

python device_connector.py                # SSH scan only (no change)
python device_connector.py --apply-fixes  # apply permitted fixes, excluding high risk
python device_connector.py --full-auto    # include high risk if the rule allows it

python evaluate_rules.py                  # fault-injection evaluation
python test_connector_offline.py          # connector test without a device
python scan_folder.py <folder>            # analyse a folder of configs
```
To scan real devices, copy `devices.example.yaml` to `devices.yaml` and fill in your own lab device.
`devices.yaml` is git-ignored: never commit credentials.

## Project layout
| Path | Role |
|---|---|
| `rules/rules.yaml` | Rule catalogue |
| `configs/` | Lab configurations (R1, SW1 and generated variants with one injected fault each) |
| `src/parser.py`, `src/rule_engine.py` | Parsing and rule engine |
| `src/build_database.py` | SQLite database |
| `src/device_connector.py` | SSH collection, auto-fix, verification |
| `src/app.py` | Streamlit dashboard |
| `src/ml_model.py` | Isolation Forest (optional) |
| `src/evaluate_rules.py`, `src/generate_variants.py` | Fault injection and variant generation |
| `src/scan_folder.py` | Analyse a folder of configurations |

## Optional: Isolation Forest reference set
The model was trained on public Cisco IOS configurations from the
[Batfish](https://github.com/batfish/batfish) repository (Apache License 2.0), which are not redistributed
here. To use `ml_model.py`, download them yourself into `configs_reference/`. The rule engine, the
connector and the dashboard work without it.

## Limitations
- No firewalls yet.
- Rules based on a missing line depend on the platform (see each rule's confidence level).
- The statistical model is exploratory (32 reference configurations).
- The lab configurations are synthetic. Their password hashes are placeholders.

## Licence
MIT, see `LICENSE`.
