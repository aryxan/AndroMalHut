# Changelog & Independent Review Remediation

This changelog records the complete status of all 23 findings identified during the independent forensic and technical review of **AndroMalHut**.

---

## Summary of Findings Status

| Phase | Item | Scope | Status | Reason / Description |
|:---:|:---:|:---|:---:|:---|
| **Phase 1** | **1** | Fix missing `Optional` import in `modules/permission_analysis.py` | **DONE** | Added missing `Optional` import from `typing`. Confirmed `python3 andromalhut.py check-deps` and `pytest` run cleanly. |
| **Phase 1** | **2** | Add undeclared dependencies (`androguard`, `cryptography`, `loguru`) to `requirements.txt` and `install_deps.sh` | **DONE** | Scanned all project imports. Pinned `androguard>=4.0.0,<5.0.0`, `cryptography>=40.0.0`, `loguru>=0.7.0`, and `pytest>=7.0.0` in both files. |
| **Phase 1** | **3** | Test clean virtualenv setup from scratch | **DONE** | Created clean virtual environment at `/tmp/clean_test_venv`, ran `pip install -r requirements.txt`, and verified 100% test pass rate with zero manual interventions. |
| **Phase 1** | **4** | CI workflow & remove hardcoded badges from `README.md` | **DONE** | Added `.github/workflows/ci.yml` testing Python 3.10, 3.11, and 3.12. Replaced static badges ("36 Passed", static accuracy) with dynamic GitHub Actions workflow status badge. |
| **Phase 2** | **5** | Remove hardcoded strings & verify hash manifest dynamically in reports | **DONE** | Removed static verification text and fictional "Mobile Forensic & Threat Incident Response Unit". Integrated real cryptographic hash verification `verify_case_hashes()` displaying PASS/FAIL and count of verified items. Configured blank default examiner unit. |
| **Phase 2** | **6** | Test tampered evidence detection in reports | **DONE** | Added `test_tampered_evidence_shows_fail_in_report` in `tests/test_reporting_and_provenance.py` verifying that modifying evidence file contents produces a `FAIL` status in generated reports. |
| **Phase 2** | **7** | Dynamic analysis opt-in, emulator-first, risk confirmation, and drop `-g` | **DONE** | Made dynamic analysis strictly opt-in (`--dynamic`). Restricted execution to emulators by default. Enforced `--allow-physical` with required typed confirmation `"I ACCEPT RISK"` for physical devices. Dropped `-g` default. Conditional report wording ("dynamic analysis was NOT performed" vs "performed on <device>"). |
| **Phase 2** | **8** | Tamper-evident audit log with hash chaining & verify command | **DONE** | Implemented cryptographic SHA-256 hash chaining (`prev_hash` + entry -> `entry_hash`) on `case_audit.log`. Added `verify_audit_log` function and `verify-audit` CLI command. Audited README language to remove ungrounded claims ("immutable", "evidence-grade", "sealed"). Added unit test `test_audit_log_hash_chain_tamper_detection`. |
| **Phase 3** | **9** | Remove circular labeling in training pipeline | **DONE** | Removed filename regex checks and model self-prediction (`ml_verdict`) labeling. Modern unverified samples without external ground truth are excluded by default. Added `--labels-csv` / `LABELS_CSV` parameter for verified external ground truth. |
| **Phase 3** | **10** | Fix train/test data leakage & deduplication | **DONE** | Deduplicated identical feature vectors BEFORE splitting (reduced 25,722 raw samples to 11,696 unique capability vectors). Removed replication. Partitioned into 70% train (8,186), 15% validation (1,755), and 15% holdout test (1,755) touched only once for final evaluation. |
| **Phase 3** | **11** | Dataset-source leakage fixes & cross-dataset evaluation | **DONE** | Added source ablation run on 111 shared features (88.72% acc, 0.9551 AUC). Implemented cross-dataset evaluation (Drebin->AndroZoo: 53.65% acc; AndroZoo->Drebin: 72.87% acc). Documented cross-dataset drop and per-source holdout breakdown directly in `README.md`. |
| **Phase 3** | **12** | Correct statistical formulas for FPR and FNR | **DONE** | Corrected formulas: $\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}} = 6.57\%$ and $\text{FNR} = \frac{\text{FN}}{\text{FN} + \text{TP}} = 6.67\%$. Updated `scripts/generate_plots.py` and Plotly interactive dashboard. |
| **Phase 3** | **13** | Consistent sample counts and metrics across repo | **DONE** | Computed dataset metrics once and stored in `ml_model/evaluation.json` and `ml_model/andromalhut_model_metadata.json`. Synchronized `scan_apk.py`, `andromalhut.py`, and `evaluation.txt`. Created `scripts/generate_readme_metrics.py` to auto-generate README markdown tables directly from `evaluation.json`. |
| **Phase 3** | **14** | Remove personal hardcoded paths & support CLI args / env vars | **DONE** | Removed all hardcoded `/home/mrrobot/...` paths from `ml_model/train.py`. Replaced with CLI arguments (`--zoo-csv`, `--drebin-csv`, `--labels-csv`) and environment variables (`ANDROZOO_CSV`, `DREBIN_CSV`, `LABELS_CSV`) with clear error guidance. Removed `.gitignore` patterns hiding inputs. |
| **Phase 3** | **15** | Model serialization security & accurate naming | **DONE** | Saved trained model using native XGBoost JSON (`andromalhut_xgboost.json`) + metadata JSON (`andromalhut_model_metadata.json`). Updated `scan_apk.py` to load native JSON format and verify SHA-256 cryptographic hashes prior to loading legacy `.joblib` files to prevent deserialization vulnerabilities. Kept backward-compatible `drebin_rf.joblib`. |
| **Phase 3** | **16** | Remove unbundled independent benchmark claim | **DONE** | Removed unverified 58-sample benchmark claim from `ml_model/README.md`. |
| **Phase 3** | **17** | Document historical dataset limitations in README | **DONE** | Added transparent limitations notice explaining that training data is primarily from 2011–2016 academic corpora, random-split overstates real-world generalization, and temporal drift degrades performance on modern malware. Replaced "state-of-the-art" with factual technical descriptions. |
| **Phase 4** | **18** | Zero-trust identity verification (no package-name-only benign labels) | **DONE** | Refactored `modules/online_verifier.py`: package name alone NEVER marks an app "verified" or "BENIGN" (yields `"Identity claimed, NOT verified"`). Only cryptographic signing certificate match against known vendor certificate digests or NSRL/CIRCL hash match produces a "VERIFIED" trust state. Removed package-name whitelist bypasses in `scan_apk.py`. |
| **Phase 4** | **19** | Restore distinct SUSPICIOUS class and explainable behavioral flags | **DONE** | Restored distinct `SUSPICIOUS` classification for scores between 0.50 and 0.65 in `scan_apk.py`. Re-introduced explainable high-risk interaction flags (covert spyware, accessibility overlay abuse, device admin persistence, SMS boot persistence) that promote borderline samples with clear forensic rationale. |
| **Phase 4** | **20** | Opt-in online lookups with privacy disclosures | **DONE** | Made all external network queries opt-in via `--online` (default `False`). Implemented interactive confirmation disclosures in `andromalhut.py` printing exact transmitted data (package name, SHA-256) before sending. Documented network governance in README. |
| **Phase 5** | **21** | Codebase hygiene, rename leftover "AScanner", and credits NOTICE | **DONE** | Removed legacy `droidsleuth.py` and renamed `tests/test_hackathon_requirements.py` to `tests/test_advanced_features.py`. Replaced all occurrences of "AScanner" with "AndroMalHut". Added `NOTICE` file documenting licenses and credits for Drebin, AndroZoo, Androguard, XGBoost, ReportLab, Scikit-learn, and Cryptography. |
| **Phase 5** | **22** | Strict input validation for package names and APK paths | **DONE** | Added `PACKAGE_NAME_REGEX` (`\A[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+\Z`), `validate_package_name()`, and `validate_apk_path()` in `modules/device_inventory.py`. Enforced input validation in ADB commands, CLI handlers, and dynamic sandbox. Verified all `subprocess` calls use argument lists with no `shell=True`. Added unit tests in `tests/test_advanced_features.py`. |
| **Phase 5** | **23** | Add `SECURITY.md` | **DONE** | Authored `SECURITY.md` detailing static analysis defaults, dynamic execution guardrails, model deserialization security, input validation guarantees, and responsible disclosure procedures. |

---

## Metrics Status

- **Regenerated Metrics (Fully Reproducible):**
  - Holdout Test Accuracy: **93.39%** (1,639 / 1,755 holdout samples)
  - Balanced Accuracy: **93.38%**
  - Holdout ROC-AUC: **0.9822**
  - False Positive Rate (FPR): **6.57%** ($\frac{58}{58 + 825}$)
  - False Negative Rate (FNR): **6.67%** ($\frac{58}{58 + 814}$)
  - Shared Features Source-Ablation (111 features): **88.72%** Accuracy, **0.9551** ROC-AUC
  - Cross-Dataset Drebin $\to$ AndroZoo: **53.65%** Accuracy, **0.8051** ROC-AUC
  - Cross-Dataset AndroZoo $\to$ Drebin: **72.87%** Accuracy, **0.8232** ROC-AUC
- **Metrics Marked "Pending Re-evaluation" (Removed from claims):**
  - Independent 58-sample benchmark (`android_malware_dataset.csv`, 86.21% claim): Removed because the dataset was not committed to the repository and had no reproducible evaluation script.
