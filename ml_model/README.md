# AndroMalHut Pre-Trained Machine Learning Model

## Overview
This directory contains the pre-trained XGBoost classifier and evaluation artifacts used by **AndroMalHut** for static APK malware triage and probability scoring.

## Model Details
- **Architecture:** Gradient Boosted Decision Trees (XGBoost)
- **Model Formats:**
  - `andromalhut_xgboost.json`: Native XGBoost JSON booster (safe deserialization, no arbitrary code execution)
  - `andromalhut_xgboost.joblib`: Serialized dictionary containing model, feature lists, and metadata (cryptographically verified)
  - `drebin_rf.joblib`: Backward-compatible legacy copy
- **Dataset Composition:** Multi-Source Benchmark
  - **AndroZoo (2013–2016):** 10,686 Real-World Applications
  - **Drebin Benchmark:** 15,036 Applications
  - **Pre-Split Deduplicated:** 11,696 unique capability rows (4,797 Malware, 6,899 Benign)
- **Evaluated Features:** 634 Canonical Android permissions, intent actions, and behavioral threat patterns.

## Verified Benchmark Metrics (Holdout Random Split, n=1,755)
- **Holdout Accuracy:** **93.39%** (1,639 / 1,755 test samples)
- **Balanced Accuracy:** **93.38%**
- **Precision (Malware):** **90.81%**
- **Recall (Malware):** **93.33%**
- **F1-Score (Malware):** **92.05%**
- **ROC-AUC Score:** **0.9822**
- **Cross-Dataset Generalization:**
  - Drebin -> AndroZoo: **53.65%** Accuracy
  - AndroZoo -> Drebin: **72.87%** Accuracy

## Dataset Limitations
- The underlying datasets stem from 2011 to 2016; runtime permissions (API 23+) and modern obfuscation techniques are not represented in legacy samples.
- Random-split accuracy overstates real-world efficacy due to distribution overlaps. Cross-dataset metrics show realistic bounds when encountering completely unseen distribution sources.

## Dataset Download Instructions
To reproduce the training pipeline from raw sources:
1. **AndroZoo Permission Dataset:** Download `Permission_DATASET.csv` from the official AndroZoo repository or academic mirror.
2. **Drebin Dataset:** Download `drebin-215.csv` from the official Drebin benchmark repository (Arp et al., NDSS 2014).
3. Place files in `~/Android-Forensics/Datasets/` or pass them explicitly:
   ```bash
   python3 ml_model/train.py --zoo-csv /path/to/Permission_DATASET.csv --drebin-csv /path/to/drebin-215.csv
   ```
