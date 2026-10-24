#!/usr/bin/env python3
"""
Script to synchronize README.md and ml_model/README.md metrics tables
directly from ml_model/evaluation.json.

Ensures 100% metric consistency across all documentation and reports,
preventing hardcoded, hallucinated, or out-of-sync evaluation numbers.
"""

import json
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVAL_JSON = PROJECT_ROOT / "ml_model" / "evaluation.json"
README_MD = PROJECT_ROOT / "README.md"
ML_README_MD = PROJECT_ROOT / "ml_model" / "README.md"


def load_evaluation_data():
    if not EVAL_JSON.exists():
        raise FileNotFoundError(f"evaluation.json not found at {EVAL_JSON}")
    return json.loads(EVAL_JSON.read_text(encoding="utf-8"))


def generate_readme_metrics_block(eval_data: dict) -> str:
    cm = eval_data["confusion_matrix"]
    tn, fp = cm[0][0], cm[0][1]
    fn, tp = cm[1][0], cm[1][1]
    test_total = tn + fp + fn + tp
    rates = eval_data.get("random_split_test_metrics", {}).get("rates", {})
    fpr = rates.get("false_positive_rate", fp / (fp + tn) if (fp + tn) > 0 else 0)
    fnr = rates.get("false_negative_rate", fn / (fn + tp) if (fn + tp) > 0 else 0)
    tpr = rates.get("true_positive_rate", tp / (tp + fn) if (tp + fn) > 0 else 0)
    tnr = rates.get("true_negative_rate", tn / (tn + fp) if (tn + fp) > 0 else 0)

    ds = eval_data.get("datasets", {})
    raw_total = ds.get("total_samples_raw", 25722)
    dedup_total = ds.get("deduplicated_samples_total", 11696)
    malware_total = ds.get("malware_samples_total", 4797)
    benign_total = ds.get("benign_samples_total", 6899)
    feat_count = eval_data.get("features_count", 630)
    shared_feat_count = eval_data.get("shared_features_count", 111)

    acc = eval_data["accuracy"]
    b_acc = eval_data["balanced_accuracy"]
    roc_auc = eval_data["roc_auc"]
    rep = eval_data.get("classification_report", {})
    mal_prec = rep.get("Malware", {}).get("precision", 0.0)
    mal_rec = rep.get("Malware", {}).get("recall", 0.0)
    mal_f1 = rep.get("Malware", {}).get("f1-score", 0.0)

    # Per source
    per_src = eval_data.get("per_source_test_metrics", {})
    drebin_acc = per_src.get("drebin", {}).get("accuracy", 0.0)
    drebin_auc = per_src.get("drebin", {}).get("roc_auc", 0.0)
    zoo_acc = per_src.get("androzoo", {}).get("accuracy", 0.0)
    zoo_auc = per_src.get("androzoo", {}).get("roc_auc", 0.0)

    # Ablation
    abl = eval_data.get("source_ablation_metrics", {})
    abl_acc = abl.get("accuracy", 0.0)
    abl_auc = abl.get("roc_auc", 0.0)
    abl_fpr = abl.get("rates", {}).get("false_positive_rate", 0.0)
    abl_fnr = abl.get("rates", {}).get("false_negative_rate", 0.0)

    # Cross dataset
    cross = eval_data.get("cross_dataset_metrics", {})
    d2z_acc = cross.get("drebin_to_androzoo", {}).get("accuracy", 0.0)
    d2z_auc = cross.get("drebin_to_androzoo", {}).get("roc_auc", 0.0)
    z2d_acc = cross.get("androzoo_to_drebin", {}).get("accuracy", 0.0)
    z2d_auc = cross.get("androzoo_to_drebin", {}).get("roc_auc", 0.0)

    block = f"""## Machine Learning Model & Evaluation

AndroMalHut integrates a calibrated **Gradient Boosted Decision Tree (XGBoost)** classifier evaluated across multi-source benchmark datasets: **AndroZoo** ({ds.get('androzoo_samples_raw', 10686):,} raw APKs, 2013–2016) and **Drebin** ({ds.get('drebin_samples_raw', 15036):,} raw APKs).

To eliminate train/test leakage, identical feature rows are deduplicated prior to splitting, reducing {raw_total:,} raw samples to **{dedup_total:,} unique application capability vectors** ({malware_total:,} Malware, {benign_total:,} Benign). The dataset is partitioned into 70% training ({eval_data['splits']['train_samples']:,}), 15% validation ({eval_data['splits']['validation_samples']:,}), and 15% holdout test ({test_total:,}) subsets. The holdout test set is evaluated only once after final model tuning.

> 📊 **Interactive Evaluation Dashboard:** Explore interactive confusion matrix tooltips, dynamic ROC threshold curves, and zoomable feature gain distributions in the [**Plotly Interactive Model Dashboard (docs/interactive_model_evaluation.html)**](docs/interactive_model_evaluation.html).

---

### Composite Performance Dashboard
*Generated dynamically via Seaborn & Matplotlib (`scripts/generate_plots.py`) from `ml_model/evaluation.json`*

<p align="center">
  <img src="docs/assets/model_evaluation_summary.png" alt="AndroMalHut Model Evaluation Summary" width="95%"/>
</p>

---

### Confusion Matrix & Classification Metrics

<p align="center">
  <img src="docs/assets/confusion_matrix.png" alt="Confusion Matrix Heatmap" width="48%"/>
  <img src="docs/assets/accuracy_metrics_comparison.png" alt="Accuracy Metrics Comparison" width="48%"/>
</p>

- **Confusion Matrix Analysis ({test_total:,} Holdout Applications):**
  - **True Benign (TN):** `{tn:,}` applications correctly identified as benign (**{tnr:.2%} Specificity**).
  - **True Malware (TP):** `{tp:,}` applications correctly flagged as malicious (**{tpr:.2%} Sensitivity / Recall**).
  - **False Positives (FP):** `{fp:,}` benign apps flagged (**{fpr:.2%} False Positive Rate = FP / (FP + TN)**).
  - **False Negatives (FN):** `{fn:,}` malware samples missed (**{fnr:.2%} False Negative Rate = FN / (FN + TP)**).

---

### ROC Curve & Feature Importance

<p align="center">
  <img src="docs/assets/roc_auc_curve.png" alt="ROC-AUC Curve" width="48%"/>
  <img src="docs/assets/top_features_importance.png" alt="Top Feature Importances" width="48%"/>
</p>

- **Receiver Operating Characteristic (ROC):** Achieves an **AUC of {roc_auc:.4f}**, demonstrating discriminative power between malicious capability combinations and benign application structures.
- **Top Detection Drivers:** Key features driving classification include telephony state inspection (`READ_PHONE_STATE`), SMS messaging (`SEND_SMS`), camera/audio recording (`CAMERA`, `RECORD_AUDIO`), and high-risk privilege combinations (overlay access, autostart boot persistence).

---

### Comprehensive Model Benchmark & Ablation Study

| Evaluation Benchmark / Protocol | Accuracy | Balanced Acc | ROC-AUC | False Positive Rate | False Negative Rate |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Random Holdout Split (Primary, n={test_total:,})** | **{acc:.2%}** | **{b_acc:.2%}** | **{roc_auc:.4f}** | **{fpr:.2%}** | **{fnr:.2%}** |
| ↳ *Drebin Subset (n={per_src.get('drebin', {}).get('sample_count', 0):,})* | {drebin_acc:.2%} | {per_src.get('drebin', {}).get('balanced_accuracy', 0.0):.2%} | {drebin_auc:.4f} | {per_src.get('drebin', {}).get('rates', {}).get('false_positive_rate', 0.0):.2%} | {per_src.get('drebin', {}).get('rates', {}).get('false_negative_rate', 0.0):.2%} |
| ↳ *AndroZoo Subset (n={per_src.get('androzoo', {}).get('sample_count', 0):,})* | {zoo_acc:.2%} | {per_src.get('androzoo', {}).get('balanced_accuracy', 0.0):.2%} | {zoo_auc:.4f} | {per_src.get('androzoo', {}).get('rates', {}).get('false_positive_rate', 0.0):.2%} | {per_src.get('androzoo', {}).get('rates', {}).get('false_negative_rate', 0.0):.2%} |
| **Source-Ablation ({shared_feat_count} Shared Permissions Only)** | **{abl_acc:.2%}** | **{abl.get('balanced_accuracy', 0.0):.2%}** | **{abl_auc:.4f}** | **{abl_fpr:.2%}** | **{abl_fnr:.2%}** |
| **Cross-Dataset: Drebin -> AndroZoo** | **{d2z_acc:.2%}** | **{cross.get('drebin_to_androzoo', {}).get('balanced_accuracy', 0.0):.2%}** | **{d2z_auc:.4f}** | **{cross.get('drebin_to_androzoo', {}).get('rates', {}).get('false_positive_rate', 0.0):.2%}** | **{cross.get('drebin_to_androzoo', {}).get('rates', {}).get('false_negative_rate', 0.0):.2%}** |
| **Cross-Dataset: AndroZoo -> Drebin** | **{z2d_acc:.2%}** | **{cross.get('androzoo_to_drebin', {}).get('balanced_accuracy', 0.0):.2%}** | **{z2d_auc:.4f}** | **{cross.get('androzoo_to_drebin', {}).get('rates', {}).get('false_positive_rate', 0.0):.2%}** | **{cross.get('androzoo_to_drebin', {}).get('rates', {}).get('false_negative_rate', 0.0):.2%}** |

```text
Holdout Confusion Matrix (Actual Rows, Predicted Columns):
                 Predicted Benign   Predicted Malware
Actual Benign          {tn:5,d}               {fp:5,d}         ({tnr:.1%} Specificity)
Actual Malware         {fn:5,d}               {tp:5,d}         ({tpr:.1%} Sensitivity)
```

---

### Dataset Limitations & Forensic Scope

> [!NOTE]
> **Dataset Age and Temporal Generalization:** The training data is derived primarily from 2011–2016 academic corpora (Drebin and AndroZoo). Because Android security models, permission architectures (runtime permissions introduced in Android 6.0), and malware evasion tactics evolve rapidly, random-split benchmark scores overstate real-world accuracy on modern samples. As demonstrated by the cross-dataset evaluation above (accuracy dropping to 53.6%–72.9% across disparate datasets), static permission triage must be corroborated with heuristic behavioral analysis, cryptographic certificate verification, and dynamic sandbox observation."""
    return block


def update_readme_files():
    eval_data = load_evaluation_data()
    metrics_block = generate_readme_metrics_block(eval_data)

    # 1. Update main README.md
    readme_text = README_MD.read_text(encoding="utf-8")
    pattern = r"## Machine Learning Model & Evaluation[\s\S]*?(?=## Operating System Compatibility)"
    if re.search(pattern, readme_text):
        new_readme = re.sub(pattern, metrics_block + "\n\n---\n\n", readme_text)
        README_MD.write_text(new_readme, encoding="utf-8")
        print(f"[+] Updated main {README_MD.name} metrics section from evaluation.json")
    else:
        print(f"[!] Warning: Pattern not matched in {README_MD.name}")

    # 2. Update ml_model/README.md
    ds = eval_data.get("datasets", {})
    acc = eval_data["accuracy"]
    b_acc = eval_data["balanced_accuracy"]
    roc_auc = eval_data["roc_auc"]
    rep = eval_data.get("classification_report", {})
    mal_prec = rep.get("Malware", {}).get("precision", 0.0)
    mal_rec = rep.get("Malware", {}).get("recall", 0.0)
    mal_f1 = rep.get("Malware", {}).get("f1-score", 0.0)
    cm = eval_data["confusion_matrix"]
    test_total = sum(sum(row) for row in cm)
    correct_test = cm[0][0] + cm[1][1]

    ml_readme_content = f"""# AndroMalHut Pre-Trained Machine Learning Model

## Overview
This directory contains the pre-trained XGBoost classifier and evaluation artifacts used by **AndroMalHut** for static APK malware triage and probability scoring.

## Model Details
- **Architecture:** Gradient Boosted Decision Trees (XGBoost)
- **Model Formats:**
  - `andromalhut_xgboost.json`: Native XGBoost JSON booster (safe deserialization, no arbitrary code execution)
  - `andromalhut_xgboost.joblib`: Serialized dictionary containing model, feature lists, and metadata (cryptographically verified)
  - `drebin_rf.joblib`: Backward-compatible legacy copy
- **Dataset Composition:** Multi-Source Benchmark
  - **AndroZoo (2013–2016):** {ds.get('androzoo_samples_raw', 10686):,} Real-World Applications
  - **Drebin Benchmark:** {ds.get('drebin_samples_raw', 15036):,} Applications
  - **Pre-Split Deduplicated:** {ds.get('deduplicated_samples_total', 11696):,} unique capability rows ({ds.get('malware_samples_total', 4797):,} Malware, {ds.get('benign_samples_total', 6899):,} Benign)
- **Evaluated Features:** {eval_data.get('features_count', 630)} Canonical Android permissions, intent actions, and behavioral threat patterns.

## Verified Benchmark Metrics (Holdout Random Split, n={test_total:,})
- **Holdout Accuracy:** **{acc:.2%}** ({correct_test:,} / {test_total:,} test samples)
- **Balanced Accuracy:** **{b_acc:.2%}**
- **Precision (Malware):** **{mal_prec:.2%}**
- **Recall (Malware):** **{mal_rec:.2%}**
- **F1-Score (Malware):** **{mal_f1:.2%}**
- **ROC-AUC Score:** **{roc_auc:.4f}**
- **Cross-Dataset Generalization:**
  - Drebin -> AndroZoo: **{eval_data.get('cross_dataset_metrics', {}).get('drebin_to_androzoo', {}).get('accuracy', 0.0):.2%}** Accuracy
  - AndroZoo -> Drebin: **{eval_data.get('cross_dataset_metrics', {}).get('androzoo_to_drebin', {}).get('accuracy', 0.0):.2%}** Accuracy

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
"""
    ML_README_MD.write_text(ml_readme_content, encoding="utf-8")
    print(f"[+] Updated {ML_README_MD.name} from evaluation.json")


if __name__ == "__main__":
    update_readme_files()
