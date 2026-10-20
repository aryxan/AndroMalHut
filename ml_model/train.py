#!/usr/bin/env python3
"""
AScanner Hybrid Android Malware Classifier Training Pipeline
Trains a high-accuracy GPU-accelerated XGBoost classifier on combined multi-source datasets:
1. AndroZoo Real-World Permission Dataset (10,686 APKs, 2013-2016)
2. Drebin Static Feature Benchmark Dataset (15,036 APKs)
Total: 25,722 Android applications (13,246 Malware, 12,476 Benign)
GPU Acceleration: NVIDIA CUDA (hist tree method) with automatic CPU fallback.
"""

import json
import subprocess
from pathlib import Path
import numpy as np
import pandas as pd
from joblib import dump
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, balanced_accuracy_score, roc_auc_score
import xgboost as xgb

BASE_DIR = Path(__file__).resolve().parent
DATASETS_DIR = BASE_DIR.parent.parent

zoo_path = DATASETS_DIR / "AndroZoo" / "Permission_DATASET.csv"
drebin_path = DATASETS_DIR / "Drebin" / "drebin-215.csv"
out_dir = BASE_DIR

print("[*] Loading datasets...")
if not zoo_path.exists():
    raise SystemExit(f"ERROR: AndroZoo dataset not found at {zoo_path}")
if not drebin_path.exists():
    raise SystemExit(f"ERROR: Drebin dataset not found at {drebin_path}")

df_zoo = pd.read_csv(zoo_path)
df_drebin = pd.read_csv(drebin_path, low_memory=False)

print(f"    AndroZoo samples: {len(df_zoo)}")
print(f"    Drebin samples:   {len(df_drebin)}")
print(f"    Total samples:    {len(df_zoo) + len(df_drebin)}")

def canon(name: str) -> str:
    n = name.strip()
    for prefix in ['android.permission.', 'permission.', 'com.android.browser.permission.']:
        if n.startswith(prefix):
            n = n[len(prefix):]
    return n.upper()

zoo_cols = [c for c in df_zoo.columns if c not in ('NAME', 'CLASS')]
drebin_cols = [c for c in df_drebin.columns if c != 'class']

# Remove deceptive IPC features from legacy 2011 Drebin that cause false negatives on modern apps
ipc_features = {'TRANSACT', 'ONSERVICECONNECTED', 'BINDSERVICE', 'ATTACHINTERFACE', 'SERVICECONNECTION', 'ANDROID.OS.BINDER'}

all_canonical = sorted(list(set(canon(c) for c in zoo_cols + drebin_cols if canon(c) not in ipc_features)))
print(f"[*] Canonical feature set size: {len(all_canonical)}")

# Build standardized matrix for AndroZoo (using bitwise OR to preserve multi-column mapped permissions)
X_zoo_dict = {cn: np.zeros(len(df_zoo), dtype=np.int8) for cn in all_canonical}
for c in zoo_cols:
    cn = canon(c)
    if cn in X_zoo_dict:
        X_zoo_dict[cn] = X_zoo_dict[cn] | (df_zoo[c].values == 1).astype(np.int8)
X_zoo = pd.DataFrame(X_zoo_dict)
y_zoo = df_zoo['CLASS'].astype(int)

# Build standardized matrix for Drebin (using bitwise OR)
X_drebin_dict = {cn: np.zeros(len(df_drebin), dtype=np.int8) for cn in all_canonical}
for c in drebin_cols:
    cn = canon(c)
    if cn in X_drebin_dict:
        vals = pd.to_numeric(df_drebin[c], errors='coerce').fillna(0).values
        X_drebin_dict[cn] = X_drebin_dict[cn] | (vals > 0).astype(np.int8)
X_drebin = pd.DataFrame(X_drebin_dict)
y_drebin = df_drebin['class'].astype(str).str.strip().str.upper().map({'S': 1, 'B': 0}).astype(int)

# Concatenate unified datasets
X_all = pd.concat([X_zoo, X_drebin], ignore_index=True)
y_all = pd.concat([y_zoo, y_drebin], ignore_index=True)

# Refined risk features distinguishing true malware patterns from legitimate banking/enterprise capabilities
risk_cols = {
    'RISK_SMS_BOOT': ((X_all.get('SEND_SMS', 0) | X_all.get('READ_SMS', 0) | X_all.get('RECEIVE_SMS', 0)) & X_all.get('RECEIVE_BOOT_COMPLETED', 0)).astype(np.int8),
    'RISK_COVERT_SPYWARE': ((X_all.get('RECORD_AUDIO', 0) | X_all.get('CAMERA', 0)) & X_all.get('READ_CALL_LOG', 0) & (X_all.get('READ_CONTACTS', 0) | X_all.get('READ_SMS', 0))).astype(np.int8),
    'RISK_OVERLAY_ACCESS': (X_all.get('SYSTEM_ALERT_WINDOW', 0) & (X_all.get('BIND_ACCESSIBILITY_SERVICE', 0) | X_all.get('RECEIVE_BOOT_COMPLETED', 0) | X_all.get('REQUEST_INSTALL_PACKAGES', 0))).astype(np.int8),
    'RISK_DEVICE_TAKEOVER': (X_all.get('BIND_DEVICE_ADMIN', 0) | X_all.get('BIND_ACCESSIBILITY_SERVICE', 0)).astype(np.int8)
}
X_all = pd.concat([X_all, pd.DataFrame(risk_cols)], axis=1)
feature_names = list(X_all.columns)

print(f"[*] Total dataset shape: {X_all.shape}")
print(f"    Class distribution: Malware(1)={int(y_all.sum())}, Benign(0)={int((1 - y_all).sum())}")

# Holdout split
X_train, X_test, y_train, y_test = train_test_split(
    X_all, y_all, test_size=0.2, random_state=42, stratify=y_all
)

# Hardware acceleration detection
device = "cpu"
gpu_name = "CPU Only"
try:
    smi = subprocess.run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"], capture_output=True, text=True)
    if smi.returncode == 0 and smi.stdout.strip():
        device = "cuda"
        gpu_name = smi.stdout.strip().splitlines()[0]
except Exception:
    pass

print(f"[*] Hardware Acceleration Device : {device.upper()} ({gpu_name})")
print("[*] Training GPU-Accelerated XGBoost Classifier (300 trees, hist method)...")

model = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.08,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric='logloss',
    device=device,
    tree_method='hist',
    random_state=42
)
model.fit(X_train, y_train)

pred = model.predict(X_test)
proba = model.predict_proba(X_test)[:, 1]

acc = float(accuracy_score(y_test, pred))
b_acc = float(balanced_accuracy_score(y_test, pred))
auc_roc = float(roc_auc_score(y_test, proba))
cm = confusion_matrix(y_test, pred).tolist()
report = classification_report(y_test, pred, target_names=["Benign", "Malware"], output_dict=True, zero_division=0)

print(f"\n[+] Holdout Evaluation Results:")
print(f"    Hardware Engine:   {gpu_name}")
print(f"    Accuracy:          {acc:.4f} ({acc*100:.2f}%)")
print(f"    Balanced Accuracy: {b_acc:.4f} ({b_acc*100:.2f}%)")
print(f"    ROC-AUC Score:     {auc_roc:.4f}")
print(f"    Confusion Matrix:  {cm}")
print("\n" + classification_report(y_test, pred, target_names=["Benign", "Malware"], zero_division=0))

metrics = {
    "datasets": [str(zoo_path), str(drebin_path)],
    "total_samples": int(len(X_all)),
    "malware_samples": int(y_all.sum()),
    "benign_samples": int((1 - y_all).sum()),
    "features_count": int(len(feature_names)),
    "accuracy": acc,
    "balanced_accuracy": b_acc,
    "roc_auc": auc_roc,
    "confusion_matrix": cm,
    "classification_report": report,
    "feature_names": feature_names,
    "hardware_acceleration": {
        "device": device,
        "gpu_model": gpu_name
    }
}

out_model_path = out_dir / "drebin_rf.joblib"
dump({
    "model": model,
    "features": feature_names,
    "canonical_features": all_canonical,
    "metrics": metrics,
    "engine": f"XGBoost-{device.upper()}",
    "gpu_model": gpu_name
}, out_model_path)

(out_dir / "evaluation.json").write_text(json.dumps(metrics, indent=2))
(out_dir / "evaluation.txt").write_text(
    f"AScanner Multi-Source Android Malware Classifier Evaluation\n"
    f"==========================================================\n"
    f"Datasets: AndroZoo (10,686) + Drebin (15,036) -> Total {len(X_all)} samples\n"
    f"Engine: XGBoost on {gpu_name} ({device.upper()})\n"
    f"Features: {len(feature_names)}\n"
    f"Accuracy: {acc:.4f}\n"
    f"Balanced Accuracy: {b_acc:.4f}\n"
    f"ROC-AUC: {auc_roc:.4f}\n\n"
    f"Confusion Matrix (Actual Rows, Predicted Cols):\n"
    f"  [Benign:  {cm[0][0]:5d} | False Pos: {cm[0][1]:5d}]\n"
    f"  [False Neg:{cm[1][0]:5d} | Malware:   {cm[1][1]:5d}]\n\n"
    + classification_report(y_test, pred, target_names=["Benign", "Malware"], zero_division=0)
)

print(f"[+] Model saved to: {out_model_path}")
print(f"[+] Evaluation saved to: {out_dir / 'evaluation.json'}")
print("[+] Training completed successfully.")
