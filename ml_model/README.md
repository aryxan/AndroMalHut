# AndroMalHut Pre-Trained Machine Learning Model

## Overview
This directory contains the pre-trained, GPU-accelerated XGBoost classifier and evaluation artifacts used by **AndroMalHut** for static APK malware triage and probability scoring.

## Model Details
- **Architecture:** GPU-Accelerated Gradient Boosted Decision Trees (XGBoost 3.4.x)
- **Execution Acceleration:** NVIDIA CUDA (`device='cuda'`, `tree_method='hist'`) with automatic CPU fallback
- **Dataset Composition:** 25,722 Multi-Source Applications
  - **AndroZoo (2013–2016):** 10,686 Real-World Applications
  - **Drebin Static Benchmark:** 15,036 Applications
- **Target Distribution:** 13,246 Malware, 12,476 Benign
- **Evaluated Features:** 630 Canonical Android permissions, intent filters, sensitive APIs, and interaction threat patterns.

## Verified Benchmark Metrics
- **Holdout Accuracy:** **93.92%** (4,832 / 5,145 test samples)
- **Balanced Accuracy:** **93.94%**
- **Precision (Malware):** **94.86%**
- **Recall (Malware):** **93.25%**
- **F1-Score (Malware):** **94.05%**
- **ROC-AUC Score:** **0.9861**
- **Independent Benchmark (`android_malware_dataset.csv`):** **86.21% Accuracy**

## Files
- `drebin_rf.joblib`: Pre-trained, serialized model dictionary containing model booster, canonical feature names, and metadata.
- `scan_apk.py`: Static feature extractor and inference engine.
- `train.py`: Full training pipeline script supporting NVIDIA CUDA GPU training.
- `evaluation.json`: Machine-readable holdout confusion matrix, classification report, and metric scores.
- `evaluation.txt`: Human-readable evaluation summary.

## Retraining the Model
To retrain the model on your local system with CUDA GPU acceleration:
```bash
python3 ml_model/train.py
```
If an NVIDIA GPU with CUDA drivers is detected, training automatically utilizes GPU hardware; otherwise, it falls back to multi-threaded CPU execution.
