# AI-Based Network Intrusion Detection System

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109.0-009688.svg)](https://fastapi.tiangolo.com/)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.0.3-orange.svg)](https://xgboost.readthedocs.io/)
[![Accuracy](https://img.shields.io/badge/Accuracy-99.89%25-brightgreen.svg)]()

A machine learning system for detecting and classifying network intrusions in real time using the **CIC-IDS2017** benchmark dataset, 78 extracted traffic features, **StandardScaler** preprocessing, and a trained **XGBoost** classifier.

---

## 1. Project Title

**AI-Based Network Intrusion Detection System**

- **Repository**: `ai-network-intrusion-detection`
- **Architecture**: Decoupled FastAPI Backend REST Service + Frontend ML Security Analysis Console

---

## 2. Problem

Network intrusion refers to unauthorized or malicious activities (such as Denial of Service attacks, port scans, brute-force attempts, or botnet activity) occurring across computer networks.

Manually identifying malicious network traffic flows is difficult because:

- **Enormous Volume**: Modern enterprise networks generate millions of packet transactions per second.
- **High Complexity**: Malicious packets are often disguised within legitimate HTTP, HTTPS, or DNS traffic.
- **Human Inspection Latency**: Manual log analysis is slow, while cyber threats require detection and mitigation in milliseconds.

---

## 3. Solution

Our system automates network threat detection using Machine Learning. Real network-traffic records from the **CIC-IDS2017** dataset are processed into 78 statistical traffic features (such as flow duration, packet sizes, inter-arrival times, and TCP flags). These numerical features undergo standard scaling and are passed through a trained **XGBoost** machine-learning model to classify the traffic as **BENIGN** or a specific **ATTACK** category.

---

## 4. How Our System Works

The end-to-end logic follows this exact sequential pipeline:

```text
CIC-IDS2017 Dataset
        ↓
Real Network Traffic Record
        ↓
78 Traffic Features
        ↓
Preprocessing (StandardScaler + Median Imputation)
        ↓
Trained XGBoost Model
        ↓
Prediction (Class & Probabilities)
        ↓
Compare with Actual Dataset Label (Match / Misclassification)
```

---

## 5. Dataset

The system is trained and evaluated on the **CIC-IDS2017** benchmark dataset provided by the Canadian Institute for Cybersecurity.

- **Representation of One Row**: Each dataset row represents a single bidirectional network flow summarized by statistical traffic metrics over a capture window.
- **Total Flows**: 2,830,743 network traffic records across 8 capture files.
- **Verified Feature Count**: Exactly **78 numerical features** per traffic record.
- **Attack Categories**: 15 target classes (1 `BENIGN` class + 14 attack types including `DDoS`, `PortScan`, `Bot`, `DoS Hulk`, `DoS GoldenEye`, `DoS Slowhttptest`, `DoS slowloris`, `FTP-Patator`, `SSH-Patator`, `Heartbleed`, `Infiltration`, `Web Attack - Brute Force`, `Web Attack - Sql Injection`, `Web Attack - XSS`).

---

## 6. Machine Learning Model

- **Primary Classifier**: Extreme Gradient Boosting (`XGBClassifier`) loaded from `models/best_comparison_model.pkl`.
- **Model Loader**: Singleton service (`api/model_service.py`) keeping pre-warmed model and scaler objects in memory for fast inference (<1ms).
- **Preprocessing**: `SimpleImputer(strategy="median")` for missing values and `StandardScaler` for zero-mean unit-variance normalization.

---

## 7. Live Prediction Workflow

1. **Record Selection**: The user selects a real test record from `dataset/real_test_samples.json` (e.g. `ddos_1`, `benign_1`, `portscan_1`).
2. **Feature Extraction**: The record's 78 numerical feature values are rendered for visual inspection.
3. **API Request**: The frontend issues a `POST /predict` HTTP request containing the 78 features.
4. **FastAPI Processing**: Backend applies the saved `StandardScaler` transformer and passes normalized features to XGBoost.
5. **Prediction & Probabilities**: XGBoost computes class probabilities and returns the predicted label alongside confidence metrics.
6. **Ground-Truth Comparison**: The dashboard compares the model's prediction against the record's ground-truth label and displays automated verification (`✓ MATCH — CORRECTLY DETECTED` or `⚠ MISCLASSIFIED`).

---

## 8. Backend API Endpoints

Implemented using **FastAPI** in `api/main.py`:

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `GET /health` | `GET` | Server health status, model loading state, and schema length |
| `GET /model-info` | `GET` | Model metadata, feature list, 15 class names, and evaluation metrics |
| `GET /dataset/samples` | `GET` | Lists available pre-extracted test dataset categories |
| `GET /dataset/sample/{key}` | `GET` | Fetches a specific test sample with ground truth & 78 features |
| `POST /predict` | `POST` | Accepts JSON with 78 features, runs XGBoost, returns prediction & confidence |

---

## 9. Frontend

The web interface is located in the `app/` directory (`index.html`, `app.js`, `style.css`):

- **Visual Dashboard**: Displays project context, problem statement, feature breakdown, model comparison charts, and live inference console.
- **Interactive Inspector**: Allows step-by-step record cycling (`[ PREVIOUS RECORD ]` / `[ NEXT RECORD ]`), full 78 feature accordion view, live pipeline animation, and ground-truth verification cards.

---

## 10. Results & Verified Performance

Evaluated on 504,473 held-out test samples from the CIC-IDS2017 test split:

- **Test Accuracy**: **99.89%** (`0.998866`)
- **Weighted F1-Score**: **99.88%** (`0.998828`)
- **Weighted Precision**: **99.88%** (`0.998829`)
- **Weighted Recall**: **99.89%** (`0.998866`)
- **Macro F1-Score**: **91.70%** (`0.916957`)
- **ROC-AUC Score**: **99.98%** (`0.999840`)

### Benchmark Model Comparison

| Model | Test Accuracy (%) |
| :--- | :--- |
| **XGBoost (Selected)** | **99.89%** |
| Random Forest | 99.84% |
| Decision Tree | 99.82% |
| Gradient Boosting | 99.19% |
| Logistic Regression | 97.81% |

---

## 11. Project Structure

```text
ai-network-intrusion-detection/
├── api/
│   ├── main.py                # FastAPI server entry point & static file routing
│   ├── model_service.py       # Singleton loader for XGBoost model bundle
│   ├── preprocessing.py       # Data validation & StandardScaler pipeline
│   ├── schemas.py             # Pydantic input/output validation models
│   ├── data_loader.py         # Real dataset sample fetcher
│   └── test_api.py            # Pytest unit test suite (8 test cases)
├── app/
│   ├── index.html             # Security Analysis Console interface
│   ├── style.css              # Cyber NOC design system & responsive styling
│   └── app.js                 # Dashboard logic & REST fetch interactions
├── dataset/
│   └── real_test_samples.json # Real pre-extracted CIC-IDS2017 test records
├── models/
│   ├── best_comparison_model.pkl # Trained XGBoost model & scaler bundle
│   ├── train_models.py        # Model training script
│   └── evaluate_model.py     # Evaluation & metrics generation script
├── notebooks/                 # Exploratory data analysis & feature selection
├── results/                   # Evaluation metrics & model comparison outputs
└── README.md                  # Project documentation
```

---

## 12. How to Run

### Step 1: Install Dependencies

```bash
pip install fastapi uvicorn xgboost scikit-learn pydantic numpy pandas pytest requests
```

### Step 2: Run Backend Unit Tests

```bash
python3 -m pytest api/test_api.py
```

### Step 3: Start FastAPI Server

```bash
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### Step 4: Open Dashboard & API Docs

- **Security Console Dashboard**: [http://localhost:8000/dashboard/](http://localhost:8000/dashboard/)
- **FastAPI Interactive Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

---

## 13. Demo Flow

When demonstrating this project to a faculty member or evaluator:

> *"Here is a real dataset record from CIC-IDS2017.*
> *These are its 78 numerical traffic features.*
> *We send those features through the same StandardScaler preprocessing used during training.*
> *The trained XGBoost model predicts the traffic class.*
> *Finally, we compare the prediction with the actual ground-truth label stored in the dataset to verify accuracy."*
