# ML-NIDS-or-Network-Intrusion-Detection
A machine learning-based real-time network intrusion detection system.

Training → Done in Kaggle, produces .pkl model files
GitHub → Contains scripts + trained models so anyone can run your IDS locally
Dataset → CIC-IDS2017 CSV 

## Features
- Real-time network packet capture using Scapy
- Multi-class attack detection (DDoS, PortScan, Web Attack, Infiltration)
- Uses a trained Random Forest ML model
- Alert system prints `[ALERT] Flow → AttackType`
- This is offline trained model — it’s already “ready to use”.
- 
## Repository Structure
/NIDS/capture.py              → Main script to capture and classify flows
/NIDS/feature_extractor.py    → Extracts 25 network features from flows
/NIDS/predictor.py            → Loads ML model and predicts flow type
/NIDS/model/                  → Contains trained ML models and encoders
    - nids_model_top25.pkl
    - top25_features.pkl
    - label_encoder.pkl

## Requirements
- Python 3.10+
- scapy
- pandas
- numpy
- scikit-learn
- joblib

## How to Run
1. Clone this repository
2. Install requirements
3. Run the NIDS:
   python capture.py
4. Watch the terminal for real-time alerts:
   [ALERT] Flow → BENIGN / DDoS / PortScan / Web Attack / Infiltration
