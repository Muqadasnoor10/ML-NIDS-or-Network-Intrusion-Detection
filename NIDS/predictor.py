import joblib
import pandas as pd

model = joblib.load("model/nids_model_top25.pkl")
features_needed = joblib.load("model/top25_features.pkl")
le = joblib.load("model/label_encoder.pkl")


def predict_flow(feature_dict):
    df = pd.DataFrame([feature_dict])

    # Add missing features as 0
    for f in features_needed:
        if f not in df.columns:
            df[f] = 0

    df = df[features_needed]

    pred = model.predict(df)[0]
    label = le.inverse_transform([pred])[0]
    return label
