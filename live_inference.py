import pandas as pd
import joblib
import os
import defense
from plyer import notification
import shap
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

# Load the Brain and the Translators
print("Loading ML Model and Encoders...")
try:
    model = joblib.load('rf_ids_model.pkl')
    le_protocol = joblib.load('le_protocol.pkl')
    le_service = joblib.load('le_service.pkl')
    le_flag = joblib.load('le_flag.pkl')
    le_label = joblib.load('le_label.pkl')
except Exception as e:
    print(f"Error loading models: {e}. Did you download the .pkl files?")

def safe_encode(encoder, value, fallback_class=0):
    """Safely encodes live data, handling unknown new services/flags."""
    try:
        return encoder.transform([value])[0]
    except ValueError:
        return fallback_class # Default to the first known class if unknown

def evaluate_traffic(csv_path="outputs/live_features.csv"):
    if not os.path.exists(csv_path): return
    try:
        df = pd.read_csv(csv_path)
        os.remove(csv_path)
    except Exception as e:
        return 

    if df.empty: return

    attacker_ips = df['_src_ip_'].copy()
    X_live = df.drop(columns=['_src_ip_'])

    # Translate the text back into the numbers the ML model expects
    X_live['protocol_type'] = X_live['protocol_type'].apply(lambda x: safe_encode(le_protocol, x))
    X_live['service'] = X_live['service'].apply(lambda x: safe_encode(le_service, x))
    X_live['flag'] = X_live['flag'].apply(lambda x: safe_encode(le_flag, x))

    # Ask the ML Model for predictions!
    predictions = model.predict(X_live)
    predicted_labels = le_label.inverse_transform(predictions)
    attack_indices = [i for i, label in enumerate(predicted_labels) if label.lower() != 'normal']

    if attack_indices:
        # 1. Translate the ML prediction back to a readable string (e.g., "neptune")
        try:
            attack_labels = le_label.inverse_transform(predictions[attack_indices])
            attack_name = attack_labels[0].upper() # Grab the first detected attack's name
            df_anomalies = X_live.iloc[attack_indices].copy()
            df_anomalies['Attack_Type'] = attack_labels
        except:
            attack_name = "UNKNOWN ANOMALY"
            df_anomalies = X_live.iloc[attack_indices].copy()
            df_anomalies['Attack_Type'] = "Unknown Attack"

        # 2. Trigger the Windows Desktop Notification
        alert_msg = f"XAI-IDS detected a {attack_name} Attack!"
        print(f"ALERT {alert_msg}")
        
        try:
            notification.notify(
                title=' XAI-IDS SECURITY ALERT',
                message=alert_msg,
                app_name='XAI-IDS',
                timeout=5
            )
        except Exception as e:
            print(f"[UI] Could not send desktop notification: {e}")

        top_shap_reason = generate_shap_explanation(model, X_live, attack_indices[0])
        
        # 2. Add it to the dataframe
        df_anomalies = X_live.iloc[attack_indices].copy()
        df_anomalies['Attack_Type'] = predicted_labels[attack_indices]
        df_anomalies['_src_ip_'] = attacker_ips.iloc[attack_indices]
        df_anomalies['SHAP_Reason'] = top_shap_reason 
        
        # 3. SAVE TO CSV LAST!
        df_anomalies.to_csv('outputs/alerts.csv', index=False)
        
        # 4. Combat Step: Block the IPs
        unique_attackers = attacker_ips.iloc[attack_indices].unique()
        for ip in unique_attackers:
            if ip != "192.168.56.1": 
                defense.block_ip(ip)
        # 5. Generate the SHAP Graph
        generate_shap_explanation(model, X_live, attack_indices[0])
    else:
        if os.path.exists('outputs/alerts.csv'):
            os.remove('outputs/alerts.csv')

import numpy as np

def generate_shap_explanation(model, X_live, attack_index):
    print("[XAI] Generating SHAP Explanation for the blocked packet...")
    try:
        malicious_packet = X_live.iloc[[attack_index]]
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(malicious_packet)
        
        values_to_analyze = shap_values[1] if isinstance(shap_values, list) else shap_values

        feature_names = X_live.columns
        
        flat_values = np.array(values_to_analyze[0]).flatten()
        
        # Find the index of the highest absolute SHAP value
        top_feature_idx = int(np.argmax(np.abs(flat_values))) 
        top_feature = feature_names[top_feature_idx]
        
        # FIX: Convert it to a standard Python float!
        top_value = float(flat_values[top_feature_idx])
        
        # Format it nicely, e.g., "count (+0.450)"
        shap_text = f"{top_feature} ({top_value:+.3f})"

        # Save the plot
        import matplotlib.pyplot as plt
        import matplotlib
        matplotlib.use('Agg')
        plt.figure(figsize=(8, 4))
        shap.summary_plot(values_to_analyze, malicious_packet, plot_type="bar", show=False)
        plt.savefig('outputs/shap_alert.png', bbox_inches='tight')
        plt.close()
        print("[XAI] SHAP plot saved successfully.")
        
        return shap_text 
        
    except Exception as e:
        print(f"[XAI] Failed to generate SHAP: {e}")
        return "N/A"