import pandas as pd
import numpy as np
import joblib
import os
import defense
from plyer import notification
import shap
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

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
        return fallback_class 

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

    X_live['protocol_type'] = X_live['protocol_type'].apply(lambda x: safe_encode(le_protocol, x))
    X_live['service'] = X_live['service'].apply(lambda x: safe_encode(le_service, x))
    X_live['flag'] = X_live['flag'].apply(lambda x: safe_encode(le_flag, x))

    predictions = model.predict(X_live)
    predicted_labels = le_label.inverse_transform(predictions)
    attack_indices = [i for i, label in enumerate(predicted_labels) if label.lower() != 'normal']

    if attack_indices:
        try:
            attack_labels = le_label.inverse_transform(predictions[attack_indices])
            attack_name = attack_labels[0].upper() 
            df_anomalies = X_live.iloc[attack_indices].copy()
            df_anomalies['Attack_Type'] = attack_labels
        except:
            attack_name = "UNKNOWN ANOMALY"
            df_anomalies = X_live.iloc[attack_indices].copy()
            df_anomalies['Attack_Type'] = "Unknown Attack"

        alert_msg = f"XAI-IDS detected a {attack_name} Attack!"
        print(f"ALERT: {alert_msg}")
        
        try:
            notification.notify(
                title=' XAI-IDS SECURITY ALERT',
                message=alert_msg,
                app_name='XAI-IDS',
                timeout=5
            )
        except Exception as e:
            print(f"[UI] Could not send desktop notification: {e}")

        # 1. Generate the explanation FIRST
        top_shap_reason = generate_shap_explanation(model, X_live, attack_indices[0])
        
        # 2. Append to CSV
        df_anomalies = X_live.iloc[attack_indices].copy()
        df_anomalies['Attack_Type'] = predicted_labels[attack_indices]
        df_anomalies['_src_ip_'] = attacker_ips.iloc[attack_indices]
        df_anomalies['SHAP_Reason'] = top_shap_reason 
        
        # Ensure outputs directory exists before saving CSV
        os.makedirs('outputs', exist_ok=True)
        df_anomalies.to_csv('outputs/alerts.csv', index=False)
        
        unique_attackers = attacker_ips.iloc[attack_indices].unique()
        for ip in unique_attackers:
            if ip != "192.168.56.1": 
                defense.block_ip(ip)
                
    else:
        if os.path.exists('outputs/alerts.csv'):
            os.remove('outputs/alerts.csv')



def generate_shap_explanation(model, X_live, attack_index, top_n=10):
    print("[XAI] Generating SHAP Explanation for the blocked packet...")
    try:
        # Ensure the outputs directory exists so savefig doesn't crash
        os.makedirs('outputs', exist_ok=True)

        malicious_packet = X_live.iloc[[attack_index]]
        explainer = shap.TreeExplainer(model)
        
        # check_additivity=False prevents random floating point errors in Scikit-Learn models
        shap_values = explainer.shap_values(malicious_packet, check_additivity=False)

        # ROBUST SHAP EXTRACTION: Handles lists, 2D arrays, and 3D arrays seamlessly
        if isinstance(shap_values, list):
            target_shap = shap_values[1] if len(shap_values) > 1 else shap_values[0]
        elif len(np.shape(shap_values)) == 3:
            target_shap = shap_values[0, :, 1] if np.shape(shap_values)[2] > 1 else shap_values[0, :, 0]
        else:
            target_shap = shap_values

        # Flatten into a strict 1D numpy array
        flat_values = np.array(target_shap).flatten()
        feature_names = np.array(X_live.columns) # Cast to numpy array for safe indexing
        
        # Text string generation for the CSV
        top_feature_idx = int(np.argmax(np.abs(flat_values))) 
        top_feature = feature_names[top_feature_idx]
        top_value = float(flat_values[top_feature_idx])
        shap_text = f"{top_feature} ({top_value:+.3f})"

        top_indices = np.argsort(np.abs(flat_values))[::-1][:top_n]
        top_indices = top_indices[::-1] # Reverse so largest is at the top of the bar chart

        top_features = feature_names[top_indices]
        top_shap_values = flat_values[top_indices]

        # Graph Generation
        plt.style.use('dark_background')
        fig, ax = plt.subplots(figsize=(10, 6), facecolor='#2b2b2b')
        ax.set_facecolor('#2b2b2b')

        colors = ['#C47A9A' if val > 0 else '#90AA7C' for val in top_shap_values]
        bars = ax.barh(top_features, top_shap_values, color=colors, height=0.6)

        ax.set_xlabel("SHAP Value (Impact on Prediction)", fontsize=12, fontweight='bold', color='white')
        ax.set_ylabel("Network Features", fontsize=12, fontweight='bold', color='white')

        ax.axvline(0, color='white', linewidth=1.5, linestyle='-')

        ax.xaxis.grid(True, linestyle='--', color='#555555', alpha=0.7)
        ax.set_axisbelow(True)
        plt.xticks(fontsize=11, fontweight='bold', color='white')
        plt.yticks(fontsize=12, fontweight='bold', color='white')

        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_visible(False) 
        ax.spines['bottom'].set_color('#555555')

        # Attach text labels to bars
        for bar in bars:
            width = bar.get_width()
            label_x_pos = width + (0.01 if width > 0 else -0.01)
            ha = 'left' if width > 0 else 'right'
            ax.text(label_x_pos, bar.get_y() + bar.get_height()/2, 
                    f'{width:+.3f}', 
                    va='center', ha=ha, color='white', fontsize=10, fontweight='bold')

        plt.tight_layout() 
        plt.savefig('outputs/shap_alert.png', bbox_inches='tight', 
                    facecolor=fig.get_facecolor(), edgecolor='none', dpi=150)
        plt.close(fig) # Explicitly close the figure object
        plt.savefig("latest_threat_shap.png", bbox_inches='tight')
        print(f"[XAI] SHAP plot saved successfully. Top feature: {shap_text}")
        return shap_text
        
    except Exception as e:
        import traceback
        print(f"[XAI] Error generating SHAP plot:\n{traceback.format_exc()}")
        return "Error generating explanation"