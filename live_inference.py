import pandas as pd
import os
from plyer import notification

# Constants for thresholds
IP_SPOOF_THRESHOLD = 500  # If more than 500 unique IPs appear in 5 seconds
SINGLE_IP_SYN_THRESHOLD = 100 # If one IP sends more than 100 SYNs

def evaluate_traffic(traffic_features):
    
    unique_ip_count = len(traffic_features)
    alert_triggered = False
    alert_msg = ""

    # 1. Check for Distributed/Spoofed Attack (The 26,000 IP scenario)
    if unique_ip_count > IP_SPOOF_THRESHOLD:
        alert_triggered = True
        alert_msg = f"DDoS/Spoofing Detected: {unique_ip_count} unique IPs active!"
        # Flag all these as anomalies for the dashboard
        anomalies = traffic_features 
    
    # 2. Check for Single-Source SYN Flood
    else:
        anomalies = traffic_features[traffic_features['syn_count'] > SINGLE_IP_SYN_THRESHOLD]
        if not anomalies.empty:
            alert_triggered = True
            alert_msg = f"SYN Flood detected from {len(anomalies)} source(s)."

    if alert_triggered:
        # Save to CSV so the Tkinter Dashboard updates
        anomalies.to_csv('outputs/alerts.csv', index=False)
        
        # Windows Desktop Notification
        notification.notify(
            title=' XAI-IDS SECURITY ALERT',
            message=alert_msg,
            app_name='XAI-IDS',
            timeout=5
        )
        print(f"[ALERT] {alert_msg}")
        
        # COMBAT STEP: Suggesting a system-level response
        if unique_ip_count > IP_SPOOF_THRESHOLD:
            print("RECOMMENDATION: Enable Windows SYN Attack Protection (Registry modification required).")
    else:
        # Clear alerts if traffic returns to normal
        if os.path.exists('outputs/alerts.csv'):
            os.remove('outputs/alerts.csv')