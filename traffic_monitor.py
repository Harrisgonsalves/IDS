from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import threading
import time
import logging
from plyer import notification
from live_inference import evaluate_traffic

packet_buffer = []
WINDOW_SIZE = 5 

def process_packet(packet):
    if IP in packet:
        # NEW: Safely extract TCP flags if the packet uses TCP
        tcp_flags = packet[TCP].flags if TCP in packet else ""
        
        packet_buffer.append({
            'src_ip': packet[IP].src,
            'length': len(packet),
            'protocol': packet[IP].proto,
            'tcp_flags': str(tcp_flags)  # NEW: Add flags to the buffer
        })

def analyze_traffic_window():
    global packet_buffer
    
    while True:
        time.sleep(WINDOW_SIZE)
        
        current_batch = packet_buffer[:]
        packet_buffer.clear()
        
        if not current_batch:
            continue
            
        df = pd.DataFrame(current_batch)
        df['is_syn'] = df['tcp_flags'].apply(lambda x: 1 if 'S' in str(x) else 0)  # NEW: Create a feature for SYN packets
        traffic_features = df.groupby('src_ip').agg(
            packet_count=('length', 'count'),
            total_bytes=('length', 'sum'),
            syn_count=('is_syn', 'sum')  # NEW: Sum up the SYN packets
        ).reset_index()
        
        
        logging.info(f"Extracted features for {len(traffic_features)} unique IPs.")
        evaluate_traffic(traffic_features)
        # ML Integration Placeholder
        # predictions = dnn_model.predict(traffic_features[['packet_count', 'total_bytes']])
        # if predictions == 'anomaly':
        #     notification.notify(
        #         title='XAI-IDS Alert: DoS Attack Detected!',
        #         message='Malicious traffic blocked. Open dashboard for SHAP explanations.',
        #         app_name='XAI-IDS',
        #         timeout=10
        #     )

def start_passive_sniffing(interface=None):
    logging.info("Starting Scapy passive network sniffing...")
    sniff(iface="VirtualBox Host-Only Ethernet Adapter", prn=process_packet, store=False)
if __name__ == '__main__':
    logging.basicConfig(filename='traffic_monitor.log', level=logging.INFO,
                        format='%(asctime)s - %(message)s')
    try:
        ml_thread = threading.Thread(target=analyze_traffic_window, daemon=True)
        ml_thread.start()

        start_passive_sniffing()
    except KeyboardInterrupt:
        logging.info("Stopping network sniffing.")