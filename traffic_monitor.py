from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
import pandas as pd
import time
import threading

ML_COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

live_traffic_buffer = []
packet_history = []  
buffer_lock = threading.Lock()

def map_tcp_flags(flags):
    """Maps raw Scapy TCP flags to the KDD dataset 'flag' format."""
    if flags == 'S': return 'S0' # SYN only (Attempted connection)
    if flags == 'R': return 'REJ' # Rejected
    if flags == 'F': return 'SF' # Normal finish
    return 'SF' # Default

def process_packet(packet):
    global packet_history
    current_time = time.time()

    # Maintain 2-second sliding window
    packet_history = [p for p in packet_history if current_time - p['time'] <= 2.0]

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol_str = "icmp" if packet.haslayer(ICMP) else ("udp" if packet.haslayer(UDP) else "tcp")
        src_bytes = len(packet)
        dst_bytes = 0 
        
        flag_str = 'SF'
        service_str = 'private' 
        dst_port = 0
        
        if packet.haslayer(TCP):
            flag_str = map_tcp_flags(packet[TCP].flags)
            dst_port = packet[TCP].dport
            if dst_port == 80: service_str = 'http'
            elif dst_port == 22: service_str = 'ssh'
            elif dst_port == 21: service_str = 'ftp'
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport

        # --- FEATURE CALCULATIONS ---
        # Time-based Volume
        count = sum(1 for p in packet_history if p['dst_ip'] == dst_ip)
        srv_count = sum(1 for p in packet_history if p['dst_port'] == dst_port and dst_port != 0)

        # Statistical Rates
        serror_rate = 1.0 if flag_str == 'S0' else 0.0
        same_srv_rate = 1.0 if count > 0 else 0.0
        
        # PROBE DETECTION: High count of different services
        # If count is high but we are seeing many different ports, this identifies a scan
        diff_srv_rate = 1.0 if (count > 20 and src_bytes < 500) else 0.0

        # Update History
        packet_history.append({
            'time': current_time, 
            'dst_ip': dst_ip, 
            'dst_port': dst_port
        })

        # --- BUILD COMPLETE DICTIONARY ---
        feature_dict = {col: 0 for col in ML_COLUMNS} 

        # Identification
        feature_dict["protocol_type"] = protocol_str
        feature_dict["service"] = service_str
        feature_dict["flag"] = flag_str
        feature_dict["src_bytes"] = src_bytes
        feature_dict["dst_bytes"] = dst_bytes
        
        # Traffic Features (DoS & Probe)
        feature_dict["count"] = count          
        feature_dict["srv_count"] = srv_count 
        feature_dict["serror_rate"] = serror_rate
        feature_dict["srv_serror_rate"] = serror_rate
        feature_dict["same_srv_rate"] = same_srv_rate
        feature_dict["diff_srv_rate"] = diff_srv_rate # Critical for Probe

        # Host-based mirroring (NSL-KDD Signature)
        feature_dict["dst_host_count"] = count
        feature_dict["dst_host_srv_count"] = srv_count
        feature_dict["dst_host_same_srv_rate"] = same_srv_rate
        feature_dict["dst_host_diff_srv_rate"] = diff_srv_rate
        feature_dict["dst_host_serror_rate"] = serror_rate
        feature_dict["dst_host_srv_serror_rate"] = serror_rate
        
        # Internal tracking for firewall/UI
        feature_dict["_src_ip_"] = src_ip 

        # --- SAVE TO BUFFER (ONLY ONCE) ---
        with buffer_lock:
            live_traffic_buffer.append(feature_dict)
            
def flush_buffer():
    global live_traffic_buffer
    while True:
        time.sleep(2)

        with buffer_lock:
            if live_traffic_buffer:
                data_to_save = list(live_traffic_buffer) 
                live_traffic_buffer.clear() 
            else:
                data_to_save = None

        if data_to_save:
            df = pd.DataFrame(data_to_save)
            df.to_csv("outputs/live_features.csv", index=False)

threading.Thread(target=flush_buffer, daemon=True).start()

print("Stateful Flow Sniffer active on VirtualBox Lab...")
# Ensure this exactly matches your Windows Network Connections name!
sniff(iface="VirtualBox Host-Only Ethernet Adapter", prn=process_packet, store=False)