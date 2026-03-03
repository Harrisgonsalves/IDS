import tkinter as tk
from tkinter import ttk, messagebox
import pandas as pd
import os
import subprocess
import threading
import atexit
from PIL import Image, ImageTk

class IDS_Dashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        
        self.title("XAI-Driven Intrusion Detection System")
        self.geometry("800x600")
        
        # --- UI SETUP ---
        self.setup_ui()
        
        # --- START BACKGROUND BACKEND ---
        self.start_backend_monitor()
        
        # --- BACKGROUND GUI CHECK ---
        self.check_alerts()

    def start_backend_monitor(self):
        """Starts the traffic_monitor.py script natively in the background"""
        self.status_var.set("Status: Starting Backend Sniffer...")
        self.monitor_process = None
        
        def run_subprocess():
            # This launches your Scapy backend script
            # We save it to self.monitor_process so we can kill it when the UI closes
            self.monitor_process = subprocess.Popen(["python", "traffic_monitor.py"])
            
        # Start the subprocess in a separate Python thread so it doesn't freeze the Tkinter UI
        backend_thread = threading.Thread(target=run_subprocess, daemon=True)
        backend_thread.start()
        
        # Make sure the backend dies when you close the Tkinter window
        atexit.register(self.kill_backend)

    def kill_backend(self):
        """Kills the background Scapy monitor when the app closes."""
        if self.monitor_process:
            self.monitor_process.kill()

    def setup_ui(self):
        # Header Area
        header = ttk.Frame(self)
        header.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Label(header, text="XAI-IDS Security Dashboard", font=("Arial", 18, "bold")).pack(side=tk.LEFT)
        
        # Status Label
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(self, textvariable=self.status_var, font=("Arial", 12))
        self.status_label.pack(pady=10)
        
        # Alert Table Area
        self.tree = ttk.Treeview(self, columns=("IP", "Packets", "Bytes", "SYN Flags"), show="headings", height=5)
        self.tree.heading("IP", text="Source IP")
        self.tree.heading("Packets", text="Total Packets")
        self.tree.heading("Bytes", text="Total Bytes")
        self.tree.heading("SYN Flags", text="SYN Count")
        self.tree.pack(fill=tk.X, padx=20)
        
        # SHAP Image Area
        self.image_label = ttk.Label(self)
        self.image_label.pack(pady=20, fill=tk.BOTH, expand=True)

    def check_alerts(self):
        alert_path = "outputs/alerts.csv"
        shap_image_path = "outputs/shap_latest_alert.png"
        
        if os.path.exists(alert_path):
            self.status_var.set("Status: 🚨 ANOMALY DETECTED!")
            self.status_label.config(foreground="red")
            
            try:
                # Load CSV data
                df = pd.read_csv(alert_path)
                
                # Clear existing table data
                for item in self.tree.get_children():
                    self.tree.delete(item)
                    
                # Populate table
                for index, row in df.iterrows():
                    self.tree.insert("", tk.END, values=(row['src_ip'], row['packet_count'], row['total_bytes'], row['syn_count']))
                
                # Load and display SHAP Image
                if os.path.exists(shap_image_path):
                    img = Image.open(shap_image_path)
                    img = img.resize((600, 300), Image.Resampling.LANCZOS)
                    photo = ImageTk.PhotoImage(img)
                    self.image_label.config(image=photo)
                    self.image_label.image = photo 
                else:
                    self.image_label.config(text="Generating SHAP explanation...", image="")
                    
            except Exception:
                pass 
        else:
            self.status_var.set("Status: ✅ Secure (Sniffing Network...)")
            self.status_label.config(foreground="green")
            
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.image_label.config(image="", text="No SHAP data to display.")
        
        # Check every 3 seconds
        self.after(3000, self.check_alerts)

if __name__ == "__main__":
    app = IDS_Dashboard()
    app.mainloop()

#sudo hping3 -S --flood --rand-source -p 8080 192.