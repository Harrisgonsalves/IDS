import time
import tkinter as tk
from tkinter import ttk, messagebox
import pandas as pd
import os
import subprocess
import threading
import atexit
from PIL import Image, ImageTk
import defense
import live_inference

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
        self.update_dashboard()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def start_backend_monitor(self):
        self.status_var.set("Status: Starting Backend Sniffer & AI Model...")
        self.monitor_process = None

        print("[SYSTEM] Wiping old traffic logs for a clean startup...")
        files_to_delete = ['outputs/live_features.csv', 'outputs/alerts.csv', 'outputs/shap_alert.png']
        for file in files_to_delete:
            if os.path.exists(file):
                try:
                    os.remove(file)
                except:
                    pass
        def run_sniffer():
            self.monitor_process = subprocess.Popen(["python", "traffic_monitor.py"])
            
        sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
        sniffer_thread.start()
        
        def run_inference():
            time.sleep(2) 
            while True:
                try:
                    live_inference.evaluate_traffic()
                except Exception as e:
                    print(f"[ML THREAD ERROR] {e}")
                
                time.sleep(2) 
                
        inference_thread = threading.Thread(target=run_inference, daemon=True)
        inference_thread.start()
    
        # Make sure the backend dies when you close the Tkinter window
        atexit.register(self.kill_backend)

    def update_dashboard(self):
        if os.path.exists('outputs/alerts.csv'):
            try:
                self.status_var.set("Status: ⚠️ ANOMALY DETECTED!")
                self.status_label.config(foreground="red")
                
                df = pd.read_csv('outputs/alerts.csv')

                for row in self.tree.get_children():
                    self.tree.delete(row)

                for index, row in df.iterrows():
                    ip = row.get('_src_ip_', "Unknown")
                    attack = row.get('Attack_Type', "Anomaly")
                    shap_reason = row.get('SHAP_Reason', "N/A")  
                    bytes_sent = row.get('src_bytes', 0)
                    proto = row.get('protocol_type', "N/A")
                    
                    self.tree.insert("", tk.END, values=(ip, attack, shap_reason, bytes_sent, proto))
                
                if os.path.exists('outputs/shap_alert.png'):
                    try:
                        img = Image.open('outputs/shap_alert.png')
                        img = img.resize((600, 300), Image.Resampling.LANCZOS)
                        photo = ImageTk.PhotoImage(img)
                        self.image_label.config(image=photo)
                        self.image_label.image = photo
                    except PermissionError:
                        print("File locked, skipping image update this second...")
                        pass
                    
            except Exception as e:
                print(f"UI Update Error: {e}")
                
        else:
            self.status_var.set("Status: ✅ Normal Traffic / Listening...")
            self.status_label.config(foreground="green")
            
            for row in self.tree.get_children():
                self.tree.delete(row)
            self.image_label.config(image='')

        # Refresh every 2 seconds
        self.after(2000, self.update_dashboard)

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
        self.tree = ttk.Treeview(self, columns=("IP", "Attack Type", "Reason", "Bytes", "Protocol"), show="headings", height=5)
        self.tree.heading("IP", text="Source IP")
        self.tree.heading("Attack Type", text="ML Prediction (Type)")
        self.tree.heading("Reason", text="Top Feature (SHAP)")
        self.tree.heading("Bytes", text="Source Bytes")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.pack(fill=tk.X, padx=20)
        
        # --- SHAP Image Area ---
        
        self.tree.column("Reason", width=150)
        self.tree.pack(fill=tk.X, padx=20)
        self.image_label = ttk.Label(self)
        self.image_label.pack(pady=20, fill=tk.BOTH, expand=True)
        
        # 2. Add the Image Label for SHAP
        self.image_label = ttk.Label(self)
        self.image_label.pack(pady=20, fill=tk.BOTH, expand=True)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.unblock_btn = ttk.Button(
            btn_frame, 
            text=" Reset Firewall (Unblock All IPs)", 
            command=self.reset_firewall
        )
        self.unblock_btn.pack(side=tk.RIGHT)

    def reset_firewall(self):
        """Calls the defense script to remove all IDS firewall rules."""
        try:
            # Call the function from defense.py
            defense.unblock_all()
            
            # Show a success popup
            messagebox.showinfo("Firewall Reset", "All IDS blocking rules have been removed from Windows Firewall.")
            
            # Update the dashboard status
            self.status_var.set("Status:  Firewall Reset. Traffic unblocked.")
            self.status_label.config(foreground="green")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reset firewall: {e}\n\nMake sure you are running the app as Administrator.")
    
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
            self.status_var.set("Status: Secure (Sniffing Network...)")
            self.status_label.config(foreground="green")
            
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.image_label.config(image="", text="No SHAP data to display.")
        
        # Check every 2 seconds
        self.after(2000, self.check_alerts)
    
    def on_closing(self):
        print("[SYSTEM] Shutting down XAI-IDS Pipeline...")

        if hasattr(self, 'monitor_process') and self.monitor_process is not None:
            try:
                self.monitor_process.terminate()
            except:
                pass

        self.destroy()

        os._exit(0)

if __name__ == "__main__":
    app = IDS_Dashboard()
    app.mainloop()
