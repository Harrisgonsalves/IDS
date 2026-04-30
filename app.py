import time
import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import pandas as pd
import os
import subprocess
import threading
import atexit
from PIL import Image, ImageTk
import defense
import live_inference
from report_gen import generate_incident_report

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class IDS_Dashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("XAI-IDS | Security Operations Center")
        self.geometry("1200x800")
        
        # Configure Grid Layout (4 rows, 2 columns)
        self.grid_columnconfigure(0, weight=2) # Left side (Table & Logs) takes more space
        self.grid_columnconfigure(1, weight=1) # Right side (SHAP & Controls)
        self.grid_rowconfigure(2, weight=1)    # Let the table expand
        
        self.current_attacker_ip = None
        self.current_threat_type = None
        self.current_top_feature = None
        self.setup_ui()
        
        self.start_backend_monitor()
        
        self.update_dashboard()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)


    def start_backend_monitor(self):
        self.log_event("Starting Backend Sniffer & AI Model...")
        self.monitor_process = None

        self.log_event("Wiping old traffic logs for a clean startup...")
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
    
        atexit.register(self.kill_backend)

 
    def log_to_terminal(self, message):
        """Helper method to securely append text to the dashboard's log box."""
        try:
            self.log_box.configure(state="normal")
            self.log_box.insert("end", f"{message}\n")
            self.log_box.see("end")
            self.log_box.configure(state="disabled")
            
        except Exception as e:
            print(f"Failed to write to GUI log: {e}")

    def kill_backend(self):
        """Kills the background Scapy monitor when the app closes."""
        if self.monitor_process:
            self.monitor_process.kill()

    def log_event(self, message):
        """Writes a message to the SOC log terminal"""
        try:
            self.log_box.configure(state="normal")
            timestamp = time.strftime("%H:%M:%S")
            self.log_box.insert("end", f"[{timestamp}] {message}\n")
            self.log_box.see("end") 
            self.log_box.configure(state="disabled")
        except:
            pass 

    def setup_ui(self):
        self.banner = ctk.CTkLabel(self, text="SYSTEM SECURE | MONITORING TRAFFIC", fg_color="green", text_color="white", font=ctk.CTkFont(size=18, weight="bold"), corner_radius=0)
        self.banner.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        self.cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.cards_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=20, pady=10)
        self.cards_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.status_card = self.create_card(self.cards_frame, "System Status", "ONLINE", 0)
        self.threat_card = self.create_card(self.cards_frame, "Threat Level", "LOW", 1)
        self.model_card = self.create_card(self.cards_frame, "AI Model", "Random Forest (Active)", 2)

        self.table_frame = ctk.CTkFrame(self)
        self.table_frame.grid(row=2, column=0, sticky="nsew", padx=(20, 10), pady=10)
        
        ctk.CTkLabel(self.table_frame, text="Active Network Threats", font=ctk.CTkFont(weight="bold")).pack(pady=5)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0)
        style.configure("Treeview.Heading", background="#1f538d", foreground="white", font=('Arial', 10, 'bold'))
        style.map('Treeview', background=[('selected', '#1f538d')])

        self.tree = ttk.Treeview(self.table_frame, columns=("IP", "Attack", "SHAP", "Bytes", "Protocol"), show="headings", height=10)
        self.tree.heading("IP", text="Source IP")
        self.tree.heading("Attack", text="ML Prediction")
        self.tree.heading("SHAP", text="Top SHAP Feature")
        self.tree.heading("Bytes", text="Bytes")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.column("SHAP", width=150)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        self.xai_frame = ctk.CTkFrame(self)
        self.xai_frame.grid(row=2, column=1, sticky="nsew", padx=(10, 20), pady=10)
        
        ctk.CTkLabel(self.xai_frame, text="Explainable AI (SHAP Analysis)", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        
        self.image_label = ctk.CTkLabel(self.xai_frame, text="No anomalies detected.\nWaiting for SHAP data...")
        self.image_label.pack(fill="both", expand=True, padx=10, pady=10)

        self.logs_frame = ctk.CTkFrame(self)
        self.logs_frame.grid(row=3, column=0, sticky="nsew", padx=(20, 10), pady=(10, 20))
        
        ctk.CTkLabel(self.logs_frame, text="Real-Time Security Logs", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=10)
        self.log_box = ctk.CTkTextbox(self.logs_frame, height=120)
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.log_box.insert("0.0", "[SYSTEM] SOC Dashboard initialized. Awaiting traffic...\n")
        self.log_box.configure(state="disabled") 

        self.controls_frame = ctk.CTkFrame(self)
        self.controls_frame.grid(row=3, column=1, sticky="nsew", padx=(10, 20), pady=(10, 20))
        
        ctk.CTkLabel(self.controls_frame, text="Firewall Controls", font=ctk.CTkFont(weight="bold")).pack(pady=5)
        
        self.btn_unblock = ctk.CTkButton(self.controls_frame, text="Reset Firewall (Unblock All IPs)", fg_color="#8B0000", hover_color="#5C0000", command=self.reset_firewall)
        self.btn_unblock.pack(pady=10, padx=20, fill="x")
        self.report_button = ctk.CTkButton(
            self.controls_frame, 
            text="Generate Incident Report", 
            fg_color="#0052cc", 
            hover_color="#003d99",
            command=self.trigger_report
        )
        self.report_button.pack(pady=0, padx=20, fill="x")

    def update_dashboard(self):
        if os.path.exists('outputs/alerts.csv'):
            try:
                file_age = time.time() - os.path.getmtime('outputs/alerts.csv')
                if file_age > 10.0:
                    os.remove('outputs/alerts.csv')
                    self.after(2000, self.update_dashboard)
                    return
                self.banner.configure(text="⚠️ THREAT DETECTED | INTRUSION PREVENTION ACTIVE", fg_color="#8B0000")
                self.threat_card.configure(text="CRITICAL", text_color="#FF4500")
                self.status_card.configure(text="BLOCKING IPS", text_color="#FF4500")
                
                df = pd.read_csv('outputs/alerts.csv')
                if not df.empty:
                    # Using .iloc[-1] grabs the absolute latest attack row
                    self.current_attacker_ip = str(df.iloc[-1].get('_src_ip_', "Unknown"))
                    self.current_threat_type = str(df.iloc[-1].get('Attack_Type', "Anomaly")).upper()
                    self.current_top_feature = str(df.iloc[-1].get('SHAP_Reason', "N/A"))
                
                for row in self.tree.get_children():
                    self.tree.delete(row)

                for index, row in df.iterrows():
                    ip = str(row.get('_src_ip_', "Unknown"))
                    attack = str(row.get('Attack_Type', "Anomaly")).upper()
                    shap_reason = str(row.get('SHAP_Reason', "N/A"))  
                    bytes_sent = str(row.get('src_bytes', 0))
                    proto = str(row.get('protocol_type', "N/A"))
                    
                    self.tree.insert("", tk.END, values=(ip, attack, shap_reason, bytes_sent, proto))
                
                # Load SHAP Image
                if os.path.exists('outputs/shap_alert.png'):
                    try:
                        img = Image.open('outputs/shap_alert.png')
                        img = img.resize((450, 250), Image.Resampling.LANCZOS)
                        photo = ctk.CTkImage(light_image=img, dark_image=img, size=(450, 250))
                        self.image_label.configure(image=photo, text="")
                    except PermissionError:
                        print("File locked, skipping image update this second...")
                        pass
                    
            except Exception as e:
                print(f"UI Update Error: {e}")
                
        else:
            self.banner.configure(text="SYSTEM SECURE | MONITORING TRAFFIC", fg_color="green")
            self.threat_card.configure(text="LOW", text_color="white")
            self.status_card.configure(text="ONLINE", text_color="white")
            
            for row in self.tree.get_children():
                self.tree.delete(row)
            self.image_label.configure(image="", text="No anomalies detected.\nWaiting for SHAP data...")

        self.after(2000, self.update_dashboard)
    
    def trigger_report(self):
        # 1. Check if there is an active threat to report on
        # (You will need to pull these variables from your active state/table)
        latest_ip = self.current_attacker_ip 
        latest_threat = self.current_threat_type
        latest_feature = self.current_top_feature
        
        if not latest_ip:
            self.log_to_terminal("[SYSTEM] No active threats to report.")
            return
            
        self.log_to_terminal(f"[SYSTEM] Compiling PDF report for {latest_ip}...")
        
        generate_incident_report(
            attacker_ip=latest_ip,
            threat_type=latest_threat,
            top_feature=latest_feature,
            shap_image_path="C:\\IDS\\outputs\\shap_alert.png"
        )
        self.log_to_terminal("[SYSTEM] PDF saved to project directory.")
    
    def create_card(self, parent, title, value, col):
        """Helper to create SOC metric cards"""
        frame = ctk.CTkFrame(parent, fg_color="#1e1e1e", corner_radius=10)
        frame.grid(row=0, column=col, sticky="ew", padx=10)
        ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=14, weight="bold"), text_color="gray").pack(pady=(10, 0))
        val_label = ctk.CTkLabel(frame, text=value, font=ctk.CTkFont(size=24, weight="bold"))
        val_label.pack(pady=(5, 10))
        return val_label

    def reset_firewall(self):
        """Calls the defense script to remove all IDS firewall rules."""
        try:
            defense.unblock_all()
            self.log_event("Firewall reset initiated. All IDS blocks removed.")
            messagebox.showinfo("Firewall Reset", "All IDS blocking rules have been removed from Windows Firewall.")
            self.banner.configure(text="FIREWALL RESET | TRAFFIC UNBLOCKED", fg_color="green")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reset firewall: {e}\n\nMake sure you are running the app as Administrator.")

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