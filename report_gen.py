from fpdf import FPDF
import datetime
import os

def generate_incident_report(attacker_ip, threat_type, top_feature, shap_image_path="C:\\IDS\\outputs\\shap_alert.png"):
    try:
        pdf = FPDF()
        pdf.add_page()
        
        # --- Header ---
        pdf.set_font("helvetica", "B", 16)
        pdf.set_text_color(200, 0, 0) # Red title
        pdf.cell(0, 10, "XAI-IDS Security Operations Center", ln=True, align="C")
        pdf.set_text_color(0, 0, 0) # Back to black
        pdf.set_font("helvetica", "B", 14)
        pdf.cell(0, 10, "Automated Incident Response Report", ln=True, align="C")
        pdf.ln(10)
        
        # --- Threat Details ---
        pdf.set_font("helvetica", "", 12)
        pdf.cell(0, 10, f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.cell(0, 10, f"Status: BLOCKED at Kernel Level", ln=True)
        pdf.cell(0, 10, f"Target Interface: VirtualBox Host-Only Ethernet Adapter", ln=True)
        pdf.ln(5)
        
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "Incident Parameters:", ln=True)
        pdf.set_font("helvetica", "", 12)
        pdf.cell(0, 10, f"- Source IP: {attacker_ip}", ln=True)
        pdf.cell(0, 10, f"- ML Classification: {threat_type}", ln=True)
        pdf.cell(0, 10, f"- Primary SHAP Indicator: {top_feature}", ln=True)
        pdf.ln(10)
        
        # --- SHAP Visualization ---
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "Explainable AI (SHAP) Analysis:", ln=True)
        
        if os.path.exists(shap_image_path):
            # Adjust 'w' (width) as needed to fit the page
            pdf.image(shap_image_path, x=10, y=pdf.get_y() + 5, w=170)
        else:
            pdf.set_font("helvetica", "I", 12)
            pdf.cell(0, 10, "[SHAP Visualization Image Not Found]", ln=True)
            
        # --- Save ---
        filename =f"outputs/Incident_Report_{attacker_ip.replace('.', '_')}.pdf"
        pdf.output(filename)
        print(f"[SYSTEM] Report successfully generated: {filename}")
        
    except Exception as e:
        print(f"[ERROR] Failed to generate report: {e}")