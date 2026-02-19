import customtkinter as ctk
import os
from tkinter import filedialog, messagebox
from core.config import config
from core.models import UploadForm
from core.security_agent import SecurityAgent
import requests
import time

# Set modern theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class VaultQDoctorApp(ctk.CTk):
    def __init__(self, doctor_id: str, private_key: bytes):
        super().__init__()
        self.title(f"VaultQ - Doctor Portal ({doctor_id})")
        self.geometry("600x500")
        
        self.doctor_id = doctor_id
        self.selected_file = None

        # Pass the unlocked ML-DSA private key into the Security Agent
        self.agent = SecurityAgent(
            log_callback=self.append_log, 
            status_callback=self.set_connection_status,
            loaded_private_key=private_key
        )

        self._build_ui()

    def _build_ui(self):
        # Grid Layout: 1 row, 2 columns (Sidebar, Main Content)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR ---
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="VaultQ", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 5))
        
        self.doc_label = ctk.CTkLabel(self.sidebar_frame, text=config.doctor_name, font=ctk.CTkFont(size=12), text_color="gray")
        self.doc_label.grid(row=1, column=0, padx=20, pady=(0, 30))

        self.connect_btn = ctk.CTkButton(self.sidebar_frame, text="Initiate Handshake", command=self.action_connect)
        self.connect_btn.grid(row=2, column=0, padx=20, pady=10)

        # Status Indicator
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="⚫ Disconnected", text_color="#ef4444", font=ctk.CTkFont(weight="bold"))
        self.status_label.grid(row=3, column=0, padx=20, pady=10)

        # --- MAIN CONTENT ---
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_rowconfigure(2, weight=1) # Makes log box expand

        # Header
        self.header = ctk.CTkLabel(self.main_frame,text="Secure Record Upload",font=ctk.CTkFont(size=28, weight="normal"))

        self.header.grid(row=0, column=0, sticky="w", pady=(0, 20))

        # Upload Card
        self.upload_card = ctk.CTkFrame(self.main_frame, corner_radius=15)
        self.upload_card.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        self.upload_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.upload_card, text="Patient ID:").grid(row=0, column=0, padx=20, pady=20, sticky="w")
        self.patient_id_entry = ctk.CTkEntry(self.upload_card, placeholder_text="e.g., PAT-8821")
        self.patient_id_entry.grid(row=0, column=1, padx=20, pady=20, sticky="ew")

        self.file_btn = ctk.CTkButton(self.upload_card, text="Select PDF/DICOM", fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"), command=self.action_select_file)
        self.file_btn.grid(row=1, column=0, columnspan=2, padx=20, pady=(0, 10), sticky="ew")
        
        self.file_label = ctk.CTkLabel(self.upload_card, text="No file selected", text_color="gray")
        self.file_label.grid(row=2, column=0, columnspan=2, pady=(0, 20))

        self.upload_btn = ctk.CTkButton(self.upload_card, text="Sign, Encrypt & Upload", command=self.action_upload, state="disabled")
        self.upload_btn.grid(row=3, column=0, columnspan=2, padx=20, pady=(0, 20), sticky="ew")

        # Log Console
        self.log_box = ctk.CTkTextbox(self.main_frame, font=ctk.CTkFont(family="Consolas", size=12), fg_color="#0f172a", text_color="#38bdf8")
        self.log_box.grid(row=2, column=0, sticky="nsew")
        self.append_log("System Boot: Security Kernel Ready.", "INFO")

    # --- ACTIONS & CALLBACKS ---
    def set_connection_status(self, connected: bool):
        if connected:
            self.status_label.configure(text="🟢 SECURE", text_color="#10b981")
            self.connect_btn.configure(state="disabled", text="Session Active")
            self._check_upload_state()
        else:
            self.status_label.configure(text="⚫ Disconnected", text_color="#ef4444")
            self.connect_btn.configure(state="normal", text="Initiate Handshake")

    def append_log(self, text: str, level: str = "INFO"):
        """Writes a log entry to a log file with color coding based on level."""
        with open("doctor_app.log", "a") as log_book:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            log_entry = f"[{timestamp}] [{level}] {text}\n"
            log_book.write(log_entry)
        log_book.close()

    def _write_log(self, text):
        self.log_box.insert("end", text)
        self.log_box.see("end")

    def action_connect(self):
        self.connect_btn.configure(state="disabled", text="Connecting...")
        self.agent.initiate_handshake()

    def action_select_file(self):
        filepath = filedialog.askopenfilename(title="Select Medical Record")
        if filepath:
            self.selected_file_path = filepath
            self.file_label.configure(text=os.path.basename(filepath), text_color="white")
            self._check_upload_state()

    def _check_upload_state(self):
        if self.agent.is_connected and self.selected_file_path and self.patient_id_entry.get():
            self.upload_btn.configure(state="normal")
        else:
            self.upload_btn.configure(state="disabled")

    def action_upload(self):
        try:
            # Validate using Pydantic
            form = UploadForm(patient_id=self.patient_id_entry.get(), filepath=self.selected_file_path)
            self.upload_btn.configure(state="disabled") # Prevent double click
            self.agent.process_and_upload(form)
            # Reset UI
            self.selected_file_path = None
            self.file_label.configure(text="No file selected", text_color="gray")
            self.patient_id_entry.delete(0, 'end')
        except Exception as e:
            self.append_log(f"Validation Error: {e}", "ERROR")

    def trigger_password_change(self):
        old_p = ctk.CTkInputDialog(text="Enter Old Password:", title="Security").get_input()
        new_p = ctk.CTkInputDialog(text="Enter New Password:", title="Security").get_input()

        if old_p and new_p:
            try:
                # 1. Update the Server first
                resp = requests.post(f"{config.server_url}/api/auth/change-password", 
                                     json={"doctor_id": self.doctor_id, "old_pass": old_p, "new_pass": new_p})
                
                if resp.status_code == 200:
                    # 2. Update the Local Vault (CRITICAL: If this fails, the local key is lost!)
                    self.agent.vault.change_password(self.doctor_id, old_p, new_p)
                    messagebox.showinfo("Success", "Password changed everywhere!")
                else:
                    messagebox.showerror("Error", "Server rejected the change.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to sync password: {str(e)}")