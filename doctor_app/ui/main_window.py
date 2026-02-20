import customtkinter as ctk
import os
from tkinter import filedialog, messagebox
from core.config import config
from core.models import UploadForm
from core.security_agent import SecurityAgent
import requests
import time

# --- App Theme ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
ctk.set_widget_scaling(1.1)
ctk.set_window_scaling(1.1)


class VaultQDoctorApp(ctk.CTk):
    def __init__(self, doctor_id: str, private_key: bytes):
        super().__init__()

        self.title(f"VaultQ – Doctor Portal")
        self.minsize(900, 600)
        self.geometry("1000x650")

        self.doctor_id = doctor_id
        self.selected_file_path = None

        self._center_window()
        self._build_ui()

        self.append_log = self._write_log

        self.agent = SecurityAgent(
            log_callback=self.append_log,
            status_callback=self.set_connection_status,
            loaded_private_key=private_key
        )
        
        self.agent = SecurityAgent(
            log_callback=self.append_log, 
            status_callback=self.set_connection_status,
            loaded_private_key=private_key,
            doctor_id=doctor_id # Pass the ID here
        )

    # ---------------- UI ---------------- #

    def _center_window(self):
        self.update_idletasks()
        w, h = 1000, 650
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- Top Bar ---
        self.top_bar = ctk.CTkFrame(self, height=60, corner_radius=0)
        self.top_bar.grid(row=0, column=0, sticky="nsew")
        self.top_bar.grid_columnconfigure(1, weight=1)

        self.app_title = ctk.CTkLabel(
            self.top_bar,
            text="VaultQ",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.app_title.grid(row=0, column=0, padx=20, pady=15, sticky="w")

        self.status_label = ctk.CTkLabel(self.top_bar, text="● Disconnected", text_color="#ef4444")
        self.status_label.grid(row=0, column=2, padx=20)

        self.connect_btn = ctk.CTkButton(self.top_bar, text="Connect", command=self.action_connect, width=100)
        self.connect_btn.grid(row=0, column=3, padx=(0, 20))

        # --- Tabs ---
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)

        self.upload_tab = self.tabs.add("Upload")
        self.logs_tab = self.tabs.add("Activity")
        self.settings_tab = self.tabs.add("Settings")

        self._build_upload_tab()
        self._build_logs_tab()
        self._build_settings_tab()

    # ---------------- Upload Tab ---------------- #

    def _build_upload_tab(self):
        self.upload_tab.grid_columnconfigure(0, weight=1)

        self.header = ctk.CTkLabel(
            self.upload_tab,
            text="Secure Record Upload",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.header.grid(row=0, column=0, sticky="w", pady=(10, 20))

        self.card = ctk.CTkFrame(self.upload_tab, corner_radius=16)
        self.card.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        self.card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.card, text="Patient ID").grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")
        self.patient_id_entry = ctk.CTkEntry(self.card, placeholder_text="PAT-8821")
        self.patient_id_entry.grid(row=0, column=1, padx=20, pady=(20, 10), sticky="ew")

        self.file_btn = ctk.CTkButton(
            self.card,
            text="Select File (PDF / DICOM)",
            command=self.action_select_file,
            fg_color="transparent",
            border_width=1
        )
        self.file_btn.grid(row=1, column=0, columnspan=2, padx=20, pady=(0, 10), sticky="ew")

        self.file_label = ctk.CTkLabel(self.card, text="No file selected", text_color="gray")
        self.file_label.grid(row=2, column=0, columnspan=2, pady=(0, 10))

        self.upload_btn = ctk.CTkButton(self.card, text="Encrypt & Upload", command=self.action_upload, state="disabled")
        self.upload_btn.grid(row=3, column=0, columnspan=2, padx=20, pady=(0, 20), sticky="ew")

    # ---------------- Logs Tab ---------------- #

    def _build_logs_tab(self):
        self.logs_tab.grid_columnconfigure(0, weight=1)
        self.logs_tab.grid_rowconfigure(0, weight=1)

        self.log_box = ctk.CTkTextbox(
            self.logs_tab,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#0f172a",
            text_color="#38bdf8"
        )
        self.log_box.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.log_box.configure(state="disabled")

        self._write_log("System Boot: Security Kernel Ready.\n")

    # ---------------- Settings Tab ---------------- #

    def _build_settings_tab(self):
        self.settings_tab.grid_columnconfigure(0, weight=1)

        self.settings_header = ctk.CTkLabel(
            self.settings_tab,
            text="Preferences",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        self.settings_header.grid(row=0, column=0, sticky="w", pady=(10, 20))

        self.theme_switch = ctk.CTkSwitch(self.settings_tab, text="Dark Mode", command=self.toggle_theme)
        self.theme_switch.select()
        self.theme_switch.grid(row=1, column=0, sticky="w", pady=10)

        self.password_btn = ctk.CTkButton(self.settings_tab, text="Change Password", command=self.trigger_password_change)
        self.password_btn.grid(row=2, column=0, sticky="w", pady=10)

    # ---------------- Callbacks ---------------- #

    def toggle_theme(self):
        mode = "dark" if self.theme_switch.get() else "light"
        ctk.set_appearance_mode(mode)

    def set_connection_status(self, connected: bool):
        if connected:
            self.status_label.configure(text="● Secure", text_color="#10b981")
            self.connect_btn.configure(state="disabled", text="Connected")
        else:
            self.status_label.configure(text="● Disconnected", text_color="#ef4444")
            self.connect_btn.configure(state="normal", text="Connect")
        self._check_upload_state()

    def append_log(self, text: str, level: str = "INFO"):
        timestamp = time.strftime("%H:%M:%S")
        formatted = f"[{timestamp}] [{level}] {text}\n"
        with open("doctor_app.log", "a") as f:
            f.write(formatted)
        self._write_log(formatted)

    def _write_log(self, text, *_):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text)
        self.log_box.configure(state="disabled")
        self.log_box.see("end")

    def action_connect(self):
        self.connect_btn.configure(text="Connecting...", state="disabled")
        self.agent.initiate_handshake()

    def action_select_file(self):
        path = filedialog.askopenfilename(title="Select Medical Record")
        if path:
            self.selected_file_path = path
            self.file_label.configure(text=os.path.basename(path), text_color="white")
            self._check_upload_state()

    def _check_upload_state(self):
        if self.agent.is_connected and self.selected_file_path and self.patient_id_entry.get():
            self.upload_btn.configure(state="normal")
        else:
            self.upload_btn.configure(state="disabled")

    def action_upload(self):
        try:
            form = UploadForm(patient_id=self.patient_id_entry.get(), filepath=self.selected_file_path)
            self.upload_btn.configure(state="disabled", text="Uploading...")
            self.agent.process_and_upload(form)
            self.selected_file_path = None
            self.file_label.configure(text="No file selected", text_color="gray")
            self.patient_id_entry.delete(0, 'end')
            self.upload_btn.configure(text="Encrypt & Upload")
        except Exception as e:
            self.append_log(f"Upload Error: {e}", "ERROR")
            self.upload_btn.configure(text="Encrypt & Upload")

    def trigger_password_change(self):
        old_p = ctk.CTkInputDialog(text="Enter Old Password:", title="Security").get_input()
        new_p = ctk.CTkInputDialog(text="Enter New Password:", title="Security").get_input()

        if old_p and new_p:
            try:
                resp = requests.post(
                    f"{config.server_url}/api/auth/change-password",
                    json={"doctor_id": self.doctor_id, "old_pass": old_p, "new_pass": new_p}
                )
                if resp.status_code == 200:
                    self.agent.vault.change_password(self.doctor_id, old_p, new_p)
                    messagebox.showinfo("Success", "Password changed successfully.")
                else:
                    messagebox.showerror("Error", "Server rejected the change.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to sync password: {e}")