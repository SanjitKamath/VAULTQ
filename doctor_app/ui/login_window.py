import base64
import requests
import customtkinter as ctk
from tkinter import messagebox, Canvas
import sys

from doctor_app.ui.main_window import VaultQDoctorApp
from doctor_app.core.keystore import LocalKeyVault
from doctor_app.core.security_agent import SecurityAgent
from doctor_app.core.config import config 
from doctor_app.core.audit_logger import get_audit_logger

class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.audit = get_audit_logger()
        self.audit.info("Doctor login window initialized")

        self.title("VaultQ – Secure Doctor Login")
        self.geometry("460x420")
        self.minsize(460, 420)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.vault = LocalKeyVault()
        self.attributes("-alpha", 0.0)

        self._center_window()
        self._build_ui()
        self._fade_in()

    def _center_window(self):
        self.update_idletasks()
        w, h = 460, 420
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        self.container = ctk.CTkFrame(self, corner_radius=24)
        self.container.pack(expand=True, fill="both", padx=40, pady=40)
        self.success_label = ctk.CTkLabel(self.container, text="✓", text_color="#22c55e", font=ctk.CTkFont(size=60, weight="bold"))
        self.success_label.pack(pady=10)
        self.success_label.pack_forget()

        ctk.CTkLabel(
            self.container,
            text="VaultQ",
            font=ctk.CTkFont(size=28, weight="bold")
        ).pack(pady=(20, 5))

        ctk.CTkLabel(
            self.container,
            text="Secure Doctor Login",
            text_color="#94a3b8"
        ).pack(pady=(0, 25))

        self.id_entry = ctk.CTkEntry(self.container, placeholder_text="Doctor ID")
        self.id_entry.pack(fill="x", padx=20, pady=8)

        self.pass_entry = ctk.CTkEntry(self.container, placeholder_text="Password", show="•")
        self.pass_entry.pack(fill="x", padx=20, pady=8)

        self.login_btn = ctk.CTkButton(
            self.container,
            text="Login",
            height=40,
            command=self.attempt_login
        )
        self.login_btn.pack(fill="x", padx=20, pady=20)

        self.status_label = ctk.CTkLabel(self.container, text="")
        self.status_label.pack()

        self.error_label = ctk.CTkLabel(
            self.container,
            text="",
            text_color="#ef4444",
            wraplength=300,
            justify="center"
        )
        self.error_label.pack(pady=(5, 0))


    def _fade_in(self):
        alpha = self.attributes("-alpha")
        if alpha < 1.0:
            self.attributes("-alpha", alpha + 0.05)
            self._fade_job = self.after(15, self._fade_in)

    def _on_close(self):
        self.withdraw()
        import sys
        sys.exit(0)

    def attempt_login(self):
        self.error_label.configure(text="")
        doc_id = self.id_entry.get().strip()
        password = self.pass_entry.get()
        self.audit.info("Login attempt started for doctor_id=%s", doc_id)

        if not doc_id or not password:
            self.audit.warning("Login blocked: missing credentials")
            messagebox.showwarning("Missing Info", "Please enter both ID and password.")
            return

        self.login_btn.configure(text="Authenticating...", state="disabled")
        self.status_label.configure(text="🔐 Verifying credentials...")

        self.after(100, lambda: self._perform_login(doc_id, password))

    def _perform_login(self, doc_id, password):
        try:
            self.audit.info("Login verify request sent for doctor_id=%s", doc_id)
            resp = requests.post(f"{config.server_url}/api/auth/verify",
                                 json={"id": doc_id, "password": password})

            if resp.status_code != 200:
                self.audit.warning("Login verify rejected for doctor_id=%s status=%s", doc_id, resp.status_code)
                raise Exception("Invalid credentials")
            self.audit.info("Login verify accepted for doctor_id=%s", doc_id)

            try:
                private_key = self.vault.load_identity(doc_id, password)
            except ValueError:
                private_key = None
                self.audit.info("Local vault password mismatch for doctor_id=%s; migration requested", doc_id)
                old_local_password = ctk.CTkInputDialog(
                    text="Server password is valid, but your local vault is still encrypted with your previous password.\n\nEnter previous local password to migrate:",
                    title="Migrate Local Vault"
                ).get_input()

                if not old_local_password:
                    self.audit.warning("Local vault migration cancelled for doctor_id=%s", doc_id)
                    raise Exception("Local vault migration cancelled.")

                self.vault.change_password(doc_id, old_local_password, password)
                private_key = self.vault.load_identity(doc_id, password)
                if not private_key:
                    self.audit.error("Local vault migration failed for doctor_id=%s", doc_id)
                    raise Exception("Local vault migration failed.")
                self.audit.info("Local vault migration succeeded for doctor_id=%s", doc_id)

            if private_key:
                self.audit.info("Login using existing local ML-DSA identity for doctor_id=%s", doc_id)
                self._show_success_tick(
                    lambda: self._animate_handshake(
                        lambda: self._animate_exit_and_launch(doc_id, private_key)
                    )
                )
                return

            agent_temp = SecurityAgent(log_callback=print, status_callback=print)
            private_key = agent_temp.signer.get_private_bytes()
            public_key = agent_temp.signer.get_public_bytes()

            onboard = requests.post(f"{config.server_url}/api/admin/doctors/onboard", json={
                "id": doc_id,
                "name": resp.json().get("name", "Doctor"),
                "pqc_public_key_b64": base64.b64encode(public_key).decode()
            })

            if onboard.status_code != 200:
                self.audit.warning("Doctor onboarding rejected during login for doctor_id=%s status=%s", doc_id, onboard.status_code)
                raise Exception("Server rejected key")
            self.audit.info("Doctor onboarding accepted for doctor_id=%s", doc_id)

            self.vault.save_identity(doc_id, password, private_key)
            self.audit.info("Local ML-DSA identity stored for doctor_id=%s", doc_id)
            self._show_success_tick(
                lambda: self._animate_handshake(
                    lambda: self._animate_exit_and_launch(doc_id, private_key)
                )
            )

        except Exception as e:
            self.audit.exception("Login flow error for doctor_id=%s: %s", doc_id, str(e))
            self.login_btn.configure(text="Login", state="normal")
            self.status_label.configure(text="")
            self.error_label.configure(text=f"❌ {str(e)}")
            self.login_btn.configure(text="Login", state="normal")
    
    def _animate_exit_and_launch(self, doc_id, private_key):
        def step(alpha, y_offset):
            if alpha <= 0:
                # ❌ self.destroy()   <-- REMOVE THIS
                self.withdraw()      # ✅ hide login window instead

                # Create main window
                app = VaultQDoctorApp(doctor_id=doc_id, private_key=private_key)
                app.deiconify()
                app.lift()
                app.focus_force()
                app.focus_force()
                return

            self.attributes("-alpha", alpha)
            self.geometry(f"460x420+{self.winfo_x()}+{self.winfo_y() + y_offset}")
            self._fade_job = self.after(15, lambda: step(alpha - 0.08, y_offset + 3))

        step(1.0, 0)

    def _show_success_tick(self, callback):
        self.login_btn.pack_forget()
        self.success_label.pack()
        self.after(300, callback)

    def _animate_handshake(self, callback):
        # Optional subtle text feedback instead of ugly spinner
        self.status_label.configure(text="🔗 Establishing secure channel...")

        # Small delay to simulate handshake animation / polish
        def finish():
            self.status_label.configure(text="")
            callback()

        # 400ms feels premium without being slow
        self.after(400, finish)

