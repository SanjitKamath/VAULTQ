import base64
import requests
import customtkinter as ctk
from tkinter import messagebox, Canvas
import sys

from doctor_app.ui.main_window import VaultQDoctorApp
from doctor_app.core.keystore import LocalKeyVault
from doctor_app.core.security_agent import SecurityAgent
from doctor_app.core.config import config 

class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()

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
            self.after(15, self._fade_in)

    def _on_close(self):
        self.destroy()
        sys.exit(0)

    def attempt_login(self):
        self.error_label.configure(text="")
        doc_id = self.id_entry.get().strip()
        password = self.pass_entry.get()

        if not doc_id or not password:
            messagebox.showwarning("Missing Info", "Please enter both ID and password.")
            return

        self.login_btn.configure(text="Authenticating...", state="disabled")
        self.status_label.configure(text="🔐 Verifying credentials...")

        self.after(100, lambda: self._perform_login(doc_id, password))

    def _perform_login(self, doc_id, password):
        try:
            private_key = self.vault.load_identity(doc_id, password)

            if private_key:
                self._show_success_tick(
                    lambda: self._animate_handshake(
                        lambda: self._animate_exit_and_launch(doc_id, private_key)
                    )
                )
                return

            resp = requests.post(f"{config.server_url}/api/auth/verify",
                                 json={"id": doc_id, "password": password})

            if resp.status_code != 200:
                raise Exception("Invalid credentials")

            agent_temp = SecurityAgent(log_callback=print, status_callback=print)
            private_key = agent_temp.signer.get_private_bytes()
            public_key = agent_temp.signer.get_public_bytes()

            onboard = requests.post(f"{config.server_url}/api/admin/doctors/onboard", json={
                "id": doc_id,
                "name": resp.json().get("name", "Doctor"),
                "pqc_public_key_b64": base64.b64encode(public_key).decode()
            })

            if onboard.status_code != 200:
                raise Exception("Server rejected key")

            self.vault.save_identity(doc_id, password, private_key)
            self._show_success_tick(
                lambda: self._animate_handshake(
                    lambda: self._animate_exit_and_launch(doc_id, private_key)
                )
            )

        except Exception as e:
            self.login_btn.configure(text="Login", state="normal")
            self.status_label.configure(text="")
            self.error_label.configure(text=f"❌ {str(e)}")
            self.login_btn.configure(text="Login", state="normal")
    
    def _animate_exit_and_launch(self, doc_id, private_key):
        def step(alpha, y_offset):
            if alpha <= 0:
                self.destroy()
                app = VaultQDoctorApp(doctor_id=doc_id, private_key=private_key)
                app.mainloop()
                import sys
                sys.exit(0)
                return

            self.attributes("-alpha", alpha)
            self.geometry(f"460x420+{self.winfo_x()}+{self.winfo_y() + y_offset}")
            self.after(15, lambda: step(alpha - 0.08, y_offset + 3))

        step(1.0, 0)

    def _show_success_tick(self, callback):
        self.login_btn.pack_forget()
        self.success_label.pack()

        def pulse(scale=1.0, growing=True):
            if scale > 1.4:
                growing = False
            if scale < 1.0 and not growing:
                callback()
                return

            size = int(60 * scale)
            self.success_label.configure(font=ctk.CTkFont(size=size, weight="bold"))
            self.after(30, lambda: pulse(scale + (0.05 if growing else -0.05), growing))

        pulse()

