import base64
import os
import requests
import customtkinter as ctk
from tkinter import messagebox
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

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
        self.server_url = str(config.server_url).rstrip("/")

        self.title("VaultQ – Secure Doctor Login")
        self.geometry("460x420")
        self.minsize(460, 420)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.vault = LocalKeyVault()
        self.attributes("-alpha", 0.0)

        self._center_window()
        self._build_ui()
        self._fade_in()

    def _request_verify_arg(self):
        if str(self.server_url).lower().startswith("http://"):
            return False
        if config.allow_insecure_dev:
            return False
        if not os.path.exists(config.ca_cert_path):
            raise RuntimeError(
                f"CA certificate not found: {config.ca_cert_path}. "
                "Either provide the CA cert, or set VAULTQ_ALLOW_INSECURE_DEV=1 for local dev."
            )
        return config.ca_cert_path

    def _try_local_dev_fallback(self, exc: Exception) -> bool:
        """Fallback only for local loopback when TLS port is unavailable."""
        current = str(self.server_url).lower()
        if not current.startswith("https://127.0.0.1:8443"):
            return False
        if "actively refused" not in str(exc).lower() and "failed to establish a new connection" not in str(exc).lower():
            return False

        self.server_url = "http://127.0.0.1:8080"
        config.server_url = self.server_url
        config.allow_insecure_dev = True
        self.audit.warning(
            "Auto-switched doctor client to local dev server URL=%s after TLS connection failure",
            self.server_url,
        )
        return True

    def _keys_dir(self):
        keys_dir = config.keys_dir if getattr(config, "keys_dir", None) else "doctor_app/storage/keys"
        os.makedirs(keys_dir, exist_ok=True)
        return keys_dir

    def _clear_local_tls_assets(self):
        keys_dir = self._keys_dir()
        for name in ("doctor_container.key", "doctor_cert.pem"):
            path = os.path.join(keys_dir, name)
            if os.path.exists(path):
                os.remove(path)
                self.audit.info("Removed stale local TLS asset: %s", path)

    def _copy_server_ca_if_available(self):
        if os.path.exists(config.ca_cert_path):
            return
        server_ca = os.path.join("server_app", "storage", "certs", "hospital_root_ca.pem")
        if os.path.exists(server_ca):
            self._keys_dir()
            with open(server_ca, "rb") as src, open(config.ca_cert_path, "wb") as dst:
                dst.write(src.read())
            self.audit.info("Copied server root CA to doctor client trust store: %s", config.ca_cert_path)

    def _prepare_tls_material(self):
        if str(config.server_url).lower().startswith("http://") or config.allow_insecure_dev:
            return False
        self._copy_server_ca_if_available()
        return self._request_verify_arg()

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
            
            # Assuming the server certificate is trusted or we bypass verification for the initial login
            # In a strict production environment, you would bundle the hospital's CA root cert here.
            verify_arg = self._prepare_tls_material()
            try:
                resp = requests.post(
                    f"{self.server_url}/api/auth/verify",
                    json={"id": doc_id, "password": password},
                    verify=verify_arg
                )
            except requests.exceptions.ConnectionError as conn_exc:
                if not self._try_local_dev_fallback(conn_exc):
                    raise
                resp = requests.post(
                    f"{self.server_url}/api/auth/verify",
                    json={"id": doc_id, "password": password},
                    verify=False,
                )

            if resp.status_code != 200:
                self.audit.warning("Login verify rejected for doctor_id=%s status=%s", doc_id, resp.status_code)
                raise Exception("Invalid credentials")
            self.audit.info("Login verify accepted for doctor_id=%s", doc_id)

            try:
                private_key = self.vault.load_identity(doc_id, password)
            except ValueError:
                private_key = None
                self.audit.info("Local vault password mismatch for doctor_id=%s; migration or recovery required", doc_id)

                choice = messagebox.askyesnocancel(
                    "Local Vault Locked",
                    "Your server password is valid, but the local vault still uses the previous password.\n\n"
                    "Yes: Enter old local password and migrate vault.\n"
                    "No: I forgot old local password (re-enroll local keys and request a new certificate).\n"
                    "Cancel: Abort login."
                )

                if choice is None:
                    self.audit.warning("Local vault migration/recovery cancelled for doctor_id=%s", doc_id)
                    raise Exception("Local vault recovery cancelled.")

                if choice is True:
                    old_local_password = ctk.CTkInputDialog(
                        text="Enter previous local vault password to migrate:",
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
                else:
                    # Lost old local password: force local re-enrollment and fresh cert issuance.
                    self.vault.delete_identity(doc_id)
                    self._clear_local_tls_assets()
                    self.audit.warning("Local vault reset for doctor_id=%s; key re-enrollment will start", doc_id)

            # If they already have keys, log them straight in
            if private_key:
                self.audit.info("Login using existing local ML-DSA identity for doctor_id=%s", doc_id)
                self.status_label.configure(text="✅ Authorized")
                self._show_success_tick(lambda: self._animate_exit_and_launch(doc_id, private_key))
                return

            # --- ONBOARDING: Generate both PQC and Classical TLS keys ---
            self.status_label.configure(text="🔑 Generating Quantum-Secure & TLS Identities...")
            self.update_idletasks()

            # 1. Generate PQC (ML-DSA) keypair
            agent_temp = SecurityAgent(log_callback=print, status_callback=print)
            pqc_priv = agent_temp.signer.get_private_bytes()
            pqc_pub = agent_temp.signer.get_public_bytes()

            # 2. Generate Classical TLS (ECDSA) keypair
            tls_private_key = ec.generate_private_key(ec.SECP256R1())
            tls_public_key_pem = tls_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            # 3. Send public keys to server for enrollment
            onboard = requests.post(
                f"{self.server_url}/api/admin/doctors/onboard", 
                json={
                    "id": doc_id,
                    "name": resp.json().get("name", "Doctor"),
                    "pqc_public_key_b64": base64.b64encode(pqc_pub).decode(),
                    "tls_public_key_pem": tls_public_key_pem
                },
                verify=verify_arg
            )

            if onboard.status_code != 200:
                self.audit.warning("Doctor onboarding rejected during login for doctor_id=%s status=%s", doc_id, onboard.status_code)
                raise Exception("Server rejected key enrollment")
            
            self.audit.info("Doctor onboarding accepted for doctor_id=%s", doc_id)

            # 4. Securely store the private keys locally
            self.vault.save_identity(doc_id, password, pqc_priv)
            self.audit.info("Local ML-DSA identity stored for doctor_id=%s", doc_id)

            # Store the TLS private key
            keys_dir = self._keys_dir()
            tls_priv_pem = tls_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(os.path.join(keys_dir, "doctor_container.key"), "wb") as f:
                f.write(tls_priv_pem)

            # 5. Start polling for the server to issue the certificate
            self.status_label.configure(text="⏳ Waiting for Admin to issue Certificate...")
            self.login_btn.pack_forget() # Hide login button to prevent double clicks
            self._poll_for_certificate(doc_id, pqc_priv)

        except Exception as e:
            self.audit.exception("Login flow error for doctor_id=%s: %s", doc_id, str(e))
            self.login_btn.configure(text="Login", state="normal")
            self.status_label.configure(text="")
            self.error_label.configure(text=f"❌ {str(e)}")
    
    def _poll_for_certificate(self, doc_id, pqc_priv):
        """Polls the server every 3 seconds until the Admin issues the cert."""
        try:
            verify_arg = self._prepare_tls_material()
            resp = requests.get(f"{self.server_url}/api/auth/my-cert/{doc_id}", verify=verify_arg)
            if resp.status_code == 200 and resp.json().get("status") == "issued":
                # Save the downloaded cert
                keys_dir = self._keys_dir()
                with open(os.path.join(keys_dir, "doctor_cert.pem"), "w") as f:
                    f.write(resp.json()["pem_data"])
                    
                self.status_label.configure(text="✅ Certificate Received!")
                self._show_success_tick(lambda: self._animate_exit_and_launch(doc_id, pqc_priv))
            else:
                # Check again in 3 seconds
                self.after(3000, lambda: self._poll_for_certificate(doc_id, pqc_priv))
        except Exception as e:
            # Network issue while polling, just keep trying
            self.audit.warning(f"Polling error for doctor_id={doc_id}: {e}")
            self.after(3000, lambda: self._poll_for_certificate(doc_id, pqc_priv))

    def _animate_exit_and_launch(self, doc_id, private_key):
        def step(alpha, y_offset):
            if alpha <= 0:
                self.withdraw()      # Hide login window

                # Create main window
                app = VaultQDoctorApp(doctor_id=doc_id, private_key=private_key, server_url=self.server_url)
                app.deiconify()
                app.lift()
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
