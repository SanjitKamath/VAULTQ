import base64
import requests
import customtkinter as ctk
from tkinter import messagebox
from doctor_app.ui.main_window import VaultQDoctorApp
from doctor_app.core.keystore import LocalKeyVault
from doctor_app.core.security_agent import SecurityAgent
from doctor_app.core.config import config 

class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("VaultQ - Doctor Login")
        self.geometry("400x350")
        self.vault = LocalKeyVault()

        ctk.CTkLabel(self, text="Secure Login", font=("Roboto", 24, "bold")).pack(pady=30)

        self.id_entry = ctk.CTkEntry(self, placeholder_text="Doctor ID (e.g., doc_123)")
        self.id_entry.pack(pady=10, padx=40, fill="x")

        self.pass_entry = ctk.CTkEntry(self, placeholder_text="Password", show="*")
        self.pass_entry.pack(pady=10, padx=40, fill="x")

        ctk.CTkButton(self, text="Login / Register", command=self.attempt_login).pack(pady=20)

    def attempt_login(self):
        doc_id = self.id_entry.get().strip()
        password = self.pass_entry.get()

        try:
            # 1. Check local vault
            private_key = self.vault.load_identity(doc_id, password)
            
            if private_key:
                self.withdraw() 
                app = VaultQDoctorApp(doctor_id=doc_id, private_key=private_key)
                app.mainloop()
                self.destroy() 
                return

            # 2. Server Enrollment
            print(f"DEBUG: Attempting server enrollment for {doc_id}...")
            resp = requests.post(f"{config.server_url}/api/auth/verify", 
                                 json={"id": doc_id, "password": password})
            
            if resp.status_code == 200:
                # 3. Authorized: Generate PQC Identity
                # log_callback=print ensures we don't look for log_box yet
                agent_temp = SecurityAgent(log_callback=print, status_callback=print)
                private_key = agent_temp.signer.get_private_bytes()
                public_key = agent_temp.signer.get_public_bytes()
                
                # Sync Public Key to server FIRST, before saving locally
                # This ensures we don't get locked out if the server rejects the key
                onboard_resp = requests.post(f"{config.server_url}/api/admin/doctors/onboard", json={
                    "id": doc_id,
                    "name": resp.json().get("name", "Unknown Doctor"),
                    "pqc_public_key_b64": base64.b64encode(public_key).decode()
                })
                
                # ADDED: Check if the onboard request succeeded
                if onboard_resp.status_code != 200:
                    error_msg = f"Server rejected the public key. Status: {onboard_resp.status_code}\nDetails: {onboard_resp.text}"
                    print(f"CRITICAL ONBOARD ERROR: {error_msg}")
                    messagebox.showerror("Enrollment Failed", "Failed to sync identity with the server. Check console for details.")
                    return # Stop the login process here

                # Save to local .vault only after server confirms receipt
                self.vault.save_identity(doc_id, password, private_key)
                
                self.withdraw()
                app = VaultQDoctorApp(doctor_id=doc_id, private_key=private_key)
                app.mainloop()
                self.destroy()
            else:
                messagebox.showerror("Access Denied", "This ID/Password was not provisioned by the Hospital Admin.")
                
        except Exception as e:
            print(f"Login error: {e}")
            messagebox.showerror("Error", f"Login/Enrollment failed: {str(e)}")

def main():
    ctk.set_appearance_mode("dark")
    login = LoginWindow()
    login.mainloop()

if __name__ == "__main__":
    main()