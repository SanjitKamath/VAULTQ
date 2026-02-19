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

        # Step 1: Check credentials with Server
        try:
            resp = requests.post(f"{config.server_url}/api/auth/verify", 
                                 json={"id": doc_id, "password": password})
            
            if resp.status_code == 200:
                # Step 2: If correct, load or generate local PQC keys
                private_key = self.vault.load_identity(doc_id, password)
                if not private_key:
                    # Generate keys only for verified users
                    agent = SecurityAgent(log_callback=print, status_callback=print)
                    private_key = agent.signer.get_private_bytes()
                    self.vault.save_identity(doc_id, password, private_key)
                
                self.destroy()
                app = VaultQDoctorApp(doctor_id=doc_id, private_key=private_key)
                app.mainloop()
            else:
                messagebox.showerror("Denied", "Incorrect ID or Password provided by Admin.")
        except Exception as e:
            messagebox.showerror("Error", "Server unreachable.")

def main():
    ctk.set_appearance_mode("dark")
    login = LoginWindow()
    login.mainloop()

if __name__ == "__main__":
    main()