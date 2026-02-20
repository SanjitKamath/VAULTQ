import customtkinter as ctk
from doctor_app.ui.login_window import LoginWindow
from doctor_app.core.audit_logger import get_audit_logger
import sys

def main():
    audit = get_audit_logger()
    audit.info("Doctor app startup initiated")
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    login = LoginWindow()
    login.mainloop()
    audit.info("Doctor app shutdown")

    # Ensure full process exit when UI closes
    sys.exit(0)

if __name__ == "__main__":
    main()
