import customtkinter as ctk
from doctor_app.ui.login_window import LoginWindow
import sys

def main():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    login = LoginWindow()
    login.mainloop()

    # Ensure full process exit when UI closes
    sys.exit(0)

if __name__ == "__main__":
    main()