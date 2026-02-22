import sys
from PySide6.QtWidgets import QApplication

from doctor_app.ui.login_window import LoginWindow
from doctor_app.core.audit_logger import get_audit_logger

def main():
    audit = get_audit_logger()
    audit.info("Doctor app startup initiated")

    # 1. Initialize the Qt Application (Must be done before creating any widgets)
    app = QApplication(sys.argv)

    # 2. Instantiate and show the login window
    login = LoginWindow()
    login.show()

    # 3. Start the Qt event loop
    # The event loop will keep running when LoginWindow hides itself and 
    # opens the VaultQDoctorApp main window.
    exit_code = app.exec()

    audit.info("Doctor app shutdown cleanly")

    # 4. Ensure full process exit using the Qt execution result
    sys.exit(exit_code)

if __name__ == "__main__":
    main()