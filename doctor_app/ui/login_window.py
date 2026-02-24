# doctor_app/ui/login_window.py
import os
import sys
import requests

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QInputDialog, QGraphicsDropShadowEffect, QFrame
)
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QParallelAnimationGroup, QPoint, Property, QRectF, QSettings
from PySide6.QtGui import QFont, QCursor, QColor, QPainter, QPen

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from security_suite.security.certificates import generate_doctor_csr_pem
from doctor_app.ui.main_window import VaultQDoctorApp
from doctor_app.core.keystore import LocalKeyVault
from doctor_app.core.security_agent import SecurityAgent
from doctor_app.core.config import config
from doctor_app.core.audit_logger import get_audit_logger

AUTH_REQUEST_TIMEOUT_SECONDS = 10
ONBOARD_REQUEST_TIMEOUT_SECONDS = 10
CERT_POLL_TIMEOUT_SECONDS = 10


class CustomTitleBar(QFrame):
    """A custom, VS Code-style frameless title bar."""
    def __init__(self, parent, title_text, is_fixed=False):
        super().__init__(parent)
        self.parent_window = parent
        self.is_fixed = is_fixed
        self.setFixedHeight(34)
        self.setObjectName("CustomTitleBar")
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 0, 0, 0)
        layout.setSpacing(0)
        
        self.title_label = QLabel(title_text)
        self.title_label.setObjectName("TitleBarText")
        layout.addWidget(self.title_label)
        
        layout.addStretch()
        
        self.min_btn = QPushButton("─")
        self.min_btn.setObjectName("TitleBtn")
        self.min_btn.clicked.connect(self.parent_window.showMinimized)
        layout.addWidget(self.min_btn)
        
        if not is_fixed:
            self.max_btn = QPushButton("□")
            self.max_btn.setObjectName("TitleBtn")
            self.max_btn.clicked.connect(self.toggle_maximize)
            layout.addWidget(self.max_btn)
        
        self.close_btn = QPushButton("✕")
        self.close_btn.setObjectName("TitleCloseBtn")
        self.close_btn.clicked.connect(self.parent_window.close)
        layout.addWidget(self.close_btn)
        
        self._start_pos = None

    def mouseDoubleClickEvent(self, event):
        if not self.is_fixed and event.button() == Qt.LeftButton:
            self.toggle_maximize()

    def toggle_maximize(self):
        if self.parent_window.isMaximized():
            self.parent_window.showNormal()
            self.max_btn.setText("□")
            self.parent_window.main_layout.setContentsMargins(12, 12, 12, 12)
        else:
            self.parent_window.main_layout.setContentsMargins(0, 0, 0, 0)
            self.parent_window.showMaximized()
            self.max_btn.setText("❐")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._start_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        if self._start_pos is not None:
            if self.parent_window.isMaximized():
                self.parent_window.showNormal()
                self.max_btn.setText("□")
                self.parent_window.main_layout.setContentsMargins(12, 12, 12, 12)
                self._start_pos = event.globalPosition().toPoint()
            
            delta = event.globalPosition().toPoint() - self._start_pos
            self.parent_window.move(self.parent_window.pos() + delta)
            self._start_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, event):
        self._start_pos = None


class AnimatedTick(QWidget):
    """A custom widget that dynamically 'draws' a modern circle and tick mark."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(60, 60)
        self._progress = 0.0

    def get_progress(self):
        return self._progress

    def set_progress(self, p):
        self._progress = p
        self.update()

    progress = Property(float, get_progress, set_progress)

    def paintEvent(self, event):
        if self._progress == 0:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        pen = QPen(QColor("#34C759"), 4.5, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        painter.setPen(pen)

        rect = QRectF(5, 5, 50, 50)
        
        circle_prog = min(self._progress * 2, 1.0)
        painter.drawArc(rect, 90 * 16, int(-360 * 16 * circle_prog))

        if self._progress > 0.5:
            tick_prog = (self._progress - 0.5) * 2
            
            p1 = QPoint(18, 32)
            p2 = QPoint(26, 40)
            p3 = QPoint(42, 22)

            if tick_prog < 0.33:
                segment_prog = tick_prog / 0.33
                current_p2 = p1 + (p2 - p1) * segment_prog
                painter.drawLine(p1, current_p2)
            else:
                painter.drawLine(p1, p2)
                segment_prog = (tick_prog - 0.33) / 0.67
                current_p3 = p2 + (p3 - p2) * segment_prog
                painter.drawLine(p2, current_p3)


class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.audit = get_audit_logger()
        self.audit.info("Doctor login window initialized")

        self.server_url = str(config.server_url).rstrip("/")
        self.pre_enroll_url = str(config.pre_enroll_url).rstrip("/")
        if not self.server_url.lower().startswith("https://"):
            raise RuntimeError("Insecure server URL blocked. Configure VAULTQ_SERVER_URL with https://")
        if not self.pre_enroll_url.lower().startswith("https://"):
            raise RuntimeError("Insecure pre-enroll URL blocked. Configure VAULTQ_PRE_ENROLL_URL with https://")

        self.vault = LocalKeyVault()
        
        # Read the global settings preference to match Main Window
        self.settings = QSettings("VaultQ", "DoctorApp")
        self.is_dark_mode = self.settings.value("theme/is_dark_mode", False, type=bool)

        self.setWindowTitle("VaultQ – Authentication")
        self.setFixedSize(460, 540) # Slightly larger to account for custom shadow margins
        
        self.setWindowOpacity(0.0)

        self._center_window()
        self._build_ui()
        self._apply_theme(self.is_dark_mode)
        
        QTimer.singleShot(50, self._animate_entrance)

    def _request_verify_arg(self):
        if not os.path.exists(config.ca_cert_path):
            raise RuntimeError(f"CA certificate not found: {config.ca_cert_path}")
        return config.ca_cert_path

    def _keys_dir(self):
        keys_dir = config.keys_dir if getattr(config, "keys_dir", None) else "doctor_app/storage/keys"
        os.makedirs(keys_dir, mode=0o700, exist_ok=True)
        return keys_dir

    def _clear_local_tls_assets(self):
        keys_dir = self._keys_dir()
        for name in ("doctor_container.key", "doctor_cert.pem"):
            path = os.path.join(keys_dir, name)
            if os.path.exists(path):
                os.remove(path)

    def _copy_server_ca_if_available(self):
        if os.path.exists(config.ca_cert_path):
            return
        server_ca = os.path.join("server_app", "storage", "certs", "hospital_root_ca.pem")
        if os.path.exists(server_ca):
            self._keys_dir()
            with open(server_ca, "rb") as src, open(config.ca_cert_path, "wb") as dst:
                dst.write(src.read())

    def _prepare_tls_material(self):
        if not str(self.server_url).lower().startswith("https://"):
            raise RuntimeError("Insecure server URL blocked. VaultQ requires HTTPS.")
        self._copy_server_ca_if_available()
        return self._request_verify_arg()

    def _sync_issued_certificate(self, doc_id: str, verify_arg: str, enroll_token: str) -> bool:
        """
        Pull latest issued cert from pre-enroll endpoint and persist locally.
        Returns True when a valid cert is present locally after sync.
        """
        resp = requests.get(
            f"{self.pre_enroll_url}/api/pre-enroll/auth/my-cert/{doc_id}",
            headers={"X-Enroll-Token": enroll_token},
            verify=verify_arg,
            timeout=CERT_POLL_TIMEOUT_SECONDS,
        )
        if resp.status_code != 200:
            return False

        payload = resp.json()
        if payload.get("status") != "issued" or not payload.get("pem_data"):
            return False

        keys_dir = self._keys_dir()
        with open(os.path.join(keys_dir, "doctor_cert.pem"), "w", encoding="utf-8") as f:
            f.write(payload["pem_data"])
        return True

    def _center_window(self):
        screen = self.screen().availableGeometry()
        self.move(
            screen.center().x() - self.width() // 2,
            screen.center().y() - self.height() // 2
        )

    def _build_ui(self):
        # Frameless outer setup
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
        root = QWidget(self)
        self.setCentralWidget(root)
        self.main_layout = QVBoxLayout(root)
        self.main_layout.setContentsMargins(12, 12, 12, 12) # Margin to render shadow
        
        # Inner Background Container (Acts as the real window)
        self.bg_container = QWidget()
        self.bg_container.setObjectName("BgContainer")
        bg_layout = QVBoxLayout(self.bg_container)
        bg_layout.setContentsMargins(0, 0, 0, 0)
        bg_layout.setSpacing(0)
        
        # Window Drop Shadow
        window_shadow = QGraphicsDropShadowEffect(self)
        window_shadow.setBlurRadius(25)
        window_shadow.setColor(QColor(0, 0, 0, 50))
        window_shadow.setOffset(0, 8)
        self.bg_container.setGraphicsEffect(window_shadow)

        # Custom VS Code-style Title Bar
        self.title_bar = CustomTitleBar(self, "VaultQ – Authentication", is_fixed=True)
        bg_layout.addWidget(self.title_bar)
        
        # Content Layout
        content_layout = QVBoxLayout()
        content_layout.setAlignment(Qt.AlignCenter)

        # Main Central Card
        self.card = QWidget()
        self.card.setObjectName("Card")
        self.card.setFixedSize(360, 440)
        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(32, 40, 32, 32)
        card_layout.setSpacing(0)

        card_shadow = QGraphicsDropShadowEffect(self)
        card_shadow.setBlurRadius(30)
        card_shadow.setColor(QColor(0, 0, 0, 15))
        card_shadow.setOffset(0, 10)
        self.card.setGraphicsEffect(card_shadow)

        title = QLabel("VaultQ")
        title.setObjectName("AppTitle")
        title.setAlignment(Qt.AlignCenter)
        
        subtitle = QLabel("Secure Workspace")
        subtitle.setObjectName("Subtitle")
        subtitle.setAlignment(Qt.AlignCenter)

        card_layout.addWidget(title)
        card_layout.addWidget(subtitle)
        card_layout.addSpacing(32)

        form_layout = QVBoxLayout()
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(0)

        self.id_entry = QLineEdit()
        self.id_entry.setPlaceholderText("Doctor ID")
        form_layout.addWidget(self.id_entry)
        
        form_layout.addSpacing(12)

        self.pass_entry = QLineEdit()
        self.pass_entry.setPlaceholderText("Password")
        self.pass_entry.setEchoMode(QLineEdit.Password)
        form_layout.addWidget(self.pass_entry)

        form_layout.addSpacing(8)

        self.forgot_btn = QPushButton("Forgot password?")
        self.forgot_btn.setCursor(QCursor(Qt.PointingHandCursor))
        self.forgot_btn.setObjectName("ForgotBtn")
        self.forgot_btn.clicked.connect(self._on_forgot_password)
        form_layout.addWidget(self.forgot_btn, alignment=Qt.AlignRight)

        form_layout.addSpacing(20)
        
        self.login_btn = QPushButton("Sign in")
        self.login_btn.setObjectName("PrimaryBtn")
        self.login_btn.setMinimumHeight(44)
        self.login_btn.setMinimumWidth(296)
        self.login_btn.setMaximumWidth(296)
        self.login_btn.setCursor(QCursor(Qt.PointingHandCursor))
        self.login_btn.clicked.connect(self.attempt_login)
        form_layout.addWidget(self.login_btn, alignment=Qt.AlignCenter)

        form_layout.addSpacing(8)

        self.msg_container = QWidget()
        self.msg_container.setFixedHeight(30)
        msg_layout = QVBoxLayout(self.msg_container)
        msg_layout.setContentsMargins(0, 0, 0, 0)
        msg_layout.setSpacing(0)
        
        self.status_label = QLabel("")
        self.status_label.setObjectName("StatusLabel")
        self.status_label.setAlignment(Qt.AlignCenter)
        
        self.error_label = QLabel("")
        self.error_label.setObjectName("ErrorLabel")
        self.error_label.setAlignment(Qt.AlignCenter)
        
        msg_layout.addWidget(self.status_label)
        msg_layout.addWidget(self.error_label)
        
        form_layout.addWidget(self.msg_container)

        self.tick_widget = AnimatedTick()
        form_layout.addWidget(self.tick_widget, alignment=Qt.AlignCenter)

        form_layout.addStretch()
        card_layout.addLayout(form_layout)
        content_layout.addWidget(self.card)
        bg_layout.addLayout(content_layout)
        
        self.main_layout.addWidget(self.bg_container)

    def _apply_theme(self, dark_mode: bool):
        font_family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
        
        if dark_mode:
            self.setStyleSheet(f"""
                QMainWindow {{ background: transparent; }}
                
                /* Main App Container */
                QWidget#BgContainer {{ 
                    background-color: #1C1C1E; 
                    border: 1px solid #38383A; 
                    border-radius: 12px; 
                }}
                
                /* Custom Title Bar */
                QFrame#CustomTitleBar {{ 
                    background-color: #242426; 
                    border-top-left-radius: 12px; 
                    border-top-right-radius: 12px; 
                }}
                QLabel#TitleBarText {{ color: #F2F2F7; font-family: {font_family}; font-size: 13px; font-weight: 500; }}
                QPushButton#TitleBtn {{ color: #8E8E93; border: none; background: transparent; font-size: 14px; width: 46px; height: 34px; }}
                QPushButton#TitleBtn:hover {{ background-color: #3A3A3C; color: #FFFFFF; }}
                QPushButton#TitleCloseBtn {{ color: #8E8E93; border: none; background: transparent; font-size: 14px; width: 46px; height: 34px; border-top-right-radius: 12px; }}
                QPushButton#TitleCloseBtn:hover {{ background-color: #FF453A; color: #FFFFFF; }}
                
                /* Login Card */
                QWidget#Card {{ 
                    background: #2C2C2E; 
                    border: 1px solid #38383A;
                    border-radius: 16px; 
                }}
                QLabel#AppTitle {{ color: #FFFFFF; font-family: {font_family}; font-size: 28px; font-weight: 800; letter-spacing: -0.5px; }}
                QLabel#Subtitle {{ color: #A1A1AA; font-size: 13px; margin-top: -4px; font-family: {font_family}; }}
                
                /* Fixed Font Colors for Dark Mode */
                QLineEdit {{ 
                    min-height: 42px;
                    padding: 0 14px; 
                    background: #1C1C1E; 
                    color: #FFFFFF; 
                    border: 1px solid #48484A; 
                    border-radius: 8px; 
                    font-size: 14px;
                    font-family: {font_family};
                }}
                QLineEdit:focus {{ border: 1.5px solid #0A84FF; background: #242426; }}
                
                QPushButton#PrimaryBtn {{ 
                    background-color: #0A84FF; 
                    color: #FFFFFF; 
                    border: none; 
                    border-radius: 8px; 
                    font-size: 15px;
                    font-weight: 600;
                    font-family: {font_family};
                }}
                QPushButton#PrimaryBtn:hover {{ background-color: #007AFF; }}
                QPushButton#PrimaryBtn:disabled {{ background-color: #3A3A3C; color: #636366; }}
                QPushButton#PrimaryBtn[state="error"], QPushButton#PrimaryBtn[state="error"]:disabled {{ 
                    background-color: #FF453A; 
                    color: #FFFFFF; 
                }}
                QPushButton#PrimaryBtn[state="success"], QPushButton#PrimaryBtn[state="success"]:disabled {{ 
                    background-color: #32D74B; 
                    color: #FFFFFF; 
                }}
                
                QPushButton#ForgotBtn {{ 
                    color: #A1A1AA; 
                    background: transparent; 
                    border: none; 
                    font-size: 13px;
                    padding: 0;
                    margin: 0;
                    font-family: {font_family};
                }}
                QPushButton#ForgotBtn:hover {{ color: #FFFFFF; text-decoration: underline; }}
                
                QLabel#StatusLabel {{ color: #A1A1AA; font-size: 12px; font-family: {font_family}; }}
                QLabel#ErrorLabel {{ color: #FF453A; font-size: 13px; font-family: {font_family}; }}
            """)
        else:
            self.setStyleSheet(f"""
                QMainWindow {{ background: transparent; }}
                
                /* Main App Container */
                QWidget#BgContainer {{ 
                    background-color: #F5F5F7; 
                    border: 1px solid #D1D1D6; 
                    border-radius: 12px; 
                }}
                
                /* Custom Title Bar */
                QFrame#CustomTitleBar {{ 
                    background-color: #E5E5EA; 
                    border-top-left-radius: 12px; 
                    border-top-right-radius: 12px; 
                }}
                QLabel#TitleBarText {{ color: #000000; font-family: {font_family}; font-size: 13px; font-weight: 500; }}
                QPushButton#TitleBtn {{ color: #6B7280; border: none; background: transparent; font-size: 14px; width: 46px; height: 34px; }}
                QPushButton#TitleBtn:hover {{ background-color: #D1D1D6; color: #1D1D1F; }}
                QPushButton#TitleCloseBtn {{ color: #6B7280; border: none; background: transparent; font-size: 14px; width: 46px; height: 34px; border-top-right-radius: 12px; }}
                QPushButton#TitleCloseBtn:hover {{ background-color: #FF3B30; color: #FFFFFF; }}

                /* Login Card */
                QWidget#Card {{ 
                    background: #FFFFFF; 
                    border: 1px solid #E4E4E7;
                    border-radius: 16px; 
                }}
                QLabel#AppTitle {{ color: #111827; font-family: {font_family}; font-size: 28px; font-weight: 800; letter-spacing: -0.5px; }}
                QLabel#Subtitle {{ color: #6B7280; font-size: 13px; margin-top: -4px; font-family: {font_family}; }}
                
                QLineEdit {{ 
                    min-height: 42px;
                    padding: 0 14px; 
                    background: #FFFFFF; 
                    color: #111827; 
                    border: 1px solid #D1D5DB; 
                    border-radius: 8px; 
                    font-size: 14px;
                    font-family: {font_family};
                }}
                QLineEdit:focus {{ border: 1.5px solid #007AFF; }}
                
                QPushButton#PrimaryBtn {{ 
                    background-color: #007AFF; 
                    color: #FFFFFF; 
                    border: none; 
                    border-radius: 8px; 
                    font-size: 15px;
                    font-weight: 600;
                    font-family: {font_family};
                }}
                QPushButton#PrimaryBtn:hover {{ background-color: #0056B3; }}
                QPushButton#PrimaryBtn:disabled {{ background-color: #E5E5EA; color: #8E8E93; }}
                QPushButton#PrimaryBtn[state="error"], QPushButton#PrimaryBtn[state="error"]:disabled {{ 
                    background-color: #FF3B30; 
                    color: #FFFFFF; 
                }}
                QPushButton#PrimaryBtn[state="success"], QPushButton#PrimaryBtn[state="success"]:disabled {{ 
                    background-color: #34C759; 
                    color: #FFFFFF; 
                }}
                
                QPushButton#ForgotBtn {{ 
                    color: #FFFFFF; 
                    background: transparent; 
                    border: none; 
                    font-size: 13px;
                    padding: 0;
                    margin: 0;
                    font-family: {font_family};
                }}
                QPushButton#ForgotBtn:hover {{ color: #111827; text-decoration: underline; }}
                
                QLabel#StatusLabel {{ color: #6B7280; font-size: 12px; font-family: {font_family}; }}
                QLabel#ErrorLabel {{ color: #FF3B30; font-size: 13px; font-family: {font_family}; }}
            """)

    def _animate_entrance(self):
        self.move_anim = QPropertyAnimation(self, b"pos")
        self.move_anim.setDuration(700)
        self.move_anim.setStartValue(self.pos() + QPoint(0, 15))
        self.move_anim.setEndValue(self.pos())
        self.move_anim.setEasingCurve(QEasingCurve.OutCubic)

        self.fade_anim = QPropertyAnimation(self, b"windowOpacity")
        self.fade_anim.setDuration(700)
        self.fade_anim.setStartValue(0.0)
        self.fade_anim.setEndValue(1.0)
        self.fade_anim.setEasingCurve(QEasingCurve.OutCubic)

        self.entrance_group = QParallelAnimationGroup()
        self.entrance_group.addAnimation(self.move_anim)
        self.entrance_group.addAnimation(self.fade_anim)
        self.entrance_group.start()

    def _show_error_state(self, error_msg):
        self.status_label.setText("")
        self.error_label.setText(error_msg)
        
        self.login_btn.setProperty("state", "error")
        self.login_btn.setText("Authentication Failed")
        self.login_btn.style().unpolish(self.login_btn)
        self.login_btn.style().polish(self.login_btn)
        
        QTimer.singleShot(2500, self._reset_to_normal)

    def _reset_to_normal(self):
        self.login_btn.setEnabled(True)
        self.login_btn.setProperty("state", "")
        self.login_btn.setText("Sign in")
        self.login_btn.style().unpolish(self.login_btn)
        self.login_btn.style().polish(self.login_btn)
        self.error_label.setText("")

    def _animate_success_state(self, callback):
        self.status_label.setText("")
        self.error_label.setText("")
        
        self.login_btn.setText("Verified")
        self.login_btn.setProperty("state", "success")
        self.login_btn.style().unpolish(self.login_btn)
        self.login_btn.style().polish(self.login_btn)
        self.login_btn.setCursor(QCursor(Qt.ArrowCursor))

        self.tick_anim = QPropertyAnimation(self.tick_widget, b"progress")
        self.tick_anim.setDuration(550)
        self.tick_anim.setStartValue(0.0)
        self.tick_anim.setEndValue(1.0)
        self.tick_anim.setEasingCurve(QEasingCurve.InOutQuad)
        
        self.tick_anim.finished.connect(lambda: QTimer.singleShot(600, callback))
        self.tick_anim.start()

    def _animate_exit_and_launch(self, doc_id, private_key, enroll_token=""):
        self.exit_fade = QPropertyAnimation(self, b"windowOpacity")
        self.exit_fade.setDuration(400)
        self.exit_fade.setEndValue(0.0)
        
        self.exit_move = QPropertyAnimation(self, b"pos")
        self.exit_move.setDuration(400)
        self.exit_move.setEndValue(self.pos() + QPoint(0, 20))
        self.exit_move.setEasingCurve(QEasingCurve.InCubic)
        
        self.exit_group = QParallelAnimationGroup()
        self.exit_group.addAnimation(self.exit_fade)
        self.exit_group.addAnimation(self.exit_move)
        
        self.exit_group.finished.connect(lambda: self._launch_main_app(doc_id, private_key, enroll_token))
        self.exit_group.start()

    def _launch_main_app(self, doc_id, private_key, enroll_token=""):
        self.hide()
        self._main_app = VaultQDoctorApp(
            doctor_id=doc_id,
            private_key=private_key,
            server_url=self.server_url,
            enroll_token=enroll_token,
        )
        self._main_app.setWindowOpacity(0.0)
        self._main_app.show()
        
        self.main_fade = QPropertyAnimation(self._main_app, b"windowOpacity")
        self.main_fade.setDuration(500)
        self.main_fade.setEndValue(1.0)
        self.main_fade.setEasingCurve(QEasingCurve.OutQuad)
        self.main_fade.start()

    def closeEvent(self, event):
        self.hide()
        sys.exit(0)

    def _on_forgot_password(self):
        self.audit.info("Forgot password triggered on login screen")
        QMessageBox.information(
            self,
            "Password Recovery",
            "To maintain quantum-grade security, passwords cannot be reset locally.\n\n"
            "Please contact the Administrator to issue a server reset and re-enroll credentials."
        )

    def attempt_login(self):
        self.error_label.setText("")
        doc_id = self.id_entry.text().strip()
        password = self.pass_entry.text()
        self.audit.info("Login attempt started for doctor_id=%s", doc_id)

        if not doc_id or not password:
            self._show_error_state("Please enter both ID and password.")
            return

        self.login_btn.setText("Authenticating...")
        self.login_btn.setEnabled(False)
        self.status_label.setText("Verifying credentials...")

        QTimer.singleShot(100, lambda: self._perform_login(doc_id, password))

    def _perform_login(self, doc_id, password):
        try:
            self.audit.info("Login verify request sent for doctor_id=%s", doc_id)
            verify_arg = self._prepare_tls_material()

            resp = requests.post(
                f"{self.pre_enroll_url}/api/pre-enroll/auth/verify",
                json={"id": doc_id, "password": password},
                verify=verify_arg,
                timeout=AUTH_REQUEST_TIMEOUT_SECONDS,
            )

            if resp.status_code != 200:
                self.audit.warning("Login verify rejected for doctor_id=%s status=%s", doc_id, resp.status_code)
                raise Exception("Invalid credentials")
            verify_body = resp.json()
            enroll_token = (verify_body.get("enroll_token") or "").strip()
            if not enroll_token:
                raise Exception("Enrollment token missing from auth response.")
            self.audit.info("Login verify accepted for doctor_id=%s", doc_id)

            try:
                private_key = self.vault.load_identity(doc_id, password)
            except ValueError:
                private_key = None
                self.audit.info("Local vault password mismatch for doctor_id=%s", doc_id)

                choice = QMessageBox.question(
                    self,
                    "Local Vault Locked",
                    "Your server password is valid, but the local vault still uses the previous password.\n\n"
                    "Yes: Enter old local password and migrate vault.\n"
                    "No: I forgot old local password (re-enroll local keys and request a new certificate).\n"
                    "Cancel: Abort login.",
                    QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel
                )

                if choice == QMessageBox.Cancel:
                    raise Exception("Local vault recovery cancelled.")

                if choice == QMessageBox.Yes:
                    old_local_password, ok = QInputDialog.getText(
                        self, "Migrate Local Vault", "Enter previous local vault password to migrate:", QLineEdit.Password
                    )
                    if not ok or not old_local_password:
                        raise Exception("Local vault migration cancelled.")

                    self.vault.change_password(doc_id, old_local_password, password)
                    private_key = self.vault.load_identity(doc_id, password)
                    
                    if not private_key:
                        raise Exception("Local vault migration failed.")
                else:
                    self.vault.delete_identity(doc_id)
                    self._clear_local_tls_assets()

            if private_key:
                self.audit.info("Login using existing local ML-DSA identity for doctor_id=%s", doc_id)
                if not self._sync_issued_certificate(doc_id, verify_arg, enroll_token):
                    raise Exception(
                        "No active certificate available for this doctor. "
                        "Ask Admin to issue/refresh certificate, then sign in again."
                    )
                self._animate_success_state(lambda: self._animate_exit_and_launch(doc_id, private_key, enroll_token))
                return

            self.status_label.setText("Generating Quantum-Secure Identities...")
            QApplication.processEvents()

            agent_temp = SecurityAgent(log_callback=print, status_callback=print)
            pqc_priv = agent_temp.signer.get_private_bytes()
            pqc_pub = agent_temp.signer.get_public_bytes()

            tls_private_key = ec.generate_private_key(ec.SECP256R1())
            csr_pem = generate_doctor_csr_pem(
                doctor_id=doc_id,
                doctor_name=verify_body.get("name", "Doctor"),
                doctor_pqc_public_bytes=pqc_pub,
                doctor_tls_private_key=tls_private_key,
            )
            onboard = requests.post(
                f"{self.pre_enroll_url}/api/pre-enroll/doctors/onboard",
                json={"id": doc_id, "csr_pem": csr_pem},
                headers={"X-Enroll-Token": enroll_token},
                verify=verify_arg,
                timeout=ONBOARD_REQUEST_TIMEOUT_SECONDS,
            )

            if onboard.status_code != 200:
                raise Exception("Server rejected key enrollment")

            self.vault.save_identity(doc_id, password, pqc_priv)

            keys_dir = self._keys_dir()
            tls_priv_pem = tls_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(os.path.join(keys_dir, "doctor_container.key"), "wb") as f:
                f.write(tls_priv_pem)

            self.status_label.setText("Waiting for Administrator Approval...")
            self.login_btn.setText("Enrolling...")
            self._poll_for_certificate(doc_id, pqc_priv, enroll_token)

        except requests.exceptions.Timeout:
            self._show_error_state("Request timed out. Please try again.")
        except requests.exceptions.RequestException as e:
            self._show_error_state(f"Network error: {str(e)}")
        except Exception as e:
            self._show_error_state(f"Error: {str(e)}")

    def _poll_for_certificate(self, doc_id, pqc_priv, enroll_token):
        try:
            verify_arg = self._prepare_tls_material()
            resp = requests.get(
                f"{self.pre_enroll_url}/api/pre-enroll/auth/my-cert/{doc_id}",
                headers={"X-Enroll-Token": enroll_token},
                verify=verify_arg,
                timeout=CERT_POLL_TIMEOUT_SECONDS,
            )

            if resp.status_code == 200 and resp.json().get("status") == "issued":
                keys_dir = self._keys_dir()
                with open(os.path.join(keys_dir, "doctor_cert.pem"), "w") as f:
                    f.write(resp.json()["pem_data"])
                
                self._animate_success_state(lambda: self._animate_exit_and_launch(doc_id, pqc_priv, enroll_token))
            else:
                QTimer.singleShot(3000, lambda: self._poll_for_certificate(doc_id, pqc_priv, enroll_token))
        except Exception:
            QTimer.singleShot(3000, lambda: self._poll_for_certificate(doc_id, pqc_priv, enroll_token))
