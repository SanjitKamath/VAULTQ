# doctor_app/ui/main_window.py
import os
import json
import time
import queue
import requests

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QFileDialog, QTabWidget,
    QPlainTextEdit, QMessageBox, QDialog, QFormLayout, QDialogButtonBox,
    QFrame, QProgressBar, QListWidget, QListWidgetItem, QGraphicsOpacityEffect, QSizeGrip, QTextEdit
)
from PySide6.QtCore import Qt, QTimer, Signal, QPropertyAnimation, QEasingCurve, QSettings, QPoint, QParallelAnimationGroup
from PySide6.QtGui import QFont, QCursor, QColor, QTextCursor
from PySide6.QtWidgets import QGraphicsDropShadowEffect

from doctor_app.core.config import config
from doctor_app.core.models import UploadForm
from doctor_app.core.security_agent import SecurityAgent
from doctor_app.core.keystore import LocalKeyVault


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
        
        # Using native Windows Segoe Fluent Icons for pixel-perfect title buttons
        self.min_btn = QPushButton("\uE921")
        self.min_btn.setObjectName("TitleBtn")
        self.min_btn.clicked.connect(self.parent_window.showMinimized)
        layout.addWidget(self.min_btn)
        
        if not is_fixed:
            self.max_btn = QPushButton("\uE922")
            self.max_btn.setObjectName("TitleBtn")
            self.max_btn.clicked.connect(self.toggle_maximize)
            layout.addWidget(self.max_btn)
        
        self.close_btn = QPushButton("\uE8BB")
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
            self.max_btn.setText("\uE922")
            self.parent_window.main_layout.setContentsMargins(12, 12, 12, 12)
        else:
            self.parent_window.main_layout.setContentsMargins(0, 0, 0, 0)
            self.parent_window.showMaximized()
            self.max_btn.setText("\uE923")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._start_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        if self._start_pos is not None:
            if self.parent_window.isMaximized():
                self.parent_window.showNormal()
                self.max_btn.setText("\uE922")
                self.parent_window.main_layout.setContentsMargins(12, 12, 12, 12)
                self._start_pos = event.globalPosition().toPoint()
            
            delta = event.globalPosition().toPoint() - self._start_pos
            self.parent_window.move(self.parent_window.pos() + delta)
            self._start_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, event):
        self._start_pos = None


class FileDropZone(QFrame):
    file_dropped = Signal(str)
    clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setObjectName("DropZone")
        self.setCursor(QCursor(Qt.PointingHandCursor))
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        
        self.icon_label = QLabel("📄")
        self.icon_label.setFont(QFont("Segoe UI", 32))
        self.icon_label.setAlignment(Qt.AlignCenter)
        self.icon_label.setObjectName("DropIcon")
        
        self.text_label = QLabel("Drag & Drop your record here\nor click to browse")
        self.text_label.setAlignment(Qt.AlignCenter)
        self.text_label.setObjectName("DropText")
        
        layout.addWidget(self.icon_label)
        layout.addWidget(self.text_label)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setProperty("dragHover", True)
            self.style().unpolish(self)
            self.style().polish(self)

    def dragLeaveEvent(self, event):
        self.setProperty("dragHover", False)
        self.style().unpolish(self)
        self.style().polish(self)

    def dropEvent(self, event):
        self.setProperty("dragHover", False)
        self.style().unpolish(self)
        self.style().polish(self)
        
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.file_dropped.emit(file_path)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()


class PasswordChangeDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent_app = parent
        self.is_dark_mode = parent.is_dark_mode
        
        # Frameless window setup for custom shadow and title bar
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
        # Increased size significantly to prevent text clipping
        self.setFixedSize(480, 340)
        
        # Start completely transparent for the entrance animation
        self.setWindowOpacity(0.0)

        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(16, 16, 16, 16)

        # Background container for shadow
        self.bg_container = QWidget()
        self.bg_container.setObjectName("BgContainer")
        bg_layout = QVBoxLayout(self.bg_container)
        bg_layout.setContentsMargins(0, 0, 0, 0)
        bg_layout.setSpacing(0)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(25)
        shadow.setColor(QColor(0, 0, 0, 50))
        shadow.setOffset(0, 8)
        self.bg_container.setGraphicsEffect(shadow)

        # Custom Title Bar
        self.title_bar = QFrame()
        self.title_bar.setObjectName("CustomTitleBar")
        self.title_bar.setFixedHeight(34)
        tb_layout = QHBoxLayout(self.title_bar)
        tb_layout.setContentsMargins(16, 0, 0, 0)
        tb_layout.setSpacing(0)

        self.title_label = QLabel("Change Password")
        self.title_label.setObjectName("TitleBarText")
        tb_layout.addWidget(self.title_label)
        tb_layout.addStretch()

        self.close_btn = QPushButton("\uE8BB")
        self.close_btn.setObjectName("TitleCloseBtn")
        self.close_btn.clicked.connect(self.reject)
        tb_layout.addWidget(self.close_btn)
        
        bg_layout.addWidget(self.title_bar)

        # Content Layout
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(28, 28, 28, 28)
        content_layout.setSpacing(20)

        form_layout = QFormLayout()
        form_layout.setVerticalSpacing(16)
        form_layout.setHorizontalSpacing(16)

        self.old = QLineEdit()
        self.old.setEchoMode(QLineEdit.Password)
        self.new = QLineEdit()
        self.new.setEchoMode(QLineEdit.Password)
        self.confirm = QLineEdit()
        self.confirm.setEchoMode(QLineEdit.Password)

        form_layout.addRow(QLabel("Current password:"), self.old)
        form_layout.addRow(QLabel("New password:"), self.new)
        form_layout.addRow(QLabel("Confirm password:"), self.confirm)

        content_layout.addLayout(form_layout)
        content_layout.addStretch()

        # Custom Button Box
        btn_layout = QHBoxLayout()
        btn_layout.setContentsMargins(0, 0, 0, 0)
        btn_layout.setSpacing(12)
        btn_layout.addStretch()
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("SecondaryBtn")
        self.cancel_btn.clicked.connect(self.reject)
        
        self.save_btn = QPushButton("Save Password")
        self.save_btn.setObjectName("PrimaryBtn")
        self.save_btn.clicked.connect(self.validate_and_accept)
        
        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addWidget(self.save_btn)
        
        content_layout.addLayout(btn_layout)
        bg_layout.addLayout(content_layout)

        self.main_layout.addWidget(self.bg_container)

        self._apply_theme()
        self._start_pos = None

    # ---- Animations & Window Events ----

    def showEvent(self, event):
        super().showEvent(event)
        self._animate_entrance()

    def _animate_entrance(self):
        self.move_anim = QPropertyAnimation(self, b"pos")
        self.move_anim.setDuration(400)
        self.move_anim.setStartValue(self.pos() + QPoint(0, 15))
        self.move_anim.setEndValue(self.pos())
        self.move_anim.setEasingCurve(QEasingCurve.OutCubic)

        self.fade_anim = QPropertyAnimation(self, b"windowOpacity")
        self.fade_anim.setDuration(400)
        self.fade_anim.setStartValue(0.0)
        self.fade_anim.setEndValue(1.0)
        self.fade_anim.setEasingCurve(QEasingCurve.OutCubic)

        self.entrance_group = QParallelAnimationGroup()
        self.entrance_group.addAnimation(self.move_anim)
        self.entrance_group.addAnimation(self.fade_anim)
        self.entrance_group.start()

    def _animate_exit(self, callback):
        # Disable buttons to prevent double clicks while animating
        self.save_btn.setEnabled(False)
        self.cancel_btn.setEnabled(False)
        self.close_btn.setEnabled(False)

        self.exit_move = QPropertyAnimation(self, b"pos")
        self.exit_move.setDuration(300)
        self.exit_move.setEndValue(self.pos() + QPoint(0, 15))
        self.exit_move.setEasingCurve(QEasingCurve.InCubic)

        self.exit_fade = QPropertyAnimation(self, b"windowOpacity")
        self.exit_fade.setDuration(300)
        self.exit_fade.setEndValue(0.0)
        self.exit_fade.setEasingCurve(QEasingCurve.InCubic)

        self.exit_group = QParallelAnimationGroup()
        self.exit_group.addAnimation(self.exit_move)
        self.exit_group.addAnimation(self.exit_fade)
        
        self.exit_group.finished.connect(callback)
        self.exit_group.start()

    def accept(self):
        # Prevent multiple triggers
        if getattr(self, "_is_closing", False):
            return
        self._is_closing = True
        
        # Safely route the accept signal directly to QDialog
        self._animate_exit(lambda: QDialog.accept(self))

    def reject(self):
        # Prevent multiple triggers
        if getattr(self, "_is_closing", False):
            return
        self._is_closing = True
        
        # Safely route the reject signal directly to QDialog
        self._animate_exit(lambda: QDialog.reject(self))

    # Enable dragging the dialog by clicking the top area
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and event.position().y() < 34:
            self._start_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        if self._start_pos is not None:
            delta = event.globalPosition().toPoint() - self._start_pos
            self.move(self.pos() + delta)
            self._start_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, event):
        self._start_pos = None

    # ---- Logic ----

    def validate_and_accept(self):
        old_pass = self.old.text()
        new_pass = self.new.text()
        conf_pass = self.confirm.text()

        if not old_pass or not new_pass or not conf_pass:
            ModernMessageBox(self, "Invalid Input", "All password fields are required.", is_error=True).exec()
            return
        if new_pass != conf_pass:
            ModernMessageBox(self, "Password Mismatch", "New passwords do not match.", is_error=True).exec()
            return

        self.accept()

    def get_result(self):
        if self.exec() != QDialog.Accepted:
            return None
        return self.old.text(), self.new.text(), self.confirm.text()

    def _apply_theme(self):
        font_family = '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
        
        if self.is_dark_mode:
            self.setStyleSheet(f"""
                QDialog {{ background: transparent; }}
                
                QWidget#BgContainer {{ 
                    background-color: #1C1C1E; 
                    border: 1px solid #38383A; 
                    border-radius: 12px; 
                }}
                
                QFrame#CustomTitleBar {{ 
                    background-color: #242426; 
                    border-top-left-radius: 12px; 
                    border-top-right-radius: 12px; 
                }}
                QLabel#TitleBarText {{ color: #EBEBF5; font-family: {font_family}; font-size: 13px; font-weight: 600; }}
                QPushButton#TitleCloseBtn {{ color: #8E8E93; border: none; background: transparent; font-size: 11px; font-family: "Segoe Fluent Icons", "Segoe MDL2 Assets", sans-serif; min-width: 46px; max-width: 46px; min-height: 34px; max-height: 34px; padding: 0; margin: 0; border-radius: 0; border-top-right-radius: 12px; }}
                QPushButton#TitleCloseBtn:hover {{ background-color: #FF453A; color: #FFFFFF; }}

                QLabel {{ color: #EBEBF5; font-family: {font_family}; font-size: 14px; font-weight: 500; }}
                
                /* Added min-height to prevent password dot clipping */
                QLineEdit {{ 
                    min-height: 38px;
                    padding: 0px 14px; 
                    background: #1C1C1E; 
                    color: #EBEBF5; 
                    border: 1px solid #38383A; 
                    border-radius: 6px; 
                    font-size: 14px;
                    font-family: {font_family};
                }}
                QLineEdit:focus {{ border: 1px solid #0A84FF; background: #242426; }}

                QPushButton {{
                    min-height: 36px;
                    padding: 6px 20px;
                    border-radius: 6px;
                    font-size: 14px;
                    font-weight: 600;
                    font-family: {font_family};
                }}
                
                QPushButton#SecondaryBtn {{
                    background-color: #3A3A3C;
                    color: #EBEBF5;
                    border: 1px solid #48484A;
                }}
                QPushButton#SecondaryBtn:hover {{ background-color: #48484A; border-color: #636366; }}

                QPushButton#PrimaryBtn {{
                    background-color: #0A84FF;
                    color: white;
                    border: none;
                }}
                QPushButton#PrimaryBtn:hover {{ background-color: #007AFF; }}
            """)
        else:
            self.setStyleSheet(f"""
                QDialog {{ background: transparent; }}
                
                QWidget#BgContainer {{ 
                    background-color: #F5F5F7; 
                    border: 1px solid #D1D1D6; 
                    border-radius: 12px; 
                }}
                
                QFrame#CustomTitleBar {{ 
                    background-color: #E5E5EA; 
                    border-top-left-radius: 12px; 
                    border-top-right-radius: 12px; 
                }}
                QLabel#TitleBarText {{ color: #111827; font-family: {font_family}; font-size: 13px; font-weight: 600; }}
                QPushButton#TitleCloseBtn {{ color: #6B7280; border: none; background: transparent; font-size: 11px; font-family: "Segoe Fluent Icons", "Segoe MDL2 Assets", sans-serif; min-width: 46px; max-width: 46px; min-height: 34px; max-height: 34px; padding: 0; margin: 0; border-radius: 0; border-top-right-radius: 12px; }}
                QPushButton#TitleCloseBtn:hover {{ background-color: #FF3B30; color: #FFFFFF; }}

                QLabel {{ color: #1D1D1F; font-family: {font_family}; font-size: 14px; font-weight: 500; }}
                
                /* Added min-height to prevent password dot clipping */
                QLineEdit {{ 
                    min-height: 38px;
                    padding: 0px 14px; 
                    background: #FFFFFF; 
                    color: #1D1D1F; 
                    border: 1px solid #D1D1D6; 
                    border-radius: 6px; 
                    font-size: 14px;
                    font-family: {font_family};
                }}
                QLineEdit:focus {{ border: 1px solid #007AFF; }}

                QPushButton {{
                    min-height: 36px;
                    padding: 6px 20px;
                    border-radius: 6px;
                    font-size: 14px;
                    font-weight: 600;
                    font-family: {font_family};
                }}
                
                QPushButton#SecondaryBtn {{
                    background-color: #FFFFFF;
                    color: #1D1D1F;
                    border: 1px solid #D1D1D6;
                }}
                QPushButton#SecondaryBtn:hover {{ background-color: #F2F2F7; border-color: #C7C7CC; }}

                QPushButton#PrimaryBtn {{
                    background-color: #007AFF;
                    color: white;
                    border: none;
                }}
                QPushButton#PrimaryBtn:hover {{ background-color: #0056B3; }}
            """)

class ModernMessageBox(QDialog):
    """A custom styled message box to replace the ugly native OS popups."""
    def __init__(self, parent, title, message, is_error=False):
        super().__init__(parent)
        self.is_dark_mode = parent.is_dark_mode
        self.is_error = is_error
        
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(380, 200)
        self.setWindowOpacity(0.0)

        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(12, 12, 12, 12)

        self.bg_container = QWidget()
        self.bg_container.setObjectName("BgContainer")
        bg_layout = QVBoxLayout(self.bg_container)
        bg_layout.setContentsMargins(0, 0, 0, 0)
        bg_layout.setSpacing(0)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(25)
        shadow.setColor(QColor(0, 0, 0, 50))
        shadow.setOffset(0, 8)
        self.bg_container.setGraphicsEffect(shadow)

        # Reuse your CustomTitleBar!
        self.title_bar = CustomTitleBar(self, title, is_fixed=True)
        bg_layout.addWidget(self.title_bar)

        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(24, 24, 24, 24)
        
        self.msg_label = QLabel(message)
        self.msg_label.setWordWrap(True)
        self.msg_label.setAlignment(Qt.AlignCenter)
        content_layout.addWidget(self.msg_label)
        
        content_layout.addStretch()

        btn_layout = QHBoxLayout()
        btn_layout.setAlignment(Qt.AlignCenter)
        self.ok_btn = QPushButton("OK")
        self.ok_btn.setObjectName("ErrorBtn" if is_error else "PrimaryBtn")
        self.ok_btn.setMinimumHeight(36)
        self.ok_btn.setMinimumWidth(120)
        self.ok_btn.clicked.connect(self.accept)
        btn_layout.addWidget(self.ok_btn)

        content_layout.addLayout(btn_layout)
        bg_layout.addLayout(content_layout)
        self.main_layout.addWidget(self.bg_container)

        self._apply_theme()
        QTimer.singleShot(10, self._animate_entrance)

    def _animate_entrance(self):
        self.move_anim = QPropertyAnimation(self, b"pos")
        self.move_anim.setDuration(300)
        self.move_anim.setStartValue(self.pos() + QPoint(0, 15))
        self.move_anim.setEndValue(self.pos())
        self.move_anim.setEasingCurve(QEasingCurve.OutCubic)

        self.fade_anim = QPropertyAnimation(self, b"windowOpacity")
        self.fade_anim.setDuration(300)
        self.fade_anim.setStartValue(0.0)
        self.fade_anim.setEndValue(1.0)
        self.fade_anim.start()
        self.move_anim.start()

    def accept(self):
        self.fade_out = QPropertyAnimation(self, b"windowOpacity")
        self.fade_out.setDuration(200)
        self.fade_out.setEndValue(0.0)
        self.fade_out.finished.connect(lambda: QDialog.accept(self))
        self.fade_out.start()

    def _apply_theme(self):
        font_family = '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
        if self.is_dark_mode:
            self.setStyleSheet(f"""
                QDialog {{ background: transparent; }}
                QWidget#BgContainer {{ background-color: #1C1C1E; border: 1px solid #38383A; border-radius: 12px; }}
                QFrame#CustomTitleBar {{ background-color: #242426; border-top-left-radius: 12px; border-top-right-radius: 12px; }}
                QLabel#TitleBarText {{ color: #EBEBF5; font-family: {font_family}; font-size: 13px; font-weight: 600; }}
                QPushButton#TitleCloseBtn {{ color: #8E8E93; border: none; background: transparent; font-size: 11px; font-family: "Segoe Fluent Icons", "Segoe MDL2 Assets", sans-serif; min-width: 46px; max-width: 46px; min-height: 34px; max-height: 34px; border-top-right-radius: 12px; }}
                QPushButton#TitleCloseBtn:hover {{ background-color: #FF453A; color: #FFFFFF; }}
                QLabel {{ color: #EBEBF5; font-family: {font_family}; font-size: 14px; font-weight: 500; }}
                QPushButton {{ border-radius: 6px; font-size: 14px; font-weight: 600; font-family: {font_family}; }}
                QPushButton#PrimaryBtn {{ background-color: #0A84FF; color: white; border: none; }}
                QPushButton#PrimaryBtn:hover {{ background-color: #007AFF; }}
                QPushButton#ErrorBtn {{ background-color: #FF453A; color: white; border: none; }}
                QPushButton#ErrorBtn:hover {{ background-color: #FF3B30; }}
            """)
        else:
            self.setStyleSheet(f"""
                QDialog {{ background: transparent; }}
                QWidget#BgContainer {{ background-color: #F5F5F7; border: 1px solid #D1D1D6; border-radius: 12px; }}
                QFrame#CustomTitleBar {{ background-color: #E5E5EA; border-top-left-radius: 12px; border-top-right-radius: 12px; }}
                QLabel#TitleBarText {{ color: #111827; font-family: {font_family}; font-size: 13px; font-weight: 600; }}
                QPushButton#TitleCloseBtn {{ color: #6B7280; border: none; background: transparent; font-size: 11px; font-family: "Segoe Fluent Icons", "Segoe MDL2 Assets", sans-serif; min-width: 46px; max-width: 46px; min-height: 34px; max-height: 34px; border-top-right-radius: 12px; }}
                QPushButton#TitleCloseBtn:hover {{ background-color: #FF3B30; color: #FFFFFF; }}
                QLabel {{ color: #1D1D1F; font-family: {font_family}; font-size: 14px; font-weight: 500; }}
                QPushButton {{ border-radius: 6px; font-size: 14px; font-weight: 600; font-family: {font_family}; }}
                QPushButton#PrimaryBtn {{ background-color: #007AFF; color: white; border: none; }}
                QPushButton#PrimaryBtn:hover {{ background-color: #0056B3; }}
                QPushButton#ErrorBtn {{ background-color: #FF3B30; color: white; border: none; }}
                QPushButton#ErrorBtn:hover {{ background-color: #D32F2F; }}
            """)
    
class VaultQDoctorApp(QMainWindow):
    def __init__(self, doctor_id: str, private_key: bytes, server_url: str = None, enroll_token: str = ""):
        super().__init__()
        self.doctor_id = doctor_id
        self.vault = LocalKeyVault()
        self.selected_file_path = None
        self._closing = False
        
        self.settings = QSettings("VaultQ", "DoctorApp")
        self.is_dark_mode = self.settings.value("theme/is_dark_mode", False, type=bool)

        self._log_history = []

        clean_url = (server_url or config.server_url or "").rstrip("/")
        if clean_url and not clean_url.lower().startswith("https://"):
            raise ValueError("Insecure server URL blocked. VaultQ doctor client requires HTTPS.")
        self.server_url = clean_url
        self.enroll_token = (enroll_token or "").strip()
        if self.server_url:
            config.server_url = clean_url

        self._ui_queue = queue.Queue()

        self.setWindowTitle("VaultQ – Doctor Portal")
        
        self.setMinimumSize(920, 620)
        self.resize(1070, 720)
        
        self._center_window()

        self._build_ui()
        
        self._apply_theme(self.is_dark_mode)

        self.append_log = self._thread_safe_log

        self.agent = SecurityAgent(
            log_callback=self.append_log,
            status_callback=lambda connected: self._ui_queue.put(("status", connected)),
            loaded_private_key=private_key,
            doctor_id=doctor_id,
            enroll_token=self.enroll_token,
        )

        QTimer.singleShot(50, self._process_ui_queue)
        QTimer.singleShot(800, self._auto_handshake)

    def _center_window(self):
        screen = self.screen().availableGeometry()
        self.move(
            screen.center().x() - self.width() // 2,
            screen.center().y() - self.height() // 2
        )

    def _build_ui(self):
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Window)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
        root = QWidget(self)
        self.setCentralWidget(root)
        self.main_layout = QVBoxLayout(root)
        self.main_layout.setContentsMargins(12, 12, 12, 12)
        
        # Inner Background Container (Acts as the real window)
        self.bg_container = QWidget()
        self.bg_container.setObjectName("BgContainer")
        bg_layout = QVBoxLayout(self.bg_container)
        bg_layout.setContentsMargins(0, 0, 0, 0)
        bg_layout.setSpacing(0)
        
        window_shadow = QGraphicsDropShadowEffect(self)
        window_shadow.setBlurRadius(25)
        window_shadow.setColor(QColor(0, 0, 0, 50))
        window_shadow.setOffset(0, 8)
        self.bg_container.setGraphicsEffect(window_shadow)

        # Custom VS Code-style Title Bar
        self.title_bar = CustomTitleBar(self, "VaultQ – Doctor Portal", is_fixed=False)
        bg_layout.addWidget(self.title_bar)

        # Original Top Bar
        top_bar = QWidget()
        top_bar.setObjectName("TopBar")
        top_bar.setFixedHeight(65)
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(24, 0, 24, 0)

        self.title_label = QLabel("VaultQ Workspace")
        self.title_label.setObjectName("AppTitle")

        self.status_label = QLabel("● Disconnected")
        self.status_label.setObjectName("StatusLabelOffline")
        self.status_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        
        top_layout.addWidget(self.title_label)
        top_layout.addStretch()
        top_layout.addWidget(self.status_label)

        workspace = QWidget()
        workspace.setObjectName("Workspace")
        ws_layout = QVBoxLayout(workspace)
        ws_layout.setContentsMargins(24, 24, 24, 24)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("MainTabs")

        self.upload_tab = QWidget()
        self.logs_tab = QWidget()
        self.settings_tab = QWidget()

        self.tabs.addTab(self.upload_tab, "Document Upload")
        self.tabs.addTab(self.logs_tab, "System Logs")
        self.tabs.addTab(self.settings_tab, "Settings")

        self._build_upload_tab()
        self._build_logs_tab()
        self._build_settings_tab()

        ws_layout.addWidget(self.tabs)
        
        bg_layout.addWidget(top_bar)
        bg_layout.addWidget(workspace)
        
        # Add a size grip to the bottom right for manual window resizing
        grip_layout = QHBoxLayout()
        grip_layout.setContentsMargins(0, 0, 0, 0)
        grip_layout.addStretch()
        grip = QSizeGrip(self.bg_container)
        grip.setFixedSize(16, 16)
        grip_layout.addWidget(grip, 0, Qt.AlignBottom | Qt.AlignRight)
        
        bg_layout.addLayout(grip_layout)
        self.main_layout.addWidget(self.bg_container)

    def _build_upload_tab(self):
        layout = QHBoxLayout(self.upload_tab)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(24)

        left_col = QWidget()
        left_layout = QVBoxLayout(left_col)
        left_layout.setContentsMargins(0, 0, 0, 0)

        header = QLabel("Upload Medical Record")
        header.setObjectName("TabHeader")
        left_layout.addWidget(header)
        left_layout.addSpacing(16)

        patient_h = QHBoxLayout()
        patient_lbl = QLabel("Patient ID:")
        patient_lbl.setObjectName("StandardLabel")
        self.patient_id_entry = QLineEdit()
        self.patient_id_entry.setPlaceholderText("e.g. PAT-8821")
        self.patient_id_entry.textChanged.connect(self._check_upload_state)
        patient_h.addWidget(patient_lbl)
        patient_h.addWidget(self.patient_id_entry)
        left_layout.addLayout(patient_h)
        left_layout.addSpacing(16)

        self.drop_zone = FileDropZone()
        self.drop_zone.setMinimumHeight(220)
        self.drop_zone.file_dropped.connect(self._handle_file_selected)
        self.drop_zone.clicked.connect(self.action_select_file)
        left_layout.addWidget(self.drop_zone)
        left_layout.addSpacing(16)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.hide()
        left_layout.addWidget(self.progress_bar)

        self.upload_btn = QPushButton("Encrypt & Secure Upload")
        self.upload_btn.setObjectName("PrimaryButton")
        self.upload_btn.setMinimumHeight(42)
        self.upload_btn.setEnabled(False)
        self.upload_btn.clicked.connect(self.action_upload)
        left_layout.addWidget(self.upload_btn)
        
        left_layout.addStretch()

        right_col = QWidget()
        right_col.setMinimumWidth(300)
        right_col.setMaximumWidth(400)
        right_layout = QVBoxLayout(right_col)
        right_layout.setContentsMargins(0, 0, 0, 0)

        history_header = QLabel("Recent Uploads")
        history_header.setObjectName("TabHeader")
        right_layout.addWidget(history_header)
        right_layout.addSpacing(8)

        self.history_list = QListWidget()
        self.history_list.setObjectName("HistoryList")
        right_layout.addWidget(self.history_list)

        layout.addWidget(left_col, stretch=2)
        layout.addWidget(right_col, stretch=1)

    def _build_logs_tab(self):
        layout = QVBoxLayout(self.logs_tab)
        layout.setContentsMargins(16, 16, 16, 16)
        
        # Change from QPlainTextEdit to QTextEdit
        self.log_box = QTextEdit() 
        self.log_box.setReadOnly(True)
        self.log_box.setObjectName("LogBox")

        self.log_box.setStyleSheet("QTextEdit#LogBox { color: transparent; }")

        layout.addWidget(self.log_box)

        self._thread_safe_log("System Boot: Security Kernel Ready.", "INFO")

    def _build_settings_tab(self):
        layout = QVBoxLayout(self.settings_tab)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setAlignment(Qt.AlignTop)

        header = QLabel("Application Settings")
        header.setObjectName("TabHeader")
        layout.addWidget(header)
        layout.addSpacing(24)

        app_header = QLabel("Appearance")
        app_header.setObjectName("SectionHeader")
        layout.addWidget(app_header)

        btn_text = "Light Mode" if self.is_dark_mode else "Dark Mode"
        self.theme_btn = QPushButton(btn_text)
        self.theme_btn.setMinimumHeight(38)
        self.theme_btn.setMaximumWidth(200)
        self.theme_btn.clicked.connect(self.action_toggle_theme)
        layout.addWidget(self.theme_btn)
        
        layout.addSpacing(32)

        net_header = QLabel("Network Connection")
        net_header.setObjectName("SectionHeader")
        layout.addWidget(net_header)

        net_controls = QHBoxLayout()
        
        self.connect_btn = QPushButton("Redo Handshake")
        self.connect_btn.setObjectName("ConnectBtn")
        self.connect_btn.setProperty("status", "offline")
        self.connect_btn.setMinimumHeight(38)
        self.connect_btn.setMaximumWidth(180)
        self.connect_btn.clicked.connect(self.action_connect)

        self.refresh_btn = QPushButton("Refresh Status")
        self.refresh_btn.setMinimumHeight(38)
        self.refresh_btn.setMaximumWidth(150)
        self.refresh_btn.clicked.connect(lambda: self.action_connect())

        net_controls.addWidget(self.connect_btn)
        net_controls.addWidget(self.refresh_btn)
        net_controls.addStretch()
        layout.addLayout(net_controls)

        layout.addSpacing(32)

        sec_header = QLabel("Account Security")
        sec_header.setObjectName("SectionHeader")
        layout.addWidget(sec_header)

        self.change_pass_btn = QPushButton("Change Password")
        self.change_pass_btn.setMinimumHeight(38)
        self.change_pass_btn.setMaximumWidth(180)
        self.change_pass_btn.clicked.connect(self.action_change_password)
        layout.addWidget(self.change_pass_btn)
        
        layout.addStretch()

    # ---- Theming & Animation ----

    def action_toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.theme_btn.setText("Light Mode" if self.is_dark_mode else "Dark Mode")
        self.settings.setValue("theme/is_dark_mode", self.is_dark_mode)

        pixmap = self.grab()
        self.overlay = QLabel(self)
        self.overlay.setPixmap(pixmap)
        self.overlay.resize(self.size())
        self.overlay.move(0, 0)
        self.overlay.setAttribute(Qt.WA_TransparentForMouseEvents) 
        self.overlay.show()

        self._apply_theme(self.is_dark_mode)

        # 🔧 Re-render logs with new colors
        self.log_box.clear()
        for text, level in self._log_history:
            self._ui_queue.put(("log", text, level))

        self.effect = QGraphicsOpacityEffect(self.overlay)
        self.overlay.setGraphicsEffect(self.effect)

        self.anim = QPropertyAnimation(self.effect, b"opacity")
        self.anim.setDuration(450)
        self.anim.setStartValue(1.0)
        self.anim.setEndValue(0.0)
        self.anim.setEasingCurve(QEasingCurve.InOutQuad)

        self.anim.finished.connect(self.overlay.deleteLater)
        self.anim.start()

    def _apply_theme(self, dark_mode: bool):
        font_family = '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
        
        if dark_mode:
            self.setStyleSheet(f"""
                QMainWindow {{ background: transparent; }}
                
                QWidget#BgContainer {{ 
                    background-color: #1C1C1E; 
                    border: 1px solid #38383A; 
                    border-radius: 12px; 
                }}
                
                QFrame#CustomTitleBar {{ 
                    background-color: #242426; 
                    border-top-left-radius: 12px; 
                    border-top-right-radius: 12px; 
                }}
                QLabel#TitleBarText {{ color: #EBEBF5; font-family: {font_family}; font-size: 13px; font-weight: 600; }}
                QPushButton#TitleBtn {{ color: #8E8E93; border: none; background: transparent; font-size: 11px; font-family: "Segoe Fluent Icons", "Segoe MDL2 Assets", sans-serif; width: 46px; height: 34px; }}
                QPushButton#TitleBtn:hover {{ background-color: #3A3A3C; color: #FFFFFF; }}
                QPushButton#TitleCloseBtn {{ color: #8E8E93; border: none; background: transparent; font-size: 11px; font-family: "Segoe Fluent Icons", "Segoe MDL2 Assets", sans-serif; width: 46px; height: 34px; border-top-right-radius: 12px; }}
                QPushButton#TitleCloseBtn:hover {{ background-color: #FF453A; color: #FFFFFF; }}

                QWidget#TopBar {{ background-color: #242426; border-bottom: 1px solid #38383A; }}
                QWidget#Workspace {{ background-color: #1C1C1E; }}
                
                QLabel {{ color: #EBEBF5; font-family: {font_family}; }}
                QLabel#AppTitle {{ color: #FFFFFF; font-size: 16px; font-weight: 600; }}
                QLabel#TabHeader {{ color: #FFFFFF; font-size: 18px; font-weight: 600; }}
                QLabel#SectionHeader {{ color: #EBEBF5; font-size: 13px; font-weight: 600; }}
                QLabel#StandardLabel {{ color: #EBEBF5; font-size: 13px; font-weight: 500; }}
                
                QLabel#DropIcon {{ color: #8E8E93; }}
                QLabel#DropText {{ color: #8E8E93; font-size: 14px; }}
                
                QLabel#StatusLabelOffline {{ color: #FF453A; }}
                QLabel#StatusLabelOnline {{ color: #32D74B; }}
                
                QTabWidget::pane {{ 
                    border: 1px solid #38383A; 
                    background: #2C2C2E; 
                    border-radius: 10px; 
                }}
                QTabBar::tab {{ 
                    background: #1C1C1E; 
                    color: #8E8E93;
                    border: 1px solid #38383A; 
                    border-bottom: none;
                    padding: 10px 20px; 
                    margin-right: 4px;
                    border-top-left-radius: 6px; 
                    border-top-right-radius: 6px; 
                    font-size: 13px;
                    font-weight: 500;
                    font-family: {font_family};
                }}
                QTabBar::tab:selected {{ 
                    background: #2C2C2E; 
                    color: #FFFFFF; 
                    border-top: 2px solid #0A84FF;
                }}
                QTabBar::tab:hover:!selected {{ background: #242426; }}

                QLineEdit {{ 
                    padding: 10px 12px; 
                    background: #1C1C1E; 
                    color: #EBEBF5; 
                    border: 1px solid #38383A; 
                    border-radius: 6px; 
                    font-size: 14px;
                    font-family: {font_family};
                }}
                QLineEdit:focus {{ border: 1px solid #0A84FF; background: #242426; }}

                QFrame#DropZone {{ 
                    border: 2px dashed #48484A; 
                    border-radius: 12px; 
                    background: #242426; 
                }}
                QFrame#DropZone:hover, QFrame#DropZone[dragHover="true"] {{ 
                    border-color: #636366; 
                    background: #2C2C2E; 
                }}

                QPushButton {{ 
                    padding: 8px 16px; 
                    background: #3A3A3C; 
                    color: #EBEBF5; 
                    border: 1px solid #48484A; 
                    border-radius: 6px; 
                    font-weight: 500; 
                    font-family: {font_family};
                }}
                QPushButton:hover {{ background: #48484A; border-color: #636366; }}
                
                QPushButton#PrimaryButton {{ 
                    background: #0A84FF;
                    color: white; 
                    border: none; 
                }}
                QPushButton#PrimaryButton:hover {{ background: #007AFF; }}
                QPushButton#PrimaryButton:disabled {{ background: #3A3A3C; color: #636366; }}

                QTextEdit#LogBox {{
                    background-color: #151517; 
                    border: 1px solid #38383A; 
                    border-radius: 8px; 
                    padding: 10px;
                }}
            """)

        else:
            self.setStyleSheet(f"""
                QMainWindow {{ background: transparent; }}
                
                QWidget#BgContainer {{ 
                    background-color: #F5F5F7; 
                    border: 1px solid #D1D1D6; 
                    border-radius: 12px; 
                }}
                
                QFrame#CustomTitleBar {{ 
                    background-color: #E5E5EA; 
                    border-top-left-radius: 12px; 
                    border-top-right-radius: 12px; 
                }}
                QLabel#TitleBarText {{ color: #111827; font-family: {font_family}; font-size: 13px; font-weight: 600; }}
                QPushButton#TitleBtn {{ color: #6B7280; border: none; background: transparent; font-size: 11px; font-family: "Segoe Fluent Icons", "Segoe MDL2 Assets", sans-serif; width: 46px; height: 34px; }}
                QPushButton#TitleBtn:hover {{ background-color: #D1D1D6; color: #1D1D1F; }}
                QPushButton#TitleCloseBtn {{ color: #6B7280; border: none; background: transparent; font-size: 11px; font-family: "Segoe Fluent Icons", "Segoe MDL2 Assets", sans-serif; width: 46px; height: 34px; border-top-right-radius: 12px; }}
                QPushButton#TitleCloseBtn:hover {{ background-color: #FF3B30; color: #FFFFFF; }}

                QWidget#TopBar {{ background-color: #FFFFFF; border-bottom: 1px solid #E5E5EA; }}
                QWidget#Workspace {{ background-color: #F5F5F7; }}
                
                QLabel {{ color: #1D1D1F; font-family: {font_family}; }}
                QLabel#AppTitle {{ color: #1D1D1F; font-size: 16px; font-weight: 600; }}
                QLabel#TabHeader {{ color: #1D1D1F; font-size: 18px; font-weight: 600; }}
                QLabel#SectionHeader {{ color: #1D1D1F; font-size: 13px; font-weight: 600; }}
                QLabel#StandardLabel {{ color: #1D1D1F; font-size: 13px; font-weight: 500; }}
                
                QLabel#DropIcon {{ color: #8E8E93; }}
                QLabel#DropText {{ color: #8E8E93; font-size: 14px; }}

                QLabel#StatusLabelOffline {{ color: #FF3B30; }}
                QLabel#StatusLabelOnline {{ color: #34C759; }}

                QTabWidget::pane {{ 
                    border: 1px solid #E5E5EA; 
                    background: #FFFFFF; 
                    border-radius: 10px; 
                }}
                QTabBar::tab {{ 
                    background: #F5F5F7; 
                    color: #8E8E93;
                    border: 1px solid #E5E5EA; 
                    border-bottom: none;
                    padding: 10px 20px; 
                    margin-right: 4px;
                    border-top-left-radius: 6px; 
                    border-top-right-radius: 6px; 
                    font-size: 13px;
                    font-weight: 500;
                    font-family: {font_family};
                }}
                QTabBar::tab:selected {{ 
                    background: #FFFFFF; 
                    color: #1D1D1F; 
                    border-top: 2px solid #007AFF;
                }}
                QTabBar::tab:hover:!selected {{ background: #E5E5EA; }}

                QLineEdit {{ 
                    padding: 10px 12px; 
                    background: #FFFFFF; 
                    color: #1D1D1F; 
                    border: 1px solid #D1D1D6; 
                    border-radius: 6px; 
                    font-size: 14px;
                    font-family: {font_family};
                }}
                QLineEdit:focus {{ border: 1px solid #007AFF; }}

                QFrame#DropZone {{ 
                    border: 2px dashed #C7C7CC; 
                    border-radius: 12px; 
                    background: #F2F2F7; 
                }}
                QFrame#DropZone:hover, QFrame#DropZone[dragHover="true"] {{ 
                    border-color: #8E8E93; 
                    background: #E5E5EA; 
                }}

                QPushButton {{ 
                    padding: 8px 16px; 
                    background: #FFFFFF; 
                    color: #1D1D1F; 
                    border: 1px solid #D1D1D6; 
                    border-radius: 6px; 
                    font-weight: 500; 
                    font-family: {font_family};
                }}
                QPushButton:hover {{ background: #F2F2F7; border-color: #C7C7CC; }}
                
                QPushButton#PrimaryButton {{ 
                    background: #007AFF;
                    color: white; 
                    border: none; 
                }}
                QPushButton#PrimaryButton:hover {{ background: #0056B3; }}
                QPushButton#PrimaryButton:disabled {{ background: #E5E5EA; color: #8E8E93; }}

                QTextEdit#LogBox {{
                    background-color: #FFFFFF; 
                    border: 1px solid #E5E5EA; 
                    border-radius: 8px; 
                    padding: 10px;
                }}
            """)

        # 🔧 CRITICAL: re-assert HTML colors for logs after theme change
        if hasattr(self, "log_box"):
            self.log_box.setStyleSheet("QTextEdit#LogBox { color: transparent; }")
        else:
            self.setStyleSheet(f"""
                QMainWindow {{ background: transparent; }}
                
                QWidget#BgContainer {{ 
                    background-color: #F5F5F7; 
                    border: 1px solid #D1D1D6; 
                    border-radius: 12px; 
                }}
                
                QFrame#CustomTitleBar {{ 
                    background-color: #E5E5EA; 
                    border-top-left-radius: 12px; 
                    border-top-right-radius: 12px; 
                }}
                QLabel#TitleBarText {{ color: #111827; font-family: {font_family}; font-size: 13px; font-weight: 600; }}
                QPushButton#TitleBtn {{ color: #6B7280; border: none; background: transparent; font-size: 11px; font-family: "Segoe Fluent Icons", "Segoe MDL2 Assets", sans-serif; width: 46px; height: 34px; }}
                QPushButton#TitleBtn:hover {{ background-color: #D1D1D6; color: #1D1D1F; }}
                QPushButton#TitleCloseBtn {{ color: #6B7280; border: none; background: transparent; font-size: 11px; font-family: "Segoe Fluent Icons", "Segoe MDL2 Assets", sans-serif; width: 46px; height: 34px; border-top-right-radius: 12px; }}
                QPushButton#TitleCloseBtn:hover {{ background-color: #FF3B30; color: #FFFFFF; }}

                QWidget#TopBar {{ background-color: #FFFFFF; border-bottom: 1px solid #E5E5EA; }}
                QWidget#Workspace {{ background-color: #F5F5F7; }}
                
                QLabel {{ color: #1D1D1F; font-family: {font_family}; }}
                QLabel#AppTitle {{ color: #1D1D1F; font-size: 16px; font-weight: 600; }}
                QLabel#TabHeader {{ color: #1D1D1F; font-size: 18px; font-weight: 600; }}
                QLabel#SectionHeader {{ color: #1D1D1F; font-size: 13px; font-weight: 600; }}
                QLabel#StandardLabel {{ color: #1D1D1F; font-size: 13px; font-weight: 500; }}
                
                QLabel#DropIcon {{ color: #8E8E93; }}
                QLabel#DropText {{ color: #8E8E93; font-size: 14px; }}
                
                QLabel#StatusLabelOffline {{ color: #FF3B30; }}
                QLabel#StatusLabelOnline {{ color: #34C759; }}
                
                QTabWidget::pane {{ 
                    border: 1px solid #E5E5EA; 
                    background: #FFFFFF; 
                    border-radius: 10px; 
                }}
                QTabBar::tab {{ 
                    background: #F5F5F7; 
                    color: #8E8E93;
                    border: 1px solid #E5E5EA; 
                    border-bottom: none;
                    padding: 10px 20px; 
                    margin-right: 4px;
                    border-top-left-radius: 6px; 
                    border-top-right-radius: 6px; 
                    font-size: 13px;
                    font-weight: 500;
                    font-family: {font_family};
                }}
                QTabBar::tab:selected {{ 
                    background: #FFFFFF; 
                    color: #1D1D1F; 
                    border-top: 2px solid #007AFF;
                }}
                QTabBar::tab:hover:!selected {{ background: #E5E5EA; }}

                QLineEdit {{ 
                    padding: 10px 12px; 
                    background: #FFFFFF; 
                    color: #1D1D1F; 
                    border: 1px solid #D1D1D6; 
                    border-radius: 6px; 
                    font-size: 14px;
                    font-family: {font_family};
                }}
                QLineEdit:focus {{ border: 1px solid #007AFF; }}

                QFrame#DropZone {{ 
                    border: 2px dashed #C7C7CC; 
                    border-radius: 12px; 
                    background: #F2F2F7; 
                }}
                QFrame#DropZone:hover, QFrame#DropZone[dragHover="true"] {{ 
                    border-color: #8E8E93; 
                    background: #E5E5EA; 
                }}

                QPushButton {{ 
                    padding: 8px 16px; 
                    background: #FFFFFF; 
                    color: #1D1D1F; 
                    border: 1px solid #D1D1D6; 
                    border-radius: 6px; 
                    font-weight: 500; 
                    font-family: {font_family};
                }}
                QPushButton:hover {{ background: #F2F2F7; border-color: #C7C7CC; }}
                
                QPushButton#PrimaryButton {{ 
                    background: #007AFF;
                    color: white; 
                    border: none; 
                }}
                QPushButton#PrimaryButton:hover {{ background: #0056B3; }}
                QPushButton#PrimaryButton:disabled {{ background: #E5E5EA; color: #8E8E93; }}
                
                /* FORCED WHITE TEXT FOR SUCCESS/ERROR EVEN WHEN DISABLED */
                QPushButton#PrimaryButton[state="error"], QPushButton#PrimaryButton[state="error"]:disabled {{ 
                    background-color: #FF3B30; 
                    color: #FFFFFF; 
                }}
                QPushButton#PrimaryButton[state="success"], QPushButton#PrimaryButton[state="success"]:disabled {{ 
                    background-color: #34C759; 
                    color: #FFFFFF; 
                }}

                QPushButton#ConnectBtn[status="online"] {{ 
                    background-color: #E8F5E9; 
                    border-color: #C8E6C9; 
                }}
                QPushButton#ConnectBtn[status="online"]:hover {{ background-color: #C8E6C9; }}
                
                QPushButton#ConnectBtn[status="offline"] {{ 
                    background-color: #FFEBEE; 
                    border-color: #FFCDD2; 
                }}
                QPushButton#ConnectBtn[status="offline"]:hover {{ background-color: #FFCDD2; }}

                QProgressBar {{ 
                    border: none; 
                    background-color: #E5E5EA; 
                    border-radius: 4px; 
                }}
                QProgressBar::chunk {{ 
                    background-color: #007AFF;
                    border-radius: 4px; 
                }}

                QListWidget#HistoryList {{ 
                    background: transparent; 
                    border: none;
                    outline: none;
                }}
                QListWidget#HistoryList::item {{ 
                    background: #FFFFFF;
                    padding: 14px; 
                    margin-bottom: 8px;
                    border: 1px solid #E5E5EA; 
                    border-radius: 8px;
                    color: #1D1D1F;
                    font-family: {font_family};
                }}
                QListWidget#HistoryList::item:selected, QListWidget#HistoryList::item:hover {{ 
                    background: #F2F2F7; 
                    border-color: #C7C7CC; 
                }}

                QTextEdit#LogBox{{
                    background-color: #FFFFFF; 
                    border: 1px solid #E5E5EA; 
                    border-radius: 8px; 
                    padding: 10px;
                }}
            """)

    def action_connect(self):
        self.connect_btn.setEnabled(False)
        self.connect_btn.setText("Negotiating...")
        try:
            self.agent.initiate_handshake()
        except Exception as e:
            self.append_log(f"Handshake failed: {e}", "ERROR")
            self.set_connection_status(False)

    def set_connection_status(self, connected: bool):
        self.agent.is_connected = connected
        if connected:
            self.status_label.setText("● Secure Connection")
            self.status_label.setObjectName("StatusLabelOnline")
            self.connect_btn.setProperty("status", "online")
        else:
            self.status_label.setText("● Disconnected")
            self.status_label.setObjectName("StatusLabelOffline")
            self.connect_btn.setProperty("status", "offline")
            
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)
        
        self.connect_btn.style().unpolish(self.connect_btn)
        self.connect_btn.style().polish(self.connect_btn)
        
        self.connect_btn.setText("Handshake Active" if connected else "Redo Handshake")
        self.connect_btn.setEnabled(True) 
        self._check_upload_state()

    def action_select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Medical Record")
        if path:
            self._handle_file_selected(path)

    def _handle_file_selected(self, file_path: str):
        self.selected_file_path = file_path
        filename = os.path.basename(file_path)
        self.drop_zone.text_label.setText(f"Selected:\n{filename}")
        self._check_upload_state()

    def _check_upload_state(self):
        if getattr(self.agent, "is_connected", False) and self.selected_file_path and self.patient_id_entry.text().strip():
            self.upload_btn.setEnabled(True)
        else:
            self.upload_btn.setEnabled(False)

    def action_upload(self):
        patient_id = self.patient_id_entry.text().strip()
        filename = os.path.basename(self.selected_file_path)

        try:
            form = UploadForm(patient_id=patient_id, filepath=self.selected_file_path)
            
            self.upload_btn.setEnabled(False)
            self.upload_btn.setText("Encrypting & Uploading...")
            self.progress_bar.show()
            self.progress_bar.setRange(0, 0)
            QApplication.processEvents()

            self.agent.process_and_upload(form)
            
            self.progress_bar.setRange(0, 1)
            self.progress_bar.setValue(1) 
            
            item = QListWidgetItem(f"✅ {patient_id}\n📄 {filename}")
            self.history_list.insertItem(0, item)

            self.selected_file_path = None
            self.drop_zone.text_label.setText("Drag & Drop your record here\nor click to browse")
            self.patient_id_entry.clear()
            self.upload_btn.setText("Encrypt & Secure Upload")
            
            QTimer.singleShot(1500, self.progress_bar.hide)

        except Exception as e:
            self.append_log(f"Upload Error: {e}", "ERROR")
            self.upload_btn.setText("Encrypt & Secure Upload")
            self.progress_bar.hide()
            
            item = QListWidgetItem(f"❌ {patient_id} (Failed)\n📄 {filename}")
            self.history_list.insertItem(0, item)
            
            QMessageBox.critical(self, "Upload Error", str(e))

    def action_change_password(self):
        dlg = PasswordChangeDialog(self)
        result = dlg.get_result()
        if not result:
            return
        old_password, new_password, confirm_password = result

        try:
            resp = requests.post(
                f"{self.server_url}/api/doctor/auth/change-password",
                json={
                    "doctor_id": self.doctor_id,
                    "old_pass": old_password,
                    "new_pass": new_password,
                },
                timeout=10,
                **self.agent._tls_request_kwargs(),
            )
            
            if resp.status_code != 200:
                try:
                    detail_payload = resp.json()
                    detail = detail_payload.get("detail", "Failed to change password.")
                except (json.JSONDecodeError, ValueError):
                    detail = (resp.text or "Failed to change password.").strip()
                
                # USING CUSTOM MODERN MESSAGE BOX (Error State)
                ModernMessageBox(self, "Change Password Failed", detail, is_error=True).exec()
                
                self.append_log(f"Password change rejected: {detail}", "WARNING")
                return

            try:
                self.vault.change_password(self.doctor_id, old_password, new_password)
            except Exception as vault_err:
                # USING CUSTOM MODERN MESSAGE BOX (Error State)
                ModernMessageBox(self, "Local Vault Sync Failed", "Local vault update failed.", is_error=True).exec()
                return

            # USING CUSTOM MODERN MESSAGE BOX (Success State)
            ModernMessageBox(self, "Password Updated", "Password changed successfully.", is_error=False).exec()
            
        except Exception as e:
            # USING CUSTOM MODERN MESSAGE BOX (Error State)
            ModernMessageBox(self, "Change Password Error", str(e), is_error=True).exec()

    def _thread_safe_log(self, text: str, level: str = "INFO"):
        self._log_history.append((text, level))
        self._ui_queue.put(("log", text, level))

    def _process_ui_queue(self):
        try:
            while not self._ui_queue.empty():
                msg = self._ui_queue.get_nowait()
                if msg[0] == "log":
                    t = time.strftime("%H:%M:%S")
                    lvl = msg[2]
                    txt = msg[1]

                    if self.is_dark_mode:
                        colors = {
                            "INFO":    "#FFFFFF",  # White
                            "WARNING": "#FFA500",  # Orange
                            "ERROR":   "#FF453A",  # Red
                            "DEBUG":   "#5AC8FA",  # Light Blue
                            "SUCCESS": "#32D74B",  # Green
                        }
                    else:
                        colors = {
                            "INFO":    "#000000",  # Black
                            "WARNING": "#FF9500",  # Orange
                            "ERROR":   "#FF3B30",  # Red
                            "DEBUG":   "#0A2AFF",  # Dark Blue
                            "SUCCESS": "#34C759",  # Green
                        }

                    log_color = colors.get(lvl, "#888888")

                    self.log_box.insertHtml(
                        f'<span style="color:{log_color}; font-family:Consolas">[{t}] [{lvl}] {txt}</span><br>'
                    )
                    self.log_box.moveCursor(QTextCursor.End)  # ✅ FIXED
                elif msg[0] == "status":
                    self.set_connection_status(msg[1])
        except queue.Empty:
            pass

        if not self._closing:
            QTimer.singleShot(50, self._process_ui_queue)

    def _auto_handshake(self):
        self.append_log("Auto-initiating secure handshake...", "INFO")
        self.action_connect()

    def closeEvent(self, event):
        self._closing = True
        try:
            if hasattr(self.agent, "shutdown"):
                self.agent.shutdown()
        except Exception:
            pass
        event.accept()
