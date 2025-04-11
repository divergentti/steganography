# Copyright (c) 2025 Jari Hiltunen / GitHub Divergentti
#
# Steganography Tool - GUI Implementation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import os
from PIL import Image
from PIL.ExifTags import TAGS

# pip install pyqt6
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSizePolicy,
    QRadioButton, QGroupBox, QLineEdit, QPushButton,  QCheckBox, QSplitter,
    QLabel, QTextEdit, QFileDialog, QStatusBar, QMessageBox, QProgressBar, QLayout
)
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import Qt, QEvent
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable, QThreadPool
import endecrypter  # Import actual encrypter and decrypter

debug_gui = False  # Set to False in production for speed
debug_verify = False # # Set to False in production for speed

VERSION = "0.1.0 - 11.04.2025"

class WorkerSignals(QObject):
    finished = pyqtSignal()
    progress = pyqtSignal(int)  # Percentage (0-100)
    status = pyqtSignal(str)  # Status text ("Encrypting...")
    phase = pyqtSignal(str)  # Current phase ("Embedding LSB...")
    result = pyqtSignal(object)

class Worker(QRunnable):
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True

    def is_cancelled(self):
        """Thread-safe check for cancellation status"""
        return self._is_cancelled

    def run(self):
        # For QRunnable
        try:
            if not self._is_cancelled:
                result = self.fn(*self.args, **self.kwargs)
                self.signals.result.emit(result)  # Thread-safe signal
        except Exception as e:
            self.signals.status.emit(f"Error: {str(e)}")

class MainWindow(QMainWindow):
    def __init__(self, stego_machine):
        super().__init__()
        self.worker = None
        self.threadpool = QThreadPool()
        self.status_bar = QStatusBar()
        self.progress_bar = QProgressBar()
        self.progress_label = QLabel("Ready")
        self.exif_text = QTextEdit()
        self.file_type_label = QLabel("Type: N/A")
        self.file_size_label = QLabel("Size: N/A")
        self.preview_label = QLabel()
        self.cancel_btn = QPushButton("Cancel")
        self.action_btn = QPushButton("Encrypt")
        self.password_edit = QLineEdit()
        self.encrypt_checkbox = QCheckBox("Enable AES Encryption")
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type or paste your secret message")
        self.message_input.setStyleSheet("QLineEdit { background-color: #90EE90 ;}")
        self.browse_btn = QPushButton("Browse")
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Browse file or path ->")
        self.path_edit.setStyleSheet("QLineEdit { background-color: #90EE90 ;}")
        self.folder_radio = QRadioButton("Folder")
        self.file_radio = QRadioButton("File")
        self.input_type_group = QGroupBox("Input Type")
        self.input_type_group.setStyleSheet("QGroupBox { font-size: 12px; font-weight: bold; }")
        self.decrypt_radio = QRadioButton("Decrypt")
        self.encrypt_radio = QRadioButton("Encrypt")
        self.mode_group = QGroupBox("Operation Mode")
        self.mode_group.setStyleSheet("QGroupBox { font-size: 12px; font-weight: bold; }")
        self.original_pixmap = None
        self.stego = stego_machine
        self.setWindowTitle("Steganography Tool version: " + VERSION)
        self.setGeometry(100, 100, 800, 550)
        self.setup_ui()
        self.create_menu()
        self.cancel_btn.clicked.connect(self.cancel_operation)

    def eventFilter(self, obj, event):
        if obj == self.preview_label and event.type() == QEvent.Type.Resize:
            self.update_preview_pixmap()
        return super().eventFilter(obj, event)

    def update_preview_pixmap(self):
        """Scales the pixmap to fit within the label's current size"""
        if self.original_pixmap is not None and not self.original_pixmap.isNull():
            available_width = self.preview_label.width()
            available_height = self.preview_label.height()
            scaled = self.original_pixmap.scaled(
                available_width,
                available_height,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            self.preview_label.setPixmap(scaled)

    def cancel_operation(self):
        if self.worker:
            self.worker.cancel()
            self.status_bar.showMessage("Cancelling...wait (slow)")
            self.cancel_btn.setEnabled(False)

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetDefaultConstraint)

        # Mode and Input Type in same row
        mode_input_row = QHBoxLayout()
        mode_layout = QHBoxLayout()
        self.encrypt_radio.setChecked(True)
        mode_layout.addWidget(self.encrypt_radio)
        mode_layout.addWidget(self.decrypt_radio)
        self.mode_group.setLayout(mode_layout)
        mode_input_row.addWidget(self.mode_group)

        input_type_layout = QHBoxLayout()
        self.file_radio.setChecked(True)
        input_type_layout.addWidget(self.file_radio)
        input_type_layout.addWidget(self.folder_radio)
        self.input_type_group.setLayout(input_type_layout)
        mode_input_row.addWidget(self.input_type_group)

        layout.addLayout(mode_input_row)

        # Path selection
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.path_edit)
        path_layout.addWidget(self.browse_btn)
        layout.addLayout(path_layout)

        # Message input
        layout.addWidget(self.message_input)

        # Password row
        password_layout = QHBoxLayout()
        self.password_edit.setPlaceholderText("Password (if AES enabled)")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(self.encrypt_checkbox)
        password_layout.addWidget(self.password_edit)
        layout.addLayout(password_layout)

        # Button row
        button_row = QHBoxLayout()
        self.cancel_btn.setEnabled(False)
        button_row.addWidget(self.action_btn)
        button_row.addWidget(self.cancel_btn)
        layout.addLayout(button_row)

        # Preview and EXIF area using QSplitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStretchFactor(0, 3)  # Give more space to preview
        splitter.setStretchFactor(1, 1)  # Less space to info panel
        layout.addWidget(splitter)

        # Image preview
        self.preview_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.preview_label.setMinimumSize(300, 300)
        self.preview_label.setStyleSheet("background-color: #f0f0f0; border: 1px solid #ccc;")
        self.preview_label.installEventFilter(self)
        splitter.addWidget(self.preview_label)

        # Right panel with file info and EXIF
        right_panel_widget = QWidget()
        right_panel_layout = QVBoxLayout(right_panel_widget)
        right_panel_widget.setMaximumWidth(250)

        file_info_group = QGroupBox("File Information")
        file_info_layout = QVBoxLayout()
        file_info_layout.addWidget(self.file_size_label)
        file_info_layout.addWidget(self.file_type_label)
        file_info_group.setLayout(file_info_layout)

        right_panel_layout.addWidget(file_info_group)

        self.exif_text.setReadOnly(True)
        right_panel_layout.addWidget(self.exif_text)

        # Splitter
        splitter.addWidget(right_panel_widget)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter)

        # Progress
        layout.addWidget(self.progress_label)
        layout.addWidget(self.progress_bar)

        # Status bar
        self.setStatusBar(self.status_bar)

        # Connections
        self.encrypt_radio.toggled.connect(self.update_ui_mode)
        self.browse_btn.clicked.connect(self.handle_browse)
        self.action_btn.clicked.connect(self.handle_action)
        self.file_radio.toggled.connect(self.update_path_field)
        self.encrypt_checkbox.stateChanged.connect(self.toggle_password_field)

        # Style sheets
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #ffffff;
                color: #333333;
            }
            QLabel {
                font-size: 11px;
                color: #333333;
            }
            QPushButton {
                background-color: #007BFF;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 3px;
                font-size: 11px;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
            QLineEdit, QTextEdit {
                border: 1px solid #cccccc;
                border-radius: 3px;
                padding: 3px;
                font-size: 11px;
            }
            QGroupBox {
                font-size: 12px;
                font-weight: bold;
                color: #0056b3;
                background-color: #f9f9f9;
                border: 1px solid #cccccc;
                border-radius: 5px;
                margin-top: 1ex;
                padding: 5px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 3px;
            }
            QProgressBar {
                border: 1px solid #cccccc;
                border-radius: 3px;
                text-align: center;
                font-size: 11px;
            }
            QStatusBar {
                background-color: #f1f1f1;
                border-top: 1px solid #cccccc;
            }
        """)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.update_preview_pixmap()

    def set_error_bar_style(self):
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid grey;
                border-radius: 5px;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background-color: red;
                border-radius: 5px;
            }
        """)

    def set_error_text_style(self):
        self.status_bar.setStyleSheet("""
            QStatusBar {
                border: 1px solid grey;
                border-radius: 5px;
                background-color: red;
                color: white;
            }
            """)

    def set_ok_progress_bar_style(self):
        # Not yet improved
        self.progress_bar.setStyleSheet("")

    def set_ok_text_style(self):
        # Not yet improved
        self.status_bar.setStyleSheet("")
        self.status_bar.showMessage("")

    def on_encrypt_progress(self, percent):
        """Handles progress updates during ENCRYPTION."""
        phases = {
            5: "Starting encryption...",
            10: "Processing image...(slow with big images)",
            30: "Embedding LSB...",
            50: "Embedding DCT...",
            70: "Saving file...",
            90: "Finalizing...",
            100: "Encryption complete!"
        }
        self._update_progress(percent, phases)

    def on_decrypt_progress(self, percent):
        """Handles progress updates during DECRYPTION."""
        phases = {
            10: "Extracting data...",
            30: "Analyzing DCT...",
            50: "Decoding message...",
            80: "Verifying...",
            100: "Decryption complete!"
        }
        self._update_progress(percent, phases)

    def _update_progress(self, percent, phase_map):
        """Shared logic for updating progress (avoid code duplication)."""
        self.progress_bar.setValue(percent)
        self.progress_label.setText(phase_map.get(percent, "Working..."))

        if percent == 100:
            self.status_bar.showMessage(phase_map[100])
        elif percent == -1:
            self.action_btn.setEnabled(True)
            self.cancel_btn.setEnabled(False)
            self.status_bar.showMessage("Operation failed!")

    def create_menu(self):
        menu_bar = self.menuBar()
        help_menu = menu_bar.addMenu("Help")
        about_action = help_menu.addAction("About")
        about_action.triggered.connect(self.show_help)

    def toggle_password_field(self):
        if self.encrypt_checkbox.isChecked():
            self.password_edit.setEnabled(True)
            self.password_edit.setStyleSheet("QLineEdit { background-color: #90EE90; }")
        else:
            self.password_edit.setEnabled(False)
            self.password_edit.setStyleSheet("")

    def update_ui_mode(self):
        is_encrypt = self.encrypt_radio.isChecked()
        self.action_btn.setText("Encrypt" if is_encrypt else "Decrypt")
        self.message_input.setVisible(is_encrypt)
        self.input_type_group.setVisible(is_encrypt)

    def update_path_field(self):
        self.path_edit.setPlaceholderText(
            "Select file..." if self.file_radio.isChecked()
            else "Select folder..."
        )

    def handle_browse(self):
        if self.encrypt_radio.isChecked() and self.folder_radio.isChecked():
            path = QFileDialog.getExistingDirectory(self, "Select Folder")
        else:
            filters = "Images (*.png *.jpg *.jpeg *.bmp *.webp)"
            path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Image",
                "",
                filters
            )

        if path:
            # Only validate extension for files
            if os.path.isfile(path):
                ext = os.path.splitext(path)[1].lower()
                if ext not in ['.png', '.jpg', '.jpeg', '.bmp', '.webp']:
                    QMessageBox.warning(self,
                                        "Unsupported File Type",
                                        "Please select an image file (PNG, JPG, JPEG, BMP, WEBP)"
                                        )
                    return
            self.path_edit.setText(path)
            self.update_preview(path)

    def update_preview(self, path):
        self.cancel_btn.setEnabled(False)
        if os.path.isfile(path):
            try:
                # Load image preview
                self.original_pixmap = QPixmap(path)
                if not self.original_pixmap.isNull():
                    self.update_preview_pixmap()
            except Exception as e:
                self.preview_label.clear()
                print(f"Error loading preview: {str(e)}")
                return

            try:
                # File size and type
                size_bytes = os.path.getsize(path)
                size_kb = size_bytes / 1024
                self.file_size_label.setText(f"Size: {size_kb:.2f} KB")

                file_ext = os.path.splitext(path)[1].upper().replace('.', '') or 'Unknown'
                self.file_type_label.setText(f"Type: {file_ext}")
            except Exception as e:
                self.file_size_label.setText(f"Size: Error {e}")
                self.file_type_label.setText(f"Type: Error")

            try:
                # Extract EXIF data
                exif_info = self.get_exif_data(path)
                self.exif_text.setPlainText(exif_info)
            except Exception as e:
                self.exif_text.setPlainText(f"Error loading EXIF: {str(e)}")

        else:
            self.preview_label.clear()
            if os.path.isdir(path):
                self.file_size_label.setText("Size: N/A (Directory)")
                self.file_type_label.setText("Type: Directory")
                self.exif_text.setPlainText("No EXIF data for directories.")
            else:
                self.file_size_label.setText("Size: N/A")
                self.file_type_label.setText("Type: N/A")
                self.exif_text.setPlainText("No EXIF data available.")

    @staticmethod
    def get_exif_data(image_path):
        try:
            with Image.open(image_path) as img:
                exif_data = img.getexif()
                if not exif_data:
                    return "No EXIF data found (PNG file?)"
                exif_info = []
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    exif_info.append(f"{tag_name}: {value}")
                return "\n".join(exif_info)
        except Exception as e:
            return f"EXIF Error: {str(e)}"

    def handle_action(self):
        path = self.path_edit.text()
        if not path:
            self.set_error_text_style()
            self.status_bar.showMessage("Please select image or input path")
            return

        if self.encrypt_radio.isChecked():
            self.handle_encrypt()
        else:
            self.handle_decrypt()

    def on_encrypt_result(self, output_path, is_folder):
        self.action_btn.setEnabled(True)
        if output_path:
            if is_folder:
                QMessageBox.information(self, "Success", output_path)
            else:
                if isinstance(output_path, str):  # Ensure it's a string path
                    self.update_preview(output_path)
                    QMessageBox.information(self, "Success", f"Saved to {output_path}")

    def handle_encrypt(self):
        path = self.path_edit.text()
        message = self.message_input.text()
        password = self.password_edit.text() if self.encrypt_checkbox.isChecked() else None
        self.set_ok_text_style()

        if not path:
            self.set_error_text_style()
            self.status_bar.showMessage("Please select an input file or folder!")
            return
        if not message:
            self.set_error_text_style()
            self.status_bar.showMessage("Message is required!")
            return

        if self.encrypt_checkbox.isChecked() and not password:
            self.set_error_text_style()
            self.status_bar.showMessage("Enter password for encryption!")
            return

        self.action_btn.setEnabled(False)
        self.progress_bar.setValue(0)

        is_folder = os.path.isdir(path)

        if is_folder:
            worker = Worker(
                lambda: self.process_folder(path, message, password)
            )
        else:
            # Standard encryption worker
            def encrypt_with_verification():
                # First, perform the encryption
                output_path = self.stego.hybrid_embed_message(path, message, password,
                                                              progress_signal=worker.signals.progress)

                # If debugging is enabled and encryption succeeded, verify the result
                if debug_verify and output_path:
                    try:
                        worker.signals.status.emit("Verifying encryption...")
                        # Extract message from the output file
                        extracted_message = self.stego.hybrid_extract_message(
                            output_path,
                            password,
                            progress_callback=None  # Skip progress for verification
                        )

                        # Compare original and extracted messages
                        if extracted_message == message:
                            worker.signals.status.emit("Verification successful!")
                        else:
                            self.set_error_text_style()
                            worker.signals.status.emit("WARNING: Verification failed - messages don't match!")
                    except Exception as e:
                        self.set_error_text_style()
                        worker.signals.status.emit(f"WARNING: Verification failed with error: {str(e)}")

                return output_path

            worker = Worker(encrypt_with_verification)

        worker.signals.progress.connect(self.on_encrypt_progress)
        worker.signals.result.connect(lambda output_path: self.on_encrypt_result(output_path, is_folder))
        worker.signals.status.connect(self.status_bar.showMessage)
        worker.signals.finished.connect(lambda: self.action_btn.setEnabled(True))

        self.worker = worker
        self.cancel_btn.setEnabled(True)
        self.threadpool.start(worker)

    def handle_decrypt(self):
        self.progress_bar.setValue(0)
        self.set_ok_text_style()
        path = self.path_edit.text()
        password = self.password_edit.text() if self.encrypt_checkbox.isChecked() else None
        if not path:
            self.set_error_text_style()
            self.status_bar.showMessage("Please select an input file or folder!")
            return

        self.action_btn.setEnabled(False)
        self.progress_bar.setValue(0)

        def on_result(message):
            self.action_btn.setEnabled(True)
            if message == "PASSWORD_REQUIRED":
                on_error(message)
                self.set_error_bar_style()
                QMessageBox.warning(self, "Password Required",
                                    "This message requires a decryption password")
                self.set_ok_progress_bar_style()
                self.progress_bar.setValue(0)
            elif message == "DECRYPTION_FAILED":
                on_error(message)
                self.set_error_bar_style()
                QMessageBox.critical(self, "Decryption Failed",
                                     "Incorrect password or corrupted data")
                self.set_ok_progress_bar_style()
                self.progress_bar.setValue(0)
            elif message == "INVALID_CHECKSUM":
                on_error(message)
                self.set_error_bar_style()
                QMessageBox.warning(self, "Integrity Error",
                                    "Message checksum failed - data may be corrupted")
                self.set_ok_progress_bar_style()
                self.progress_bar.setValue(0)

            elif message:
                self.progress_bar.setValue(100)
                QMessageBox.information(self, "Decrypted Message", message)
            else:
                QMessageBox.warning(self, "No Message",
                                    "No valid message found in this image")

        def on_error(e):
            self.set_error_text_style()
            self.status_bar.showMessage(f"Decryption Error: {str(e)}")

        worker = Worker(
            lambda: machine.hybrid_extract_message(path, password, progress_callback=self.on_decrypt_progress)
        )
        worker.signals.status.connect(self.status_bar.showMessage)
        worker.signals.result.connect(on_result)
        worker.signals.finished.connect(lambda: self.action_btn.setEnabled(True))
        self.threadpool.start(worker)

    def process_folder(self, folder_path, message, password=None):
        if hasattr(self, 'worker') and hasattr(self.worker.signals, 'status'):
            self.worker.signals.status.emit("Starting ... wait (slow)")

        supported_ext = ('.png', '.jpg', '.jpeg', '.bmp', '.webp')
        files = []
        folder_path = os.path.abspath(folder_path)

        for root, _, filenames in os.walk(folder_path):
            for f in filenames:
                if f.lower().endswith(supported_ext):
                    full_path = os.path.join(root, f)
                    resolved_path = os.path.realpath(full_path)
                    if os.path.isfile(resolved_path):
                        files.append(full_path)

        total = len(files)
        results = []

        for i, file_path in enumerate(files):
            if hasattr(self, 'worker') and self.worker.is_cancelled():
                if hasattr(self, 'worker') and hasattr(self.worker.signals, 'progress'):
                    self.worker.signals.progress.emit(-1)  # Signal cancelation
                self.set_error_bar_style()
                return "Operation cancelled"

            try:
                result = self.stego.hybrid_embed_message(
                    file_path,
                    message,
                    password,
                    progress_signal=None
                )
                results.append(result)

                if hasattr(self, 'worker') and hasattr(self.worker.signals, 'progress'):
                    overall_progress = int(((i + 1) / total) * 100)
                    self.worker.signals.progress.emit(overall_progress)
                    status_msg = f"Processing file {i + 1} of {total} ({int(overall_progress)}%)"
                    self.worker.signals.status.emit(status_msg)

            except Exception as e:
                print(f"Error processing {file_path}: {str(e)}")
                if hasattr(self, 'worker') and hasattr(self.worker.signals, 'status'):
                    self.worker.signals.status.emit(f"Error on file: {os.path.basename(file_path)}")
                continue

        return f"Processed {len(results)}/{len(files)} files successfully"

    def show_help(self):
        help_text = """Steganography Tool - Help Guide

Embed or extract hidden messages in images. 
Currently supports png, jp(e)g, bmp and webp.

Key Features:
- Embed/extract messages with optional password protection
- Preserves EXIF metadata
- Hybrid methods: LSB + DCT steganography
- Survives common format conversions

Usage:
    [Encrypt]
    1. Select image/folder
    2. Enter message to be emdedded
    3. (Optional) Set password
    4. Output saved as "encrypted_[original filename]

    [Decrypt]
    1. Select encrypted image to be extracted
    2. (Optional) Enter password

Important Notes:
• Always test extraction to verify embedding worked
• Originals are never modified
• For sensitive data, always use password protection
• Debug options available in source code

Security Warning: Steganography ≠ Encryption! 
Hidden data may be detectable:
• For best security, pre-encrypt messages
• Or use built-in AES with strong password

Technical:
- PNG: Best for embedding (lossless)
- WEBP: May affect hidden data (lossless)
- JPEG: May affect hidden data (lossy)
- Capacity: ~1 bit per pixel/subpixel

Applications:
- Secure communication
- Copyright watermarking
- Metadata embedding

(C) 2025 - Jari Hiltunen / Divergentti
        """
        QMessageBox.information(self, "Help", help_text)


if __name__ == "__main__":
    machine = endecrypter.StegaMachine()
    app = QApplication(sys.argv)
    window = MainWindow(machine)
    window.show()
    sys.exit(app.exec())