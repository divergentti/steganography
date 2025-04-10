# Copyright (c) 2025 Jari Hiltunen / GitHub Divergentti
#
# Steganography Tool
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
import numpy as np
from scipy.fftpack import dct, idct
import cv2
import functools
import zlib
from concurrent.futures import ThreadPoolExecutor  # For parallelization

# pip install pyqt6
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSizePolicy,
    QRadioButton, QGroupBox, QLineEdit, QPushButton,  QCheckBox, QSplitter,
    QLabel, QTextEdit, QFileDialog, QStatusBar, QMessageBox, QProgressBar, QLayout
)
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import Qt, QEvent
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable, QThreadPool

# pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# For debugging issues with the code
debug_extract = False  # Set to False in production for speed
debug_crypto = False  # Set to False in production for speed
debug_embed = False  # Set to False in production for speed
debug_gui = False  # Set to False in production for speed
debug_verify = False # # Set to False in production for speed

if debug_gui or debug_embed or debug_extract or debug_crypto:
    import faulthandler
    faulthandler.enable()

# Number of worker threads for parallel processing
NUM_WORKERS = max(1, os.cpu_count() - 1)  # Leave one core free for system
VERSION = "0.0.5 - 10.04.2025"

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

    def run(self):
        # For QRunnable
        try:
            if not self._is_cancelled:
                result = self.fn(*self.args, **self.kwargs)
                self.signals.result.emit(result)  # Thread-safe signal
        except Exception as e:
            self.signals.status.emit(f"Error: {str(e)}")

class StegaMachine:
    START_CHAR = '\x02'  # Use non-printable Unicode characters
    STOP_CHAR = '\x03'
    CHECKSUM_LENGTH = 16  # Using 16-bit checksum

    def __init__(self):
        # Initialize the thread pool for parallel processing
        self.thread_pool = ThreadPoolExecutor(max_workers=NUM_WORKERS)
        # Cache for complexity calculations to avoid redundant work
        self.complexity_cache = {}

    def _calculate_checksum(self, message):
        return bin(zlib.crc32(message.encode()) & 0xffff)[2:].zfill(16)

    def _aes_encrypt(self, message, password):
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = PBKDF2(password, salt, dkLen=32, count=100000)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        if debug_crypto:
            print(f"AES{salt.hex()}{iv.hex()}{ct_bytes.hex()}")
        return f"AES{salt.hex()}{iv.hex()}{ct_bytes.hex()}"

    def _aes_decrypt(self, ciphertext, password):
        try:
            salt = bytes.fromhex(ciphertext[3:35])
            iv = bytes.fromhex(ciphertext[35:67])
            ct = bytes.fromhex(ciphertext[67:])
            key = PBKDF2(password, salt, dkLen=32, count=100000)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            if debug_crypto:
                print("PT: ", pt)
            return pt.decode()
        except:
            return None

    # ------------------ Optimized Adaptive LSB Implementation ------------------

    @functools.lru_cache(maxsize=256)
    def get_embedding_capacity(self, complexity, threshold_low=5, threshold_high=15):
        """Cached function to determine LSB capacity"""
        if complexity < threshold_low:
            return 1  # Low complexity - use only 1 LSB
        elif complexity < threshold_high:
            return 2  # Medium complexity - use 2 LSBs
        else:
            return 3  # High complexity - use 3 LSBs

    def adaptive_lsb_embed(self, img, binary_message):
        """Vectorized adaptive LSB embedding"""
        img_array = None
        # Convert PIL image to numpy array once
        try:
            img_array = np.array(img)
            height, width, _ = img_array.shape

            # Prepare binary message as numpy array for faster access
            message_bits = np.array([int(bit) for bit in binary_message], dtype=np.uint8)
            message_length = len(message_bits)
            data_index = 0

            # Pre-calculate all complexity values for 3x3 regions
            complexity_map = np.zeros((height - 2, width - 2), dtype=np.float32)

            # Calculate standard deviation for each 3x3 region using efficient sliding window
            for y in range(0, height - 2, 3):
                for x in range(0, width - 2, 3):
                    if y + 3 <= height and x + 3 <= width:
                        region = img_array[y:y + 3, x:x + 3]
                        complexity_map[y, x] = np.std(region)

            # Process in batches for better cache utilization
            batch_size = 100  # You may adjust this value based on testing
            modified_pixels = []

            for i in range(0, width * height, batch_size):
                # Get coordinates for this batch
                coords = []
                for j in range(i, min(i + batch_size, width * height)):
                    y, x = j // width, j % width
                    if 1 <= y < height - 1 and 1 <= x < width - 1:
                        coords.append((y, x))

                # Skip if no valid coordinates in this batch
                if not coords:
                    continue

                # Process this batch
                for y, x in coords:
                    if data_index >= message_length:
                        break

                    # Use precomputed complexity if available
                    if y - 1 < len(complexity_map) and x - 1 < len(complexity_map[0]):
                        complexity = complexity_map[y - 1, x - 1]
                    else:
                        # Fallback for edge pixels
                        region = img_array[max(0, y - 1):min(height, y + 2), max(0, x - 1):min(width, x + 2)]
                        complexity = np.std(region)

                    capacity = self.get_embedding_capacity(complexity)
                    pixel = img_array[y, x].copy()

                    # Embed bits in all channels at once
                    for z in range(3):  # RGB channels
                        # Clear LSBs based on capacity
                        mask = (1 << capacity) - 1
                        pixel[z] &= (0xFF ^ mask)

                        # Get bits to embed (as many as capacity allows)
                        bits_to_embed = 0
                        for j in range(capacity):
                            if data_index < message_length:
                                bit_value = message_bits[data_index]
                                bits_to_embed |= bit_value << j
                                data_index += 1

                        # Embed bits
                        pixel[z] |= bits_to_embed

                    # Store the modified pixel
                    modified_pixels.append((y, x, pixel))

            # Apply all modified pixels to the original image
            result_img = img.copy()
            result_array = np.array(result_img)
            for y, x, pixel in modified_pixels:
                result_array[y, x] = pixel

            # Convert back to PIL Image
            result_img = Image.fromarray(result_array)

            return result_img, data_index
        finally:
            if img_array is not None:
                del img_array

    def adaptive_lsb_extract(self, img, message_length):
        """Optimized LSB extraction using NumPy vectorization"""
        # Convert to numpy array for faster processing
        img_array = np.array(img)
        height, width, _ = img_array.shape

        # Pre-allocate result array
        binary_message = np.zeros(message_length, dtype=np.uint8)
        data_index = 0

        # Process in batches for better memory locality
        for y in range(0, height - 2, 3):
            for x in range(0, width - 2, 3):
                if data_index >= message_length:
                    break

                # Get center pixel and calculate complexity
                if y + 1 < height and x + 1 < width:
                    pixel = img_array[y + 1, x + 1]
                    region = img_array[y:min(y + 3, height), x:min(x + 3, width)]
                    complexity = np.std(region)
                    capacity = self.get_embedding_capacity(complexity)

                    # Extract bits from all channels
                    for i in range(3):  # RGB channels
                        for j in range(capacity):
                            if data_index < message_length:
                                # Extract bit using bit mask and shift
                                bit = (pixel[i] >> j) & 1
                                binary_message[data_index] = bit
                                data_index += 1

        # Convert numpy array to string
        result = ''.join(str(bit) for bit in binary_message)

        if debug_extract:
            print(f"Adaptive LSB extract Binary message: {result[:100]}...")

        return result

    # ------------------ Optimized DCT Implementation ------------------

    def rgb_to_ycbcr_vectorized(self, img_array):
        """Vectorized RGB to YCbCr conversion"""
        # Create transformation matrix
        transform = np.array([
            [0.299, 0.587, 0.114],
            [-0.168736, -0.331264, 0.5],
            [0.5, -0.418688, -0.081312]
        ])

        # Reshape for matrix multiplication
        flat_rgb = img_array.reshape(-1, 3)

        # Apply transformation
        flat_ycbcr = np.dot(flat_rgb, transform.T)

        # Add offsets to Cb and Cr channels
        flat_ycbcr[:, 1:] += 128

        # Reshape back to original dimensions
        return flat_ycbcr.reshape(img_array.shape)

    def ycbcr_to_rgb_vectorized(self, ycbcr_array):
        """Vectorized YCbCr to RGB conversion"""
        # Create inverse transformation matrix
        inverse_transform = np.array([
            [1.0, 0.0, 1.402],
            [1.0, -0.344136, -0.714136],
            [1.0, 1.772, 0.0]
        ])

        # Make a copy to avoid modifying the original
        ycbcr_copy = ycbcr_array.copy()

        # Subtract offsets from Cb and Cr channels
        ycbcr_copy[..., 1:] -= 128

        # Reshape for matrix multiplication
        flat_ycbcr = ycbcr_copy.reshape(-1, 3)

        # Apply transformation
        flat_rgb = np.dot(flat_ycbcr, inverse_transform.T)

        # Clip values to valid range and convert to uint8
        flat_rgb = np.clip(flat_rgb, 0, 255).astype(np.uint8)

        # Reshape back to original dimensions
        return flat_rgb.reshape(ycbcr_array.shape)

    def process_dct_block_batch(self, blocks, bits_array, start_indices, alpha=5):
        """Process multiple DCT blocks in parallel"""
        results = []

        for i, (block, start_idx) in enumerate(zip(blocks, start_indices)):
            # Get bits for this block
            bits = bits_array[start_idx:start_idx + 5]
            if len(bits) == 0:
                # No more bits to embed
                results.append(block)
                continue

            # Apply DCT
            dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')

            # Mid-frequency coefficients positions
            positions = [(1, 2), (2, 1), (2, 2), (1, 3), (3, 1)]

            # Modify coefficients based on bits
            for j, pos in enumerate(positions):
                if j < len(bits):
                    if bits[j] == '1':
                        # Ensure coefficient is positive
                        if dct_block[pos] > 0:
                            dct_block[pos] = max(dct_block[pos], alpha)
                        else:
                            dct_block[pos] = alpha
                    else:
                        # Ensure coefficient is negative
                        if dct_block[pos] < 0:
                            dct_block[pos] = min(dct_block[pos], -alpha)
                        else:
                            dct_block[pos] = -alpha

            # Apply inverse DCT
            idct_block = idct(idct(dct_block.T, norm='ortho').T, norm='ortho')
            results.append(idct_block)

        return results

    def dct_embed(self, img, binary_message):
        """Optimized DCT embedding using parallel processing"""
        # Convert PIL image to numpy array
        img_array = np.array(img)

        # Convert to YCbCr color space using vectorized function
        ycbcr = self.rgb_to_ycbcr_vectorized(img_array)

        # Get image dimensions
        height, width, _ = ycbcr.shape

        # Ensure dimensions are multiples of 8
        height_pad = height - (height % 8)
        width_pad = width - (width % 8)

        # Prepare message
        message_length = len(binary_message)

        # Collect blocks for batch processing
        blocks = []
        block_positions = []
        start_indices = []
        data_index = 0

        # Divide image into 8x8 blocks
        for y in range(0, height_pad, 8):
            for x in range(0, width_pad, 8):
                if data_index >= message_length:
                    break

                # Get Y channel block
                block = ycbcr[y:y + 8, x:x + 8, 0].copy()
                blocks.append(block)
                block_positions.append((y, x))

                # Store starting index for this block's bits
                start_indices.append(data_index)

                # Update data index (5 bits per block)
                bits_this_block = min(5, message_length - data_index)
                data_index += bits_this_block

        # Process blocks in parallel batches
        batch_size = 50  # Adjust based on testing
        for i in range(0, len(blocks), batch_size):
            batch_blocks = blocks[i:i + batch_size]
            batch_positions = block_positions[i:i + batch_size]
            batch_indices = start_indices[i:i + batch_size]

            # Process this batch
            modified_blocks = self.process_dct_block_batch(batch_blocks, binary_message, batch_indices)

            # Update blocks in the YCbCr array
            for modified_block, (y, x) in zip(modified_blocks, batch_positions):
                ycbcr[y:y + 8, x:x + 8, 0] = modified_block

        # Convert back to RGB using vectorized function
        rgb = self.ycbcr_to_rgb_vectorized(ycbcr)

        # Create new PIL image
        dct_img = Image.fromarray(rgb)
        return dct_img, data_index

    def extract_from_dct_blocks_batch(self, blocks):
        """Extract bits from multiple DCT blocks in parallel"""
        results = []

        for block in blocks:
            # Apply DCT
            dct_block = dct(dct(block.T, norm='ortho').T, norm='ortho')

            # Same positions used for embedding, if you add more zigzags, make changes to encryption too!
            positions = [(1, 2), (2, 1), (2, 2), (1, 3), (3, 1)]
            bits = ""

            # Extract bits based on coefficient signs
            for pos in positions:
                bits += '1' if dct_block[pos] > 0 else '0'

            results.append(bits)

        return results

    def dct_extract(self, img, message_length):
        """Optimized DCT extraction using parallel processing"""
        # Convert to numpy array
        img_array = np.array(img)

        # Convert to YCbCr
        ycbcr = self.rgb_to_ycbcr_vectorized(img_array)

        # Get dimensions
        height, width, _ = ycbcr.shape

        # Ensure dimensions are multiples of 8
        height_pad = height - (height % 8)
        width_pad = width - (width % 8)

        # Collect blocks for batch processing
        blocks = []
        bits_needed = message_length
        blocks_needed = (bits_needed + 4) // 5  # Each block can hold 5 bits

        # Collect required blocks
        for y in range(0, height_pad, 8):
            for x in range(0, width_pad, 8):
                if len(blocks) >= blocks_needed:
                    break

                # Get Y channel block
                block = ycbcr[y:y + 8, x:x + 8, 0]
                blocks.append(block)

        # Process blocks in parallel batches
        binary_message = ""
        batch_size = 50  # Adjust based on testing

        for i in range(0, len(blocks), batch_size):
            batch_blocks = blocks[i:i + batch_size]

            # Extract bits from this batch
            batch_results = self.extract_from_dct_blocks_batch(batch_blocks)

            # Combine results
            for bits in batch_results:
                remaining = bits_needed - len(binary_message)
                binary_message += bits[:min(5, remaining)]
                if len(binary_message) >= bits_needed:
                    break

        if debug_extract:
            print(f"DCT Extract binary message first 30 bits {binary_message[:30]}")

        return binary_message

    # ------------------ Optimized Hybrid Steganography Functions ------------------

    def hybrid_embed_message(self, image_path, message, password=None, progress_signal=None):
        """Optimized embedding with progress reporting"""
        temp_png_path = ""

        try:
            # Convert to absolute path and verify existence
            abs_path = os.path.abspath(image_path)
            if not os.path.exists(abs_path):
                raise FileNotFoundError(f"Image file not found at {abs_path}")

            # Progress bar updates
            try:
                if progress_signal:
                    progress_signal.emit(5)  # Starting
            except Exception as e:
                if progress_signal:
                    progress_signal.emit(-1)

            # Read Exif (cv2 do not support it)
            with Image.open(image_path) as img:
                exif_data = img.getexif().tobytes() if hasattr(img, 'getexif') else None

            # Load image with OpenCV for better performance
            cv_img = cv2.imread(abs_path)
            if cv_img is None:
                raise ValueError(f"Failed to load image: {abs_path}")

            # Convert from BGR to RGB (OpenCV uses BGR)
            cv_img_rgb = cv2.cvtColor(cv_img, cv2.COLOR_BGR2RGB)

            # Convert to PIL for compatibility with rest of code
            img = Image.fromarray(cv_img_rgb)

            if password:
                message_with_prefix = self._aes_encrypt(message, password)
            else:
                message_with_prefix = message

            checksum = self._calculate_checksum(message_with_prefix)
            full_message = f"{self.START_CHAR}{checksum}{message_with_prefix}{self.STOP_CHAR}"

            try:
                if progress_signal:
                    progress_signal.emit(10)  # Starting
            except Exception as e:
                if progress_signal:
                    progress_signal.emit(-1)

            # Vectorized binary conversion
            binary_message = ''.join(format(ord(char), '08b') for char in full_message)
            message_length = len(binary_message)
            length_binary = format(message_length, '032b')

            # Embed length using Adaptive LSB
            img_copy = img.copy()
            img_with_length, _ = self.adaptive_lsb_embed(img_copy, length_binary)

            try:
                if progress_signal:
                    progress_signal.emit(30)
            except Exception as e:
                if progress_signal:
                    progress_signal.emit(-1)

            # Embed message using DCT
            modified_img, embedded_bits = self.dct_embed(img_with_length, binary_message)

            # Check if entire message was embedded
            if embedded_bits < message_length:
                raise ValueError("Could not embed entire message. Try a larger image.")

            # Progress bar updates
            try:
                if progress_signal:
                    progress_signal.emit(50)
            except Exception as e:
                if progress_signal:
                    progress_signal.emit(-1)

            original_dir = os.path.dirname(abs_path)
            original_name = os.path.basename(abs_path)
            base_name, original_ext = os.path.splitext(original_name)
            original_ext = original_ext.lower()

            try:
                if progress_signal:
                    progress_signal.emit(70)
            except Exception as e:
                if progress_signal:
                    progress_signal.emit(-1)

            # Always embed to PNG first (temporary if original isn't PNG)
            temp_png_path = os.path.join(original_dir, f"temp_embedded_{base_name}.png")
            modified_img.save(temp_png_path, format='PNG')

            try:
                if progress_signal:
                    progress_signal.emit(90)
            except Exception as e:
                if progress_signal:
                    progress_signal.emit(-1)

            # Case 1: Original is PNG -> Keep PNG output
            if original_ext == '.png':
                final_path = os.path.join(original_dir, f"encrypted_{base_name}.png")
                os.replace(temp_png_path, final_path)  # Atomic rename

                try:
                    if progress_signal:
                        progress_signal.emit(100)
                except Exception as e:
                    if progress_signal:
                        progress_signal.emit(-1)

                return final_path

            # Case 2: Original is JPEG/BMP -> Convert back to original format
            else:
                final_path = os.path.join(original_dir, f"encrypted_{base_name}{original_ext}")

                # High-quality conversion for JPEG
                if original_ext in ('.jpg', '.jpeg'):
                    save_args = {
                        'format': 'JPEG',
                        'quality': 95,
                        'subsampling': 0,
                    }
                    if exif_data is not None:
                        save_args['exif'] = exif_data
                    Image.open(temp_png_path).save(final_path, **save_args)

                os.remove(temp_png_path)  # Clean up temporary PNG

                try:
                    if progress_signal:
                        progress_signal.emit(100)
                except Exception as e:
                    if progress_signal:
                        progress_signal.emit(-1)

                return final_path

        except Exception as e:
            # Clean up temp file if something failed
            if 'temp_png_path' in locals() and os.path.exists(temp_png_path):
                os.remove(temp_png_path)
                if progress_signal:
                    progress_signal.emit(-1)
            raise e

    def hybrid_extract_message(self, image_path, password=None, progress_callback=None):
        """Optimized extraction with progress reporting"""
        try:
            # Load image with OpenCV for better performance
            cv_img = cv2.imread(image_path)
            if cv_img is None:
                raise ValueError(f"Failed to load image: {image_path}")

            # Convert from BGR to RGB (OpenCV uses BGR)
            cv_img_rgb = cv2.cvtColor(cv_img, cv2.COLOR_BGR2RGB)

            # Convert to PIL for compatibility with rest of code
            img = Image.fromarray(cv_img_rgb)

            # Progress update
            if progress_callback:
                progress_callback(10)  # Length

            # First extract the message length using Adaptive LSB
            length_binary = self.adaptive_lsb_extract(img, 32)
            message_length = int(length_binary, 2)

            # Progress update
            if progress_callback:
                progress_callback(30)  # Analyzing DCT...

            # Extract main message using DCT
            binary_message = self.dct_extract(img, message_length)

            # Optimized binary to characters conversion
            chars = []
            for i in range(0, len(binary_message), 8):
                byte = binary_message[i:i + 8]
                if len(byte) == 8:  # Ensure we have a full byte
                    chars.append(chr(int(byte, 2)))
            extracted = ''.join(chars)

            # Progress update
            if progress_callback:
                progress_callback(50)  # Characters decoded

            if self.START_CHAR not in extracted or self.STOP_CHAR not in extracted:
                return None

            start_idx = extracted.find(self.START_CHAR) + 1
            stop_idx = extracted.find(self.STOP_CHAR)

            # Progress update
            if progress_callback:
                progress_callback(80)  # Verifying

            checksum = extracted[start_idx:start_idx + self.CHECKSUM_LENGTH]
            message_content = extracted[start_idx + self.CHECKSUM_LENGTH:stop_idx]

            if self._calculate_checksum(message_content) != checksum:
                return "INVALID_CHECKSUM"

            if message_content.startswith("AES"):
                if not password:
                    return "PASSWORD_REQUIRED"
                decrypted = self._aes_decrypt(message_content, password)
                return decrypted if decrypted else "DECRYPTION_FAILED"

            if progress_callback:
                progress_callback(100)  # Done

            return message_content

        except Exception as e:
            if progress_callback:
                progress_callback(-1)  # Error indicator
            if debug_extract:
                print(f"Extraction error: {str(e)}")
            return None


# ------------------------------------- The GUI part
class MainWindow(QMainWindow):
    def __init__(self, stego_machine):
        super().__init__()
        self.stego = stego_machine
        self.setWindowTitle("Steganography Tool version: " + VERSION)
        self.setGeometry(100, 100, 800, 550)
        self.setup_ui()
        self.create_menu()
        self.worker = None
        self.cancel_btn.clicked.connect(self.cancel_operation)

    def eventFilter(self, obj, event):
        if obj == self.preview_label and event.type() == QEvent.Type.Resize:
            self.update_preview_pixmap()
        return super().eventFilter(obj, event)

    def update_preview_pixmap(self):
        """Scales the pixmap to fit within the label's current size"""
        if hasattr(self, 'original_pixmap') and not self.original_pixmap.isNull():
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
            self.status_bar.showMessage("Cancelling...")
            self.cancel_btn.setEnabled(False)

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetDefaultConstraint)

        # Mode and Input Type in same row
        mode_input_row = QHBoxLayout()
        self.mode_group = QGroupBox("Operation Mode")
        mode_layout = QHBoxLayout()
        self.encrypt_radio = QRadioButton("Encrypt")
        self.decrypt_radio = QRadioButton("Decrypt")
        self.encrypt_radio.setChecked(True)
        mode_layout.addWidget(self.encrypt_radio)
        mode_layout.addWidget(self.decrypt_radio)
        self.mode_group.setLayout(mode_layout)
        mode_input_row.addWidget(self.mode_group)

        self.input_type_group = QGroupBox("Input Type")
        input_type_layout = QHBoxLayout()
        self.file_radio = QRadioButton("File")
        self.folder_radio = QRadioButton("Folder")
        self.file_radio.setChecked(True)
        input_type_layout.addWidget(self.file_radio)
        input_type_layout.addWidget(self.folder_radio)
        self.input_type_group.setLayout(input_type_layout)
        mode_input_row.addWidget(self.input_type_group)

        layout.addLayout(mode_input_row)

        # Path selection
        path_layout = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.browse_btn = QPushButton("Browse")
        path_layout.addWidget(self.path_edit)
        path_layout.addWidget(self.browse_btn)
        layout.addLayout(path_layout)

        # Message input
        self.message_label = QLabel("Secret Message:")
        self.message_input = QLineEdit()
        layout.addWidget(self.message_label)
        layout.addWidget(self.message_input)

        # Password row
        password_layout = QHBoxLayout()
        self.encrypt_checkbox = QCheckBox("Enable AES Encryption")
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Password (optional)")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(self.encrypt_checkbox)
        password_layout.addWidget(self.password_edit)
        layout.addLayout(password_layout)

        # Button row
        button_row = QHBoxLayout()
        self.action_btn = QPushButton("Encrypt")
        self.cancel_btn = QPushButton("Cancel")
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
        self.preview_label = QLabel()
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
        self.file_size_label = QLabel("Size: N/A")
        self.file_type_label = QLabel("Type: N/A")
        file_info_layout.addWidget(self.file_size_label)
        file_info_layout.addWidget(self.file_type_label)
        file_info_group.setLayout(file_info_layout)
        right_panel_layout.addWidget(file_info_group)

        self.exif_text = QTextEdit()
        self.exif_text.setReadOnly(True)
        right_panel_layout.addWidget(self.exif_text)

        # Splitter
        splitter.addWidget(right_panel_widget)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter)

        # Progress
        self.progress_label = QLabel("Ready")
        layout.addWidget(self.progress_label)
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Connections
        self.encrypt_radio.toggled.connect(self.update_ui_mode)
        self.browse_btn.clicked.connect(self.handle_browse)
        self.action_btn.clicked.connect(self.handle_action)
        self.file_radio.toggled.connect(self.update_path_field)
        self.encrypt_checkbox.stateChanged.connect(self.toggle_password_field)
        self.threadpool = QThreadPool()

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
            10: "Processing image...",
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
        self.password_edit.setEnabled(self.encrypt_checkbox.isChecked())

    def update_ui_mode(self):
        is_encrypt = self.encrypt_radio.isChecked()
        self.action_btn.setText("Encrypt" if is_encrypt else "Decrypt")
        self.message_label.setVisible(is_encrypt)
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
            filters = "Images (*.png *.jpg *.jpeg *.bmp)"
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
                if ext not in ['.png', '.jpg', '.jpeg', '.bmp']:
                    QMessageBox.warning(self,
                                        "Unsupported File Type",
                                        "Please select an image file (PNG, JPG, JPEG, BMP)"
                                        )
                    return
            self.path_edit.setText(path)
            self.update_preview(path)

    def update_preview(self, path):
        self.cancel_btn.setEnabled(False)
        if os.path.isfile(path):
            try:
                self.original_pixmap = QPixmap(path)
                if not self.original_pixmap.isNull():
                    self.update_preview_pixmap()
            except Exception as e:
                self.preview_label.clear()
                print(f"Error loading preview: {str(e)}")
                return
            finally:
                pass

            try:
                size_bytes = os.path.getsize(path)
                size_kb = size_bytes / 1024
                self.file_size_label.setText(f"Size: {size_kb:.2f} KB")

                file_ext = os.path.splitext(path)[1].upper().replace('.', '') or 'Unknown'
                self.file_type_label.setText(f"Type: {file_ext}")
            except Exception as e:
                self.file_size_label.setText(f"Size: Error {e}")
                self.file_type_label.setText(f"Type: Error")

            try:
                with Image.open(path) as img:
                    exif_info = self.get_exif_data(img)
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

    def get_exif_data(self, image):
        try:
            exif_data = image.getexif()
            if not exif_data:
                return "No EXIF data found (PNG file?)"

            exif_info = []
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, tag_id)
                exif_info.append(f"{tag_name}: {value}")
                image.close()
            return "\n".join(exif_info)
        except Exception as e:
            self.status_bar.showMessage(f"EXIF Error: {str(e)}")
            image.close()
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
        supported_ext = ('.png', '.jpg', '.jpeg', '.bmp')
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
            if hasattr(self, 'worker') and self.worker._is_cancelled:
                if hasattr(self, 'worker') and hasattr(self.worker.signals, 'progress'):
                    self.worker.signals.progress.emit(-1)  # Signal cancelation
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
Currently supports png and jp(e)g.
        
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
    machine = StegaMachine()
    app = QApplication(sys.argv)
    window = MainWindow(machine)
    window.show()
    sys.exit(app.exec())
