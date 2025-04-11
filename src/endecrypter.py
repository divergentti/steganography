# Copyright (c) 2025 Jari Hiltunen / GitHub Divergentti
#
# Steganography Tool - Encrypter and Decrypter
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

import os
from PIL import Image
from typing import Tuple
import numpy as np
from scipy.fftpack import dct, idct
import cv2
import zlib
import functools

# pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from concurrent.futures import ThreadPoolExecutor  # For parallelization

debug_extract = False  # Set to False in production for speed
debug_crypto = False  # Set to False in production for speed
debug_embed = False  # Set to False in production for speed

if debug_embed or debug_extract or debug_crypto:
    import faulthandler
    faulthandler.enable()

# Number of worker threads for parallel processing
NUM_WORKERS = max(1, os.cpu_count() - 1)  # Leave one core free for system

class StegaMachine:
    START_CHAR = '\x02'  # Use non-printable Unicode characters
    STOP_CHAR = '\x03'
    CHECKSUM_LENGTH = 16  # Using 16-bit checksum

    def __init__(self):
        # Initialize the thread pool for parallel processing
        self.thread_pool = ThreadPoolExecutor(max_workers=NUM_WORKERS)
        # Cache for complexity calculations to avoid redundant work
        self.complexity_cache = {}

    @staticmethod
    def _calculate_checksum(message):
        return bin(zlib.crc32(message.encode()) & 0xffff)[2:].zfill(16)

    @staticmethod
    def _aes_encrypt(message, password):
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = PBKDF2(password, salt, dkLen=32, count=100000)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        if debug_crypto:
            print(f"AES{salt.hex()}{iv.hex()}{ct_bytes.hex()}")
        return f"AES{salt.hex()}{iv.hex()}{ct_bytes.hex()}"

    @staticmethod
    def _aes_decrypt(ciphertext, password):
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
        except (ValueError, IndexError, TypeError, UnicodeDecodeError) as e:
            # Specific exceptions we expect and understand
            if debug_crypto:
                print(f"Expected decryption error: {type(e).__name__}: {str(e)}")
            return None
        except Exception as e:
            # Unexpected exceptions - consider logging these differently
            if debug_crypto:
                print(f"Unexpected decryption error: {type(e).__name__}: {str(e)}")
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

    def adaptive_lsb_embed(self, img: Image.Image, binary_message: str) -> Tuple[Image.Image, int]:
        """Vectorized adaptive LSB embedding with improved structure and error handling

        Args:
            img: PIL Image to embed the message into
            binary_message: Binary string representation of the message

        Returns:
            Tuple containing the modified image and number of embedded bits

        Raises:
            ValueError: If the image cannot accommodate the message
        """
        # Convert PIL image to numpy array
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

        # Check if we embedded the entire message
        if data_index < message_length:
            raise ValueError(f"Could only embed {data_index}/{message_length} bits. Image too small for message.")

        # Apply all modified pixels to a copy of the original image
        result_array = np.array(img).copy()  # Create copy to avoid modifying original
        for y, x, pixel in modified_pixels:
            result_array[y, x] = pixel

        # Convert back to PIL Image
        result_img = Image.fromarray(result_array)

        return result_img, data_index

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

    @staticmethod
    def rgb_to_ycbcr_vectorized(img_array):
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

    @staticmethod
    def ycbcr_to_rgb_vectorized(ycbcr_array):
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

    @staticmethod
    def process_dct_block_batch(blocks, bits_array, start_indices, alpha=5):
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

    @staticmethod
    def extract_from_dct_blocks_batch(blocks):
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

            if progress_signal:
                try:
                    progress_signal.emit(5)  # Starting
                except (AttributeError, TypeError) as e:
                    if debug_embed:
                        print(f"Progress signal error: {type(e).__name__}: {str(e)}")
                    try:
                        progress_signal.emit(-1)
                    except:
                        # Last resort - can't even send error code
                        pass

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

            if progress_signal:
                try:
                    progress_signal.emit(10)  # Starting
                except (AttributeError, TypeError) as e:
                    if debug_embed:
                        print(f"Progress signal error: {type(e).__name__}: {str(e)}")
                    try:
                        progress_signal.emit(-1)
                    except:
                        # Last resort - can't even send error code
                        pass
            # Vectorized binary conversion
            binary_message = ''.join(format(ord(char), '08b') for char in full_message)
            message_length = len(binary_message)
            length_binary = format(message_length, '032b')

            # Embed length using Adaptive LSB
            img_copy = img.copy()
            img_with_length, _ = self.adaptive_lsb_embed(img_copy, length_binary)

            if progress_signal:
                try:
                    progress_signal.emit(30)
                except (AttributeError, TypeError) as e:
                    if debug_embed:
                        print(f"Progress signal error: {type(e).__name__}: {str(e)}")
                    try:
                        progress_signal.emit(-1)
                    except:
                        # Last resort - can't even send error code
                        pass

            # Embed message using DCT
            modified_img, embedded_bits = self.dct_embed(img_with_length, binary_message)

            # Check if entire message was embedded
            if embedded_bits < message_length:
                raise ValueError("Could not embed entire message. Try a larger image.")

            # Progress bar updates
            if progress_signal:
                try:
                    progress_signal.emit(50)
                except (AttributeError, TypeError) as e:
                    if debug_embed:
                        print(f"Progress signal error: {type(e).__name__}: {str(e)}")
                    try:
                        progress_signal.emit(-1)
                    except:
                        # Last resort - can't even send error code
                        pass

            original_dir = os.path.dirname(abs_path)
            original_name = os.path.basename(abs_path)
            base_name, original_ext = os.path.splitext(original_name)
            original_ext = original_ext.lower()

            if progress_signal:
                try:
                    progress_signal.emit(70)
                except (AttributeError, TypeError) as e:
                    if debug_embed:
                        print(f"Progress signal error: {type(e).__name__}: {str(e)}")
                    try:
                        progress_signal.emit(-1)
                    except:
                        # Last resort - can't even send error code
                        pass

            # Always embed to PNG first (temporary if original isn't PNG)
            temp_png_path = os.path.join(original_dir, f"temp_embedded_{base_name}.png")
            modified_img.save(temp_png_path, format='PNG')

            if progress_signal:
                try:
                    progress_signal.emit(90)
                except (AttributeError, TypeError) as e:
                    if debug_embed:
                        print(f"Progress signal error: {type(e).__name__}: {str(e)}")
                    try:
                        progress_signal.emit(-1)
                    except:
                        # Last resort - can't even send error code
                        pass

            # Case 1: Original is PNG -> Keep PNG output
            if original_ext == '.png':
                final_path = os.path.join(original_dir, f"encrypted_{base_name}.png")
                os.replace(temp_png_path, final_path)  # Atomic rename

                if progress_signal:
                    try:
                        progress_signal.emit(100)
                    except (AttributeError, TypeError) as e:
                        if debug_embed:
                            print(f"Progress signal error: {type(e).__name__}: {str(e)}")
                        try:
                            progress_signal.emit(-1)
                        except:
                            # Last resort - can't even send error code
                            pass

                return final_path

            # Case 2: Original is JPEG/BMP/WEBP -> Convert back to original format
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

                # Lossless conversion for WebP
                elif original_ext == '.webp':
                    save_args = {
                        'format': 'WEBP',
                        'lossless': True,
                    }
                    if exif_data is not None:
                        save_args['exif'] = exif_data
                    Image.open(temp_png_path).save(final_path, **save_args)
                # Lossless conversion for AVIF
                elif original_ext == '.avif':
                    save_args = {
                    'format': 'AVIF',
                    'lossless': True,
                }
                    if exif_data is not None:
                        save_args['exif'] = exif_data
                    Image.open(temp_png_path).save(final_path, **save_args)

                # Default conversion for other formats (e.g., BMP)
                else:
                    Image.open(temp_png_path).save(final_path)

                os.remove(temp_png_path)  # Clean up temporary PNG

                if progress_signal:
                    try:
                        progress_signal.emit(100)
                    except (AttributeError, TypeError) as e:
                        if debug_embed:
                            print(f"Progress signal error: {type(e).__name__}: {str(e)}")
                        try:
                            progress_signal.emit(-1)
                        except:
                            # Last resort - can't even send error code
                            pass

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

