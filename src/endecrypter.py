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

# Audio encryption
import wave
from pydub import AudioSegment
from reedsolo import RSCodec, ReedSolomonError

debug_extract = True  # Set to False in production for speed
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

    # --- audio related ---

    def get_audio_embedding_capacity(self, complexity, threshold_low=300, threshold_high=1500):
        """Determine LSB capacity based on audio complexity.

        Args:
            self: Instance of StegaMachine.
            complexity: Complexity metric (e.g., standard deviation) of audio block.
            threshold_low: Lower complexity threshold for 1-bit embedding.
            threshold_high: Upper complexity threshold for 2-bit embedding.

        Returns:
            Integer capacity (1, 2, or 3 bits).
        """
        if complexity < threshold_low:
            return 1
        elif complexity < threshold_high:
            return 2
        else:
            return 3

    def audio_adaptive_lsb_embed(self, samples: np.ndarray, binary_message: str) -> Tuple[np.ndarray, int]:
        """Embed a binary message into audio samples using adaptive LSB.

        Args:
            samples: Numpy array of audio samples (int16).
            binary_message: Binary string to embed.

        Returns:
            Tuple of modified samples and number of embedded message bits.
        """
        message_bits = np.array([int(bit) for bit in binary_message], dtype=np.uint8)
        message_length = len(message_bits)
        sample_count = len(samples)

        if message_length > sample_count * 3:
            raise ValueError(f"Message too large: {message_length} bits but only {sample_count * 3} bits available.")

        modified_samples = samples.copy()
        data_index = 0

        block_size = 512
        start_sample = 1000  # Skip first ~20ms
        for i in range(start_sample, sample_count, block_size):
            if data_index >= message_length:
                break

            block = samples[i:i + block_size]
            if len(block) < 2:
                continue

            complexity = np.std(block)
            if complexity < 100:
                continue

            capacity = self.get_audio_embedding_capacity(complexity)

            if debug_embed:
                print(f"Block {i//block_size}: complexity={complexity}, capacity={capacity}")

            for j in range(len(block)):
                if data_index >= message_length:
                    break
                sample_idx = i + j

                mask = (1 << capacity) - 1
                modified_samples[sample_idx] &= ~mask

                bits_to_embed = 0
                for k in range(capacity):
                    if data_index < message_length:
                        bits_to_embed |= message_bits[data_index] << k
                        data_index += 1
                modified_samples[sample_idx] |= bits_to_embed

        if data_index < message_length:
            raise ValueError(f"Could only embed {data_index}/{message_length} bits.")

        return modified_samples, message_length

    def audio_adaptive_lsb_extract(self, samples: np.ndarray, message_length: int) -> str:
        """Extract a binary message from audio samples using adaptive LSB.

        Args:
            self: Instance of StegaMachine.
            samples: Numpy array of audio samples.
            message_length: Number of bits to extract.

        Returns:
            Extracted binary string.
        """
        if message_length > len(samples) * 3:
            raise ValueError(f"Requested {message_length} bits, but only {len(samples) * 3} bits available.")

        extracted_bits = []

        block_size = 512
        start_sample = 1000
        for i in range(start_sample, len(samples), block_size):
            if len(extracted_bits) >= message_length:
                break

            block = samples[i:i + block_size]
            if len(block) < 2:
                continue

            complexity = np.std(block)
            if complexity < 100:
                continue

            capacity = self.get_audio_embedding_capacity(complexity)

            for j in range(len(block)):
                if len(extracted_bits) >= message_length:
                    break
                sample = samples[i + j]
                for k in range(capacity):
                    if len(extracted_bits) < message_length:
                        bit = (sample >> k) & 1
                        extracted_bits.append(bit)

        return ''.join(str(bit) for bit in extracted_bits)[:message_length]

    def embed_audio_message(self, audio_path: str, message: str, password: str = None, progress_signal=None) -> str:
        """Embed a message into a WAV or MP3 file using fixed 1-bit LSB with Reed-Solomon.

        Args:
            audio_path: Path to input audio file.
            message: Message to embed.
            password: Optional password for AES encryption.
            progress_signal: Optional signal for progress updates.

        Returns:
            Path to the output audio file.
        """
        abs_path = os.path.abspath(audio_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Audio file not found at {abs_path}")

        file_ext = os.path.splitext(abs_path)[1].lower()
        if file_ext not in ('.wav', '.mp3'):
            raise ValueError(f"Unsupported audio format: {file_ext}")

        if progress_signal:
            try:
                progress_signal.emit(10)  # Preparing audio
            except Exception as e:
                if debug_embed:
                    print(f"Progress signal error: {str(e)}")

        # Prepare message
        message_with_prefix = self._aes_encrypt(message, password) if password else message
        checksum = self._calculate_checksum(message_with_prefix)
        full_message = f"{self.START_CHAR}{checksum}{message_with_prefix}{self.STOP_CHAR}"

        if progress_signal:
            try:
                progress_signal.emit(30)  # Encoding message
            except Exception as e:
                if debug_embed:
                    print(f"Progress signal error: {str(e)}")

        # Convert to bytes
        message_bytes = full_message.encode('utf-8')
        message_length = len(message_bytes)

        # Split into chunks and pad
        chunk_size = 50  # Max data bytes per RS chunk
        chunks = [message_bytes[i:i + chunk_size] for i in range(0, message_length, chunk_size)]
        padded_chunks = [bytearray(chunk) + bytearray(chunk_size - len(chunk)) if len(chunk) < chunk_size else chunk for
                         chunk in chunks]
        chunk_count = len(padded_chunks)

        # Apply Reed-Solomon to each chunk
        rs = RSCodec(100)  # Corrects up to 50 bytes
        rs_encoded_chunks = [rs.encode(chunk) for chunk in padded_chunks]

        if debug_embed:
            print(f"Message length: {message_length}")
            print(f"Chunk count: {chunk_count}")
            for i, chunk in enumerate(rs_encoded_chunks):
                print(f"Chunk {i} encoded bytes: {[hex(b) for b in chunk][:20]}...")
            message_binary_debug = ''.join(
                ''.join(format(byte, '08b') for byte in chunk) for chunk in rs_encoded_chunks)
            print(f"Message binary: {message_binary_debug[:100]}...")

        # Prepare header
        header = bytearray()
        header.extend(message_length.to_bytes(4, 'big'))
        header.extend((100).to_bytes(2, 'big'))  # Parity bytes per chunk
        header.extend(chunk_count.to_bytes(2, 'big'))  # Number of chunks
        header_rs = RSCodec(64)
        header_encoded = header_rs.encode(header)

        if debug_embed:
            header_binary_debug = ''.join(format(byte, '08b') for byte in header_encoded)
            print(f"Embedded header binary: {header_binary_debug}")
            print(f"Header encoded bytes: {[hex(b) for b in header_encoded]}")

        if progress_signal:
            try:
                progress_signal.emit(50)  # Embedding message
            except Exception as e:
                if debug_embed:
                    print(f"Progress signal error: {str(e)}")

        # Convert to binary
        header_binary = ''.join(format(byte, '08b') for byte in header_encoded)
        message_binary = ''.join(''.join(format(byte, '08b') for byte in chunk) for chunk in rs_encoded_chunks)
        total_binary = header_binary + message_binary

        if file_ext == '.wav':
            with wave.open(abs_path, 'rb') as wav_file:
                params = wav_file.getparams()
                sample_width = wav_file.getsampwidth()
                if sample_width != 2:
                    raise ValueError("Only 16-bit WAV files are supported.")
                samples = np.frombuffer(wav_file.readframes(wav_file.getnframes()), dtype=np.int16)

            # Check sample availability and complexity
            total_samples_needed = 4000 + len(total_binary)
            if total_samples_needed > len(samples):
                raise ValueError(f"Audio file too short: need {total_samples_needed} samples, have {len(samples)}")
            if debug_embed:
                block = samples[4000:min(6000, len(samples))]
                complexity = np.std(block)
                print(f"Complexity at sample 4000: {complexity}")
                if complexity < 100:
                    print("Warning: Low audio complexity may increase MP3 errors")

            # Embed header and message with fixed 1-bit LSB
            modified_samples = samples.copy()
            start_sample = 4000
            bits_embedded = 0
            for i, bit in enumerate(total_binary):
                modified_samples[start_sample + i] &= ~1
                modified_samples[start_sample + i] |= int(bit)
                bits_embedded += 1

            if debug_embed:
                print(f"Embedded {bits_embedded} bits from sample {start_sample} to {start_sample + bits_embedded - 1}")
                print(f"Header bits: {len(header_binary)}, Message bits: {len(message_binary)}")
                print(f"Total samples used: {start_sample + bits_embedded}")

            if bits_embedded < len(total_binary):
                raise ValueError(f"Could only embed {bits_embedded}/{len(total_binary)} bits.")

            if progress_signal:
                try:
                    progress_signal.emit(80)  # Saving audio
                except Exception as e:
                    if debug_embed:
                        print(f"Progress signal error: {str(e)}")

            output_path = os.path.join(os.path.dirname(abs_path), f"encrypted_{os.path.basename(abs_path)}")
            with wave.open(output_path, 'wb') as wav_out:
                wav_out.setparams(params)
                wav_out.writeframes(modified_samples.tobytes())

        else:
            audio = AudioSegment.from_mp3(abs_path)
            if audio.sample_width != 2:
                raise ValueError("Only 16-bit MP3 files are supported.")
            samples = np.array(audio.get_array_of_samples(), dtype=np.int16)

            # Check sample availability and complexity
            total_samples_needed = 4000 + len(total_binary)
            if total_samples_needed > len(samples):
                raise ValueError(f"Audio file too short: need {total_samples_needed} samples, have {len(samples)}")
            if debug_embed:
                block = samples[4000:min(6000, len(samples))]
                complexity = np.std(block)
                print(f"Complexity at sample 4000: {complexity}")
                if complexity < 100:
                    print("Warning: Low audio complexity may increase MP3 errors")

            # Embed header and message with fixed 1-bit LSB
            modified_samples = samples.copy()
            start_sample = 4000
            bits_embedded = 0
            for i, bit in enumerate(total_binary):
                modified_samples[start_sample + i] &= ~1
                modified_samples[start_sample + i] |= int(bit)
                bits_embedded += 1

            if debug_embed:
                print(f"Embedded {bits_embedded} bits from sample {start_sample} to {start_sample + bits_embedded - 1}")
                print(f"Header bits: {len(header_binary)}, Message bits: {len(message_binary)}")
                print(f"Total samples used: {start_sample + bits_embedded}")

            if bits_embedded < len(total_binary):
                raise ValueError(f"Could only embed {bits_embedded}/{len(total_binary)} bits.")

            if progress_signal:
                try:
                    progress_signal.emit(80)  # Saving audio
                except Exception as e:
                    if debug_embed:
                        print(f"Progress signal error: {str(e)}")

            modified_audio = AudioSegment(
                modified_samples.tobytes(),
                frame_rate=audio.frame_rate,
                sample_width=audio.sample_width,
                channels=audio.channels
            )

            output_path = os.path.join(os.path.dirname(abs_path), f"encrypted_{os.path.basename(abs_path)}")
            modified_audio.export(output_path, format="mp3", bitrate="320k")

        if progress_signal:
            try:
                progress_signal.emit(100)  # Encryption complete
            except Exception as e:
                if debug_embed:
                    print(f"Progress signal error: {str(e)}")

        return output_path

    def extract_audio_message(self, audio_path: str, password: str = None, progress_callback=None) -> str:
        """Extract a message from a WAV or MP3 file using fixed 1-bit LSB with Reed-Solomon.

        Args:
            audio_path: Path to audio file.
            password: Optional password for AES decryption.
            progress_callback: Optional callback for progress updates.

        Returns:
            Extracted message or error string.
        """
        abs_path = os.path.abspath(audio_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Audio file not found at {abs_path}")

        file_ext = os.path.splitext(abs_path)[1].lower()
        if file_ext not in ('.wav', '.mp3'):
            raise ValueError(f"Unsupported audio format: {file_ext}")

        if progress_callback:
            try:
                progress_callback(10)  # Loading audio
            except Exception as e:
                if debug_extract:
                    print(f"Progress callback error: {str(e)}")

        # Load samples
        if file_ext == '.wav':
            with wave.open(abs_path, 'rb') as wav_file:
                sample_width = wav_file.getsampwidth()
                if sample_width != 2:
                    raise ValueError("Only 16-bit WAV files are supported.")
                samples = np.frombuffer(wav_file.readframes(wav_file.getnframes()), dtype=np.int16)
        else:
            audio = AudioSegment.from_mp3(abs_path)
            if audio.sample_width != 2:
                raise ValueError("Only 16-bit MP3 files are supported.")
            samples = np.array(audio.get_array_of_samples(), dtype=np.int16)

        if debug_extract:
            print(f"Total samples available: {len(samples)}")

        if progress_callback:
            try:
                progress_callback(30)  # Extracting header
            except Exception as e:
                if debug_extract:
                    print(f"Progress callback error: {str(e)}")

        # Extract header (8 bytes + 64 parity = 72 bytes = 576 bits)
        header_rs = RSCodec(64)
        header_bits = 72 * 8
        header_binary = []
        start_sample = 4000
        for i in range(header_bits):
            if start_sample + i >= len(samples):
                if progress_callback:
                    progress_callback(-1)
                return "INVALID_LENGTH"
            bit = samples[start_sample + i] & 1
            header_binary.append(str(bit))
        header_binary = ''.join(header_binary)

        if debug_extract:
            print(f"Raw header binary: {header_binary}")
            print(f"Header binary length: {len(header_binary)}")

        header_bytes = bytearray()
        for i in range(0, len(header_binary), 8):
            byte = header_binary[i:i + 8]
            if len(byte) == 8:
                header_bytes.append(int(byte, 2))

        try:
            header_decoded = header_rs.decode(header_bytes)
            if isinstance(header_decoded, tuple):
                header_decoded = header_decoded[0]
            if debug_extract:
                corrected = header_rs.encode(header_decoded)
                corrections = sum(a != b for a, b in zip(header_bytes, corrected))
                print(f"Header RS corrections: {corrections}")
                print(f"Decoded header bytes: {[hex(b) for b in header_decoded]}")
                embedded_binary = ''.join(format(byte, '08b') for byte in header_rs.encode(header_decoded))
                bit_errors = sum(a != b for a, b in zip(embedded_binary, header_binary))
                print(f"Header bit errors: {bit_errors}")
            message_length = int.from_bytes(header_decoded[:4], 'big')
            parity_bytes = int.from_bytes(header_decoded[4:6], 'big')
            chunk_count = int.from_bytes(header_decoded[6:8], 'big')
        except ReedSolomonError as e:
            if debug_extract:
                print(f"Header RS decode error: {str(e)}")
            if progress_callback:
                progress_callback(-1)
            return "HEADER_RS_DECODE_FAILED"
        except (ValueError, IndexError) as e:
            if debug_extract:
                print(f"Header parse error: {str(e)}")
            if progress_callback:
                progress_callback(-1)
            return "INVALID_LENGTH"

        if progress_callback:
            try:
                progress_callback(50)  # Decoding message
            except Exception as e:
                if debug_extract:
                    print(f"Progress callback error: {str(e)}")

        # Extract RS-encoded message chunks
        rs = RSCodec(parity_bytes)
        chunk_size_bytes = 50 + parity_bytes
        rs_binary = []
        message_start = start_sample + header_bits
        for i in range(chunk_count * chunk_size_bytes * 8):
            if message_start + i >= len(samples):
                if progress_callback:
                    progress_callback(-1)
                return "NO_MESSAGE_FOUND"
            bit = samples[message_start + i] & 1
            rs_binary.append(str(bit))
        rs_binary = ''.join(rs_binary)

        if debug_extract:
            print(
                f"Extracting message from sample {message_start} to {message_start + chunk_count * chunk_size_bytes * 8 - 1}")
            print(f"Raw message binary: {rs_binary[:100]}...")
            print(f"Message binary length: {len(rs_binary)}")

        # Split into chunks
        rs_bytes_chunks = []
        for i in range(0, len(rs_binary), chunk_size_bytes * 8):
            chunk_binary = rs_binary[i:i + chunk_size_bytes * 8]
            chunk_bytes = bytearray()
            for j in range(0, len(chunk_binary), 8):
                byte = chunk_binary[j:j + 8]
                if len(byte) == 8:
                    chunk_bytes.append(int(byte, 2))
            rs_bytes_chunks.append(chunk_bytes)

        # Decode each chunk
        decoded_bytes = bytearray()
        for i, chunk_bytes in enumerate(rs_bytes_chunks):
            try:
                chunk_decoded = rs.decode(chunk_bytes)
                if isinstance(chunk_decoded, tuple):
                    chunk_decoded = chunk_decoded[0]
                if debug_extract:
                    corrected = rs.encode(chunk_decoded)
                    corrections = sum(a != b for a, b in zip(chunk_bytes, corrected))
                    print(f"Chunk {i} RS corrections: {corrections}")
                    embedded_binary = ''.join(format(byte, '08b') for byte in rs.encode(chunk_decoded))
                    bit_errors = sum(a != b for a, b in zip(embedded_binary, rs_binary[i:i + chunk_size_bytes * 8]))
                    print(f"Chunk {i} bit errors: {bit_errors}")
                decoded_bytes.extend(chunk_decoded[:min(len(chunk_decoded), message_length - len(decoded_bytes))])
            except ReedSolomonError as e:
                if debug_extract:
                    print(f"Chunk {i} RS decode error: {str(e)}")
                    embedded_binary = ''.join(format(byte, '08b') for byte in chunk_bytes)
                    bit_errors = sum(a != b for a, b in zip(embedded_binary, rs_binary[i:i + chunk_size_bytes * 8]))
                    print(f"Chunk {i} bit errors (failed): {bit_errors}")
                if progress_callback:
                    progress_callback(-1)
                return "RS_DECODE_FAILED"

        # Trim to message_length
        decoded_bytes = decoded_bytes[:message_length]

        if progress_callback:
            try:
                progress_callback(80)  # Verifying
            except Exception as e:
                if debug_extract:
                    print(f"Progress callback error: {str(e)}")

        # Convert bytes to string
        try:
            extracted = decoded_bytes.decode('utf-8')
        except UnicodeDecodeError:
            if progress_callback:
                progress_callback(-1)
            return "DECODE_ERROR"

        if self.START_CHAR not in extracted or self.STOP_CHAR not in extracted:
            if progress_callback:
                progress_callback(-1)
            return "NO_MESSAGE_FOUND"

        start_idx = extracted.find(self.START_CHAR) + 1
        stop_idx = extracted.find(self.STOP_CHAR)
        checksum = extracted[start_idx:start_idx + self.CHECKSUM_LENGTH]
        message_content = extracted[start_idx + self.CHECKSUM_LENGTH:stop_idx]

        if self._calculate_checksum(message_content) != checksum:
            if progress_callback:
                progress_callback(-1)
            return "INVALID_CHECKSUM"

        if message_content.startswith("AES"):
            if not password:
                if progress_callback:
                    progress_callback(-1)
                return "PASSWORD_REQUIRED"
            decrypted = self._aes_decrypt(message_content, password)
            if not decrypted:
                if progress_callback:
                    progress_callback(-1)
                return "DECRYPTION_FAILED"
            return decrypted

        if progress_callback:
            try:
                progress_callback(100)  # Decryption complete
            except Exception as e:
                if debug_extract:
                    print(f"Progress callback error: {str(e)}")

        return message_content
    # ------------------ Optimized Hybrid Steganography Functions ------------------

    def hybrid_embed_message(self, image_path: str, message: str, password: str = None, progress_signal=None) -> str:
        """Embed a message into an image or audio file.

        Args:
            image_path: Path to input image or audio file.
            message: Message to embed.
            password: Optional password for AES encryption.
            progress_signal: Optional signal for progress updates (images only).

        Returns:
            Path to the output file.
        """
        abs_path = os.path.abspath(image_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"File not found at {abs_path}")

        file_ext = os.path.splitext(abs_path)[1].lower()

        if file_ext in ('.wav', '.mp3'):
            return self.embed_audio_message(abs_path, message, password)

        # Existing image embedding code follows...
        temp_png_path = ""
        try:
            # Convert to absolute path and verify existence
            if progress_signal:
                try:
                    progress_signal.emit(5)  # Starting
                except (AttributeError, TypeError) as e:
                    if debug_embed:
                        print(f"Progress signal error: {type(e).__name__}: {str(e)}")
                    try:
                        progress_signal.emit(-1)
                    except:
                        pass

            # Read Exif (cv2 does not support it)
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
                        pass

            # Embed message using DCT
            modified_img, embedded_bits = self.dct_embed(img_with_length, binary_message)

            # Check if entire message was embedded
            if embedded_bits < message_length:
                raise ValueError("Could not embed entire message. Try a larger image.")

            if progress_signal:
                try:
                    progress_signal.emit(50)
                except (AttributeError, TypeError) as e:
                    if debug_embed:
                        print(f"Progress signal error: {type(e).__name__}: {str(e)}")
                    try:
                        progress_signal.emit(-1)
                    except:
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
                            pass
                return final_path

            # Case 2: Original is JPEG/BMP/WEBP -> Convert back to original format
            else:
                final_path = os.path.join(original_dir, f"encrypted_{base_name}{original_ext}")
                if original_ext in ('.jpg', '.jpeg'):
                    save_args = {
                        'format': 'JPEG',
                        'quality': 95,
                        'subsampling': 0,
                    }
                    if exif_data is not None:
                        save_args['exif'] = exif_data
                    Image.open(temp_png_path).save(final_path, **save_args)
                elif original_ext == '.webp':
                    save_args = {
                        'format': 'WEBP',
                        'lossless': True,
                    }
                    if exif_data is not None:
                        save_args['exif'] = exif_data
                    Image.open(temp_png_path).save(final_path, **save_args)
                elif original_ext == '.avif':
                    save_args = {
                        'format': 'AVIF',
                        'lossless': True,
                    }
                    if exif_data is not None:
                        save_args['exif'] = exif_data
                    Image.open(temp_png_path).save(final_path, **save_args)
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
                            pass
                return final_path

        except Exception as e:
            if 'temp_png_path' in locals() and os.path.exists(temp_png_path):
                os.remove(temp_png_path)
                if progress_signal:
                    progress_signal.emit(-1)
            raise e

    def hybrid_extract_message(self, image_path: str, password: str = None, progress_callback=None) -> str:
        """Extract a message from an image or audio file.

        Args:
            image_path: Path to image or audio file.
            password: Optional password for AES decryption.
            progress_callback: Optional callback for progress updates (images only).

        Returns:
            Extracted message or error string.
        """
        abs_path = os.path.abspath(image_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"File not found at {abs_path}")

        file_ext = os.path.splitext(abs_path)[1].lower()

        if file_ext in ('.wav', '.mp3'):
            return self.extract_audio_message(abs_path, password)

        try:
            # Load image with OpenCV for better performance
            cv_img = cv2.imread(image_path)
            if cv_img is None:
                raise ValueError(f"Failed to load image: {image_path}")

            # Convert from BGR to RGB (OpenCV uses BGR)
            cv_img_rgb = cv2.cvtColor(cv_img, cv2.COLOR_BGR2RGB)

            # Convert to PIL for compatibility with rest of code
            img = Image.fromarray(cv_img_rgb)

            if progress_callback:
                progress_callback(10)  # Length

            # First extract the message length using Adaptive LSB
            length_binary = self.adaptive_lsb_extract(img, 32)
            try:
                message_length = int(length_binary, 2)
            except ValueError:
                return "INVALID_LENGTH"

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

            if progress_callback:
                progress_callback(50)  # Characters decoded

            if self.START_CHAR not in extracted or self.STOP_CHAR not in extracted:
                return "NO_MESSAGE_FOUND"

            start_idx = extracted.find(self.START_CHAR) + 1
            stop_idx = extracted.find(self.STOP_CHAR)

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
            return f"EXTRACTION_ERROR: {str(e)}"

