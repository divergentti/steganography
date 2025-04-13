# Steganography Tool

A powerful, user-friendly tool for hiding and extracting secret messages in images and audio files using advanced steganography techniques. Version 0.1.1 brings exciting support for WAV (16-bit PCM) and MP3 files, alongside improved progress feedback for a smoother experience.

© 2025 Jari Hiltunen / Divergentti - Licensed under MIT.

## Features

- **Image Support**: Embed/extract messages in PNG, JPG, JPEG, BMP, and WEBP using hybrid LSB + DCT methods.
- **Audio Support**: New in v0.1.1! Hide messages in WAV (16-bit PCM) and MP3 files with fixed 1-bit LSB and Reed-Solomon error correction (~33% per chunk).
- **AES Encryption**: Optional password protection for secure message embedding.
- **GUI Feedback**: Real-time progress updates for both image and audio processing (e.g., "Embedding message...", "Encryption complete!").
- **Preserves Metadata**: Maintains image EXIF data; non-destructive to original files.
- **Robustness**: Survives common image conversions; audio embedding reliable in WAV, with MP3 handling lossy compression challenges.
- **Applications**: Secure communication, watermarking, metadata embedding.

*Note*: Steganography hides data but doesn't guarantee undetectability. For sensitive data, always use AES encryption with a strong password.


## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/divergentti/steganography.git
   cd steganography

2. Make virtual environment and activate it:
    python -m venv venv
    source venv/bin/activate  # Windows: venv\Scripts\activate

3. Install dependecies:
    pip install pillow pyqt6 pycryptodome numpy scipy opencv-python pydub reedsolo

    # or pip install -r requirements.txt

4.  Run the tool python Stegatool-v0-1-1.py

Requirements: Python 3.8+, tested on Windows and Linux.

If I manage to free up space (now almost 1Gb) so that I can upload binaries:

    Linux: bin/stegatool.bin (run chmod +x bin/stegatool first).
    Windows: exe/stegatool.exe.
    Note: Download binaries as raw files from the GitHub repository.

## Usage

Encrypt

    Launch the GUI and select "Encrypt" mode.
    Choose an image (PNG, JPG, etc.), WAV, or MP3 file, or an image folder.
    Enter your secret message.
    (Optional) Enable AES encryption and set a password.
    Click "Encrypt" to generate encrypted_[filename].

Decrypt

    Select "Decrypt" mode.
    Choose the encrypted image or audio file.
    Enter the password if AES was used.
    Click "Decrypt" to reveal the hidden message.

Tips

    Use WAV for reliable audio embedding; MP3 is lossy and less dependable.
    Test extraction to verify embedding success.
    Check "Help > About" in the GUI for detailed guidance.

---

## Motivation

This project started in April 2025, inspired by a LinkedIn discussion with **Santeri Kallio**, where the topic was:

> *"ChatGPT:llä tehtyihin kuviin lisätään dataa mikä paljastaa että tekoäly on generoinut sen."*  
> *(Posted on 4.4.2025)*

While **C2PA** provides robust AI image attribution, I wanted to explore the broader potential of hiding extra data inside images—whether it’s secret messages, watermarks, or provenance data. This tool demonstrates how hidden content can be embedded *without visibly degrading* the image.

---

## Technical Details

    Images:
        Hybrid LSB (adaptive, 1-3 bits/pixel) + DCT embedding.
        Capacity: ~1 bit/pixel.
        Formats: PNG (lossless, best), JPG/WEBP (lossy, riskier).
    Audio:
        Fixed 1-bit LSB, 4000-sample offset, 50-byte chunks with 100-byte parity.
        Capacity: 1 bit/sample.
        Formats: WAV (lossless, reliable), MP3 (320kbps recommended, ~33% error correction).
    Security: AES-CBC with PBKDF2; checksums ensure integrity.

See endecrypter.py for implementation details and debug options.

---

## Contributing

Contributions welcome!  
Please fork the repo and submit a pull request.

➡️ Before larger changes, open an issue to discuss your idea.

---

## License

This project is licensed under the **MIT License**.

---

## Acknowledgments

- **Santeri Kallio** – for the initial spark and discussion on LinkedIn
- Open-source libraries:
  - PyQt6
  - Pillow
  - OpenCV
  - NumPy
  - SciPy
  - PyCryptodome
- Grok 3 for unbeliviably good refractoring and advices for audio encryption!


## Changelog

Version 0.1.1 (April 13, 2025)

    Added: Support for WAV (16-bit PCM) and MP3 embedding/extraction using fixed 1-bit LSB with Reed-Solomon error correction.
    Improved: GUI now shows progress for audio processing (e.g., "Preparing audio...", "Decryption complete!").
    Updated: Help guide includes audio support details and MP3 lossy compression warning.
    Fixed: Enhanced error handling for audio extraction (e.g., checksum failures, invalid headers).
    Optimized: Maintains performance for large files with threaded processing.

See endecrypter.py for technical details and debug options.

