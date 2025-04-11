# Steganography Tool

This is a cross-platform (Windows and Linux) GUI steganography tool that supports hybrid embedding techniques, combining **adaptive LSB** and **DCT-based** methods to hide secret messages within images. Optional **AES encryption** is also supported to secure the hidden message. The tool preserves image quality and **EXIF metadata**, allowing the output image to retain key info from the original.

**Supported formats:** `.jpg`, `.jpeg`, `.png`, `.bmp`, `.webp`

📺 **Video demo:** [https://www.youtube.com/@Controvergent](https://www.youtube.com/@Controvergent)  
🖼️ **Samples:** Found in the `samples/` folder — password is `qwerty`.

---

## Motivation

This project started in April 2025, inspired by a LinkedIn discussion with **Santeri Kallio**, where the topic was:

> *"ChatGPT:llä tehtyihin kuviin lisätään dataa mikä paljastaa että tekoäly on generoinut sen."*  
> *(Posted on 4.4.2025)*

While **C2PA** provides robust AI image attribution, I wanted to explore the broader potential of hiding extra data inside images—whether it’s secret messages, watermarks, or provenance data. This tool demonstrates how hidden content can be embedded *without visibly degrading* the image.

---

## Features

### 🧠 Hybrid Embedding Techniques

- **Adaptive LSB:** Dynamically adjusts bit depth based on local image complexity.
- **DCT-based embedding:** Uses mid-frequency DCT coefficients for more robust hiding.

### 🔐 Optional AES Encryption

- Encrypt messages with AES (CBC mode)
- Uses `PBKDF2` for key derivation
- Random salt and IV are automatically managed

### 🧾 Metadata Preservation

- Original **EXIF metadata** is preserved in the final output image

### 🖥️ GUI Interface

- Built using **PyQt6**
- Simple interface for file selection, encryption/decryption, and message entry

### 💻 Cross-Platform

- Tested and packaged for both **Windows** and **Linux**
- Built using **Nuitka**
  - Linux binary: `bin/` directory (run with `chmod +x`)
  - Windows EXE: `exe/` directory
Note! Download RAW to get binary file!
---

## Requirements (for source version)

Install Python dependencies (Python 3.8+):

\`\`\`bash
pip install -r requirements.txt
\`\`\`

Main dependencies:

- Python ≥ 3.8
- PyQt6
- Pillow
- OpenCV-Python
- NumPy
- SciPy
- PyCryptodome

---

## Installation (from source)

\`\`\`bash
git clone https://github.com/divergentti/steganography.git
cd steganography

# Optional virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt
\`\`\`

The code is modular and split into:
- GUI layer
- Encryption/decryption engine

Comments and optional debug flags are included.

---

## Usage

Run the main application:

\`\`\`bash
python Stegatool-v0-1-0.py
\`\`\`

### Encryption Mode

1. Select image or folder
2. Enter message
3. (Optional) Enable AES and set password
4. Click **Encrypt**

### Decryption Mode

1. Select encrypted image
2. (If used) Enter password
3. Click **Decrypt**

✅ The tool uses checksums for message integrity and preserves EXIF metadata during processing.

---

## Future Work

- Add CLI support to `endecrypter.py`
- Expand image format support
- Add a **Settings** page:
  - Custom DCT coefficient positions
  - Batch size
  - Embedding parameters

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
