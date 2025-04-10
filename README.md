**Steganography Tool**

This project is a cross-platform (Windows and Linux) GUI steganography tool that supports hybrid embedding techniques, combining adaptive LSB and DCT-based methods to hide secret messages within images. It also offers optional AES encryption to secure the hidden message. The tool preserves image quality and metadata—such as EXIF data—allowing the final file to retain important information from the original image.

Video about how this application works at my channel https://www.youtube.com/@Controvergent

Sample images under samples. Password is qwerty.

**Motivation**

The project was initiated last week, inspired by a discussion on LinkedIn with Santeri Kallio. While C2PA markings provide a robust way to authenticate AI-generated images, I believed that the potential to hide additional information—such as secret messages, digital watermarks, or provenance data—in images is much greater. This tool demonstrates that hidden data can be seamlessly integrated into images without noticeably affecting their quality.

**Features**

Hybrid Embedding Techniques: 

- Adaptive LSB: Uses an adaptive algorithm to choose the number of least significant bits based on local image complexity.
- DCT-based Embedding: Incorporates discrete cosine transform (DCT) to hide bits within the mid-frequency coefficients for enhanced robustness.

Optional AES Encryption:
- Secure your hidden message with AES encryption. The tool uses PBKDF2 for key derivation and includes proper initialization vector (IV) and salt handling.

EXIF Data Preservation:
- Original image EXIF metadata is extracted and preserved during the embedding process so that important file information is retained in the final output.

GUI Application:
- Built with PyQt6, offering a user-friendly interface for selecting files, entering messages, and monitoring progress.

Cross-Platform Compatibility:
- Designed for Windows and Linux. Linux executable onefile is found under bin-directory (115,6 Mb), packaged with nuitka

**Requirements**

If you prefer to test from source code (under src), you need:

Python 3.8 or higher
PyQt6
Pillow
OpenCV-Python
NumPy
SciPy
PyCryptodome

**Installation if using source code**

1. Clone the repository: git clone https://github.com/divergentti/steganography.git
cd steganography
2. Create a virtual environment (optional but recommended):
- python -m venv venv
- source venv/bin/activate  # On Windows: venv\Scripts\activate
- Install the required packages: pip install -r requirements.txt

The source code is commented and with options to enable debugging.

**Usage**

Run the main application file: python stegaGUI-pwd.py

The GUI offers two modes:

Encrypt:
     Select a file or folder.
     Enter your secret message.
     (Optional) Enable AES encryption and set a password.
      Click "Encrypt" to hide your message in the image.

Decrypt:
    Select the encrypted image.
    (If required) Enter the password.
    Click "Decrypt" to extract and (if applicable) decrypt the message.

The tool processes the image by embedding the message (including a checksum for integrity) and preserves any EXIF metadata from the original file.

**Future Work**

Add support for webp, bmp etc.

**Contributing**
Contributions are welcome! Feel free to fork the repository and submit pull requests. 
Please open an issue first to discuss changes you’d like to see.

**License**
This project is licensed under the MIT License.

**Acknowledgments**
Santeri Kallio: A special thanks for sparking the idea on LinkedIn with his post on using C2PA markings for AI-generated images.

Open Source Libraries: Thanks to the developers of PyQt6, Pillow, OpenCV, NumPy, SciPy, and PyCryptodome for making this project possible.
