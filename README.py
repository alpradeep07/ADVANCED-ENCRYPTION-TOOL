To build a robust encryption tool for encrypting and decrypting files using advanced algorithms like AES-256, we will need to create an application with both the following components:

1. **Encryption and Decryption Logic**: The core of the tool will use the AES-256 algorithm for encrypting and decrypting files.
2. **User Interface (UI)**: A simple, user-friendly interface (GUI) where users can interact with the tool to select files and perform encryption/decryption operations.
3. **File Handling**: The application will allow users to select files, perform encryption, and save the encrypted or decrypted files.
4. **Security Features**: We should ensure that the encryption keys are securely handled.

Below is an example of how this could be implemented in Python using `PyQt5` for the UI and `cryptography` for the encryption. This will allow us to create a cross-platform application.

### Requirements:
1. **PyQt5** for GUI: Install it with:
   ```bash
   pip install pyqt5
   ```
2. **cryptography** for encryption and decryption: Install it with:
   ```bash
   pip install cryptography
   ```

### Implementation

```python
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog, QLabel, QLineEdit, QHBoxLayout
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

class EncryptionTool(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('File Encryption Tool')
        self.setGeometry(200, 200, 400, 250)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # UI components
        self.file_path_label = QLabel('No file selected')
        layout.addWidget(self.file_path_label)

        select_file_btn = QPushButton('Select File to Encrypt/Decrypt')
        select_file_btn.clicked.connect(self.select_file)
        layout.addWidget(select_file_btn)

        self.password_label = QLabel('Enter Password:')
        layout.addWidget(self.password_label)

        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        # Buttons for encryption and decryption
        self.encrypt_btn = QPushButton('Encrypt File')
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encrypt_btn)

        self.decrypt_btn = QPushButton('Decrypt File')
        self.decrypt_btn.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_btn)

        self.result_label = QLabel('')
        layout.addWidget(self.result_label)

        self.setLayout(layout)

    def select_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a File", "", "All Files (*);;Text Files (*.txt)", options=options)
        if file_path:
            self.file_path_label.setText(file_path)

    def generate_key_from_password(self, password: str):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        key = kdf.derive(password.encode())
        return key, salt

    def encrypt_file(self):
        file_path = self.file_path_label.text()
        password = self.password_input.text()

        if not file_path or not password:
            self.result_label.setText("Please provide both file and password.")
            return

        try:
            # Generate AES key from password
            key, salt = self.generate_key_from_password(password)

            with open(file_path, 'rb') as f:
                data = f.read()

            # Padding the data to be multiple of 128 bits (16 bytes)
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()

            # Generate IV (Initialization Vector)
            iv = os.urandom(16)

            # AES encryption using AES-256 and CBC mode
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Save encrypted data to file
            encrypted_file_path = file_path + ".enc"
            with open(encrypted_file_path, 'wb') as enc_file:
                enc_file.write(salt + iv + encrypted_data)

            self.result_label.setText(f"File encrypted successfully: {encrypted_file_path}")
        except Exception as e:
            self.result_label.setText(f"Error: {e}")

    def decrypt_file(self):
        file_path = self.file_path_label.text()
        password = self.password_input.text()

        if not file_path or not password:
            self.result_label.setText("Please provide both file and password.")
            return

        try:
            with open(file_path, 'rb') as enc_file:
                file_data = enc_file.read()

            salt, iv, encrypted_data = file_data[:16], file_data[16:32], file_data[32:]

            # Generate AES key from password using the salt
            key, _ = self.generate_key_from_password(password)

            # AES decryption using AES-256 and CBC mode
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Unpad the data
            unpadder = padding.PKCS7(128).unpadder()
            original_data = unpadder.update(decrypted_data) + unpadder.finalize()

            # Save the decrypted file
            decrypted_file_path = file_path + ".dec"
            with open(decrypted_file_path, 'wb') as dec_file:
                dec_file.write(original_data)

            self.result_label.setText(f"File decrypted successfully: {decrypted_file_path}")
        except Exception as e:
            self.result_label.setText(f"Error: {e}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = EncryptionTool()
    window.show()
    sys.exit(app.exec_())
```

### How It Works:

1. **File Selection**: The user can choose a file using the `Select File to Encrypt/Decrypt` button.
2. **Password Input**: The user provides a password for encryption/decryption.
3. **Encryption**:
   - The file is read, and the data is padded to fit AES's block size (128 bits).
   - AES-256 is used with CBC (Cipher Block Chaining) mode, which requires a 256-bit key and a 128-bit initialization vector (IV).
   - The encrypted file is saved with a `.enc` extension.
4. **Decryption**:
   - The encrypted file is read, the salt and IV are extracted, and the key is derived from the password using PBKDF2.
   - The file is decrypted, unpadded, and saved with a `.dec` extension.

### Key Points:
- **AES-256** is used for strong encryption.
- **PBKDF2** (Password-Based Key Derivation Function 2) is used to derive the encryption key from the password, adding salt for extra security.
- **CBC Mode** is chosen for encryption, which provides confidentiality but requires careful handling of padding and IVs.
- The program creates a `.enc` file for encrypted data and `.dec` for decrypted data, ensuring the original file is not overwritten.

This is a basic version, and additional features could include error handling improvements, better UI features (progress bars, etc.), and key management for added security.