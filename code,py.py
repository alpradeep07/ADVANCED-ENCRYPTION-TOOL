import os
from tkinter import Tk, filedialog, Button, Label, Entry, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

# Define constants
BLOCK_SIZE = 16  # AES block size (16 bytes)
KEY_SIZE = 32    # AES-256 requires a 32-byte key

# Function to generate AES-256 key from password
def generate_key(password, salt):
    return scrypt(password.encode(), salt, KEY_SIZE, N=2**14, r=8, p=1)

# Encrypt the file
def encrypt_file(input_file, password):
    try:
        # Generate salt and key
        salt = get_random_bytes(16)
        key = generate_key(password, salt)
        
        cipher = AES.new(key, AES.MODE_GCM)
        
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Write the encrypted file
        output_file = input_file + ".enc"
        with open(output_file, 'wb') as f:
            f.write(salt)  # Store the salt in the encrypted file
            f.write(cipher.nonce)  # Store the nonce
            f.write(tag)  # Store the tag
            f.write(ciphertext)  # Write the encrypted data
        
        messagebox.showinfo("Success", f"File encrypted successfully: {output_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Decrypt the file
def decrypt_file(input_file, password):
    try:
        with open(input_file, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        key = generate_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Write the decrypted file
        output_file = input_file.replace(".enc", ".dec")
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        messagebox.showinfo("Success", f"File decrypted successfully: {output_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Open file dialog
def open_file():
    file = filedialog.askopenfilename()
    if file:
        return file
    else:
        messagebox.showwarning("No File", "No file selected.")
        return None

# Main GUI
def create_gui():
    root = Tk()
    root.title("AES-256 Encryption Tool")

    Label(root, text="Enter Password").grid(row=0, column=0, padx=10, pady=10)
    password_entry = Entry(root, show="*", width=30)
    password_entry.grid(row=0, column=1, padx=10, pady=10)

    # Encrypt Button
    def encrypt_action():
        password = password_entry.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password.")
            return
        file = open_file()
        if file:
            encrypt_file(file, password)

    encrypt_button = Button(root, text="Encrypt File", command=encrypt_action)
    encrypt_button.grid(row=1, column=0, padx=10, pady=10)

    # Decrypt Button
    def decrypt_action():
        password = password_entry.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password.")
            return
        file = open_file()
        if file:
            decrypt_file(file, password)

    decrypt_button = Button(root, text="Decrypt File", command=decrypt_action)
    decrypt_button.grid(row=1, column=1, padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
