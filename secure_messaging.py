import os
import base64
import json
import time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Load RSA keys
def load_keys():
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return private_key, public_key

# AES helpers
def generate_aes_key():
    return os.urandom(32)

def encrypt_aes(key, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv, ciphertext

def decrypt_aes(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Encrypt text message
def encrypt_message(message, receiver_public_key):
    aes_key = generate_aes_key()
    iv, ciphertext = encrypt_aes(aes_key, message.encode())

    encrypted_key = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    data = {
        "type": "text",
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "aes_key": base64.b64encode(encrypted_key).decode(),
        "timestamp": time.time()
    }

    filename = f"messages/msg_{int(time.time())}.json"
    with open(filename, "w") as f:
        json.dump(data, f)
    print(f"[+] Message encrypted and saved to {filename}")

# Encrypt file
def encrypt_file(filepath, receiver_public_key):
    if not os.path.exists(filepath):
        print("[!] File not found.")
        return

    with open(filepath, "rb") as f:
        file_data = f.read()

    aes_key = generate_aes_key()
    iv, ciphertext = encrypt_aes(aes_key, file_data)

    encrypted_key = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    file_ext = os.path.splitext(filepath)[1]

    data = {
        "type": "file",
        "file_ext": file_ext,
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "aes_key": base64.b64encode(encrypted_key).decode(),
        "timestamp": time.time()
    }

    filename = f"messages/file_{int(time.time())}.json"
    with open(filename, "w") as f:
        json.dump(data, f)
    print(f"[+] File encrypted and saved to {filename}")

# Decrypt message or file
def decrypt_data(file, receiver_private_key, expire_seconds=300):
    with open(file, "r") as f:
        data = json.load(f)

    # Expiry check
    if time.time() - data["timestamp"] > expire_seconds:
        print("[!] Data expired and cannot be read.")
        os.remove(file)
        return

    encrypted_key = base64.b64decode(data["aes_key"])
    aes_key = receiver_private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    iv = base64.b64decode(data["iv"])
    ciphertext = base64.b64decode(data["ciphertext"])
    plaintext = decrypt_aes(aes_key, iv, ciphertext)

    if data["type"] == "text":
        print(f"[+] Decrypted message: {plaintext.decode()}")
    else:
        out_file = f"messages/decrypted_{int(time.time())}{data['file_ext']}"
        with open(out_file, "wb") as f:
            f.write(plaintext)
        print(f"[+] Decrypted file saved as {out_file}")

    os.remove(file)

# CLI menu
if __name__ == "__main__":
    priv, pub = load_keys()
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    print("3. Encrypt a file")
    print("4. Decrypt a file")
    choice = input("Choose: ")

    if choice == "1":
        msg = input("Enter message: ")
        encrypt_message(msg, pub)
    elif choice == "2":
        filename = input("Enter file path: ")
        decrypt_data(filename, priv)
    elif choice == "3":
        filepath = input("Enter file path to encrypt: ")
        encrypt_file(filepath, pub)
    elif choice == "4":
        filename = input("Enter encrypted file path: ")
        decrypt_data(filename, priv)

