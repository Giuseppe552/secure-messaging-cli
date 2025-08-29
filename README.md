
# 🔐 Secure Messaging CLI  

> End-to-End Encrypted Messaging in Python — hybrid **RSA + AES** with file/message encryption and expiring messages.  

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python&logoColor=white)  
![License](https://img.shields.io/badge/License-MIT-green.svg)  
![Status](https://img.shields.io/badge/Status-Active-success)  

---

## 🚀 Overview  
This project is a **command-line tool** that demonstrates how end-to-end encryption (E2EE) works in practice.  
Using a **hybrid cryptosystem (RSA for keys + AES for content)**, users can securely:  

- Generate RSA keypairs  
- Encrypt & decrypt **messages**  
- Encrypt & decrypt **files**  
- Create **expiring messages** that self-delete after reading  

⚡ Designed for **educational & research purposes only** — to help engineers, security students, and businesses understand the mechanics of secure communication.  

---

## 📸 Demo  

### Encrypt a message  
```bash
python secure_messaging.py
````

```
1. Encrypt a message
2. Decrypt a message
3. Encrypt a file
4. Decrypt a file
Choose: 1
Enter message: hello this is encrypted
[+] Message encrypted and saved to messages/msg_1756425023.json
```

### Decrypt a message

```bash
python secure_messaging.py
```

```
1. Encrypt a message
2. Decrypt a message
Choose: 2
Enter file path: messages/msg_1756425023.json
[+] Decrypted message: hello this is encrypted
```

---

## ⚙️ Installation

Clone the repo and install dependencies:

```bash
git clone https://github.com/Giuseppe552/secure-messaging-cli.git
cd secure-messaging-cli
python -m pip install -r requirements.txt
```

---

## 📂 Project Structure

```
secure-messaging-cli/
│── generate_keys.py     # Generates RSA keypair (public/private)
│── secure_messaging.py  # CLI for message/file encryption & decryption
│── requirements.txt     # Dependencies (cryptography)
│── messages/            # Stores encrypted JSON messages
│── README.md            # Documentation
```

---

## 💡 Business Use Case

Secure communication is **not optional** in 2025.

* 📧 **Email interception** → Sensitive deals leaked.
* 🏦 **Finance** → Fraud from insecure data transfers.
* 🏛 **Government & Legal** → Citizen data exposed.

This CLI demonstrates how even a **lightweight Python tool** can protect confidentiality, prevent **man-in-the-middle attacks**, and reinforce **trust as a business moat**.

---

## 🛠 Roadmap

* [ ] Add **Elliptic Curve Cryptography (ECC)** support
* [ ] Implement **steganography** (hide messages in images)
* [ ] Add **secure key exchange over QR codes**
* [ ] Enable **group messaging mode** with shared keys
* [ ] Web-based interface (Flask/FastAPI demo)

---

## ⚠️ Disclaimer

This tool is for **educational and research purposes only**.
It is **not production-ready** and should not be used for securing real-world sensitive data.

---

## ✨ Author

👤 **Giuseppe Giona**

* GitHub: [@Giuseppe552](https://github.com/Giuseppe552)
* LinkedIn: [Giuseppe Giona](https://linkedin.com/in/giuseppe552)

---

> *"Security is not just code — it’s leverage. Trust compounds faster than revenue."* 🔑

```

