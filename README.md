# 🔐 SimplePGP Client

A simple, modern, and secure graphical interface to manage, create, encrypt, decrypt, and sign messages with PGP!

---

## ✅ Features

- **PGP key generation** (optionally protected by passphrase)
- **Encrypt and decrypt messages** with public/private keys
- **Digital signature** and **signature verification**
- **Key protection**: keys are saved in an encrypted file unique to each computer
- **Modern interface** (Sun Valley ttk theme, dark mode!)

---

## 🚀 Installation

1. **Clone the repo:**
    ```bash
    git clone https://github.com/<your-username>/mypgp.git
    cd mypgp
    ```

2. **Create a virtual environment (optional but recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate      # on Linux/Mac
    .\venv\Scripts\activate      # on Windows
    ```

3. **Install dependencies:**
    ```bash
    python3 -m pip install -r requirements.txt
    ```

4. **Start the app:**
    ```bash
    python3 main.py
    ```

---

## 🖥️ How are keys saved?

Generated keys are encrypted and automatically saved in a secure folder in the user's home directory:
- **Linux/macOS:** `~/.mypgp_vault/`
- **Windows:** `C:\Users\YOURNAME\.mypgp_vault\`

No key is ever saved in plain text!

---

## ⚠️ Security
- Keys are always encrypted locally.
- NEVER send your private key over the Internet.
- If you lose your masterkey (created automatically the first time), you will not be able to recover your keys.

---

## 🤝 License

MIT. Use, share, improve!

---

## 🛠️ Credits

- [Sun Valley ttk Theme by rdbende](https://github.com/rdbende/Sun-Valley-ttk-theme)
- [pgpy](https://github.com/SecurityInnovation/PGPy)
- [cryptography](https://cryptography.io/en/latest/)
