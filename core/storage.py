import os
import json
import base64
import uuid
import pathlib
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


APP_FOLDER = os.path.join(pathlib.Path.home(), ".mypgp_vault")
KEYS_FILE = os.path.join(APP_FOLDER, "keys.dat")
MASTERKEY_FILE = os.path.join(APP_FOLDER, ".masterkey")
LOCK_FILE = os.path.join(APP_FOLDER, "lock.dat")
def save_lock_code(lock_code, recovery_phrase):
    ensure_appfolder()
    mk = load_masterkey()
    akey = derive_aes_key(mk)
    data = json.dumps({"lock_code": lock_code, "recovery_phrase": recovery_phrase}).encode()
    enc = aes_encrypt(akey, data)
    with open(LOCK_FILE, "wb") as f:
        f.write(enc)

def load_lock_code():
    if not os.path.exists(LOCK_FILE):
        return None
    mk = load_masterkey()
    akey = derive_aes_key(mk)
    try:
        with open(LOCK_FILE, "rb") as f:
            cdata = f.read()
        data = aes_decrypt(akey, cdata)
        return json.loads(data.decode())
    except Exception:
        return None

def clear_lock_code():
    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)

def ensure_appfolder():
    if not os.path.exists(APP_FOLDER):
        os.makedirs(APP_FOLDER, exist_ok=True)

def generate_masterkey():
    uniq = uuid.getnode().to_bytes(6,'big')
    try:
        hostname = os.uname().nodename.encode()
    except Exception:
        hostname = os.getenv('COMPUTERNAME', 'UNKNOWN').encode()
    secret = os.urandom(32) + uniq + hostname
    masterkey = base64.urlsafe_b64encode(secret)
    with open(MASTERKEY_FILE, "wb") as f:
        f.write(masterkey)
    return masterkey

def load_masterkey():
    try:
        with open(MASTERKEY_FILE,"rb") as f:
            return f.read()
    except Exception:
        return generate_masterkey()

def derive_aes_key(masterkey):
    salt = b"mypgp_salt_v1"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000
    )
    return kdf.derive(masterkey)

def aes_encrypt(key, data: bytes):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return base64.b64encode(nonce + ct)

def aes_decrypt(key, ctenc: bytes):
    blob = base64.b64decode(ctenc)
    nonce, ct = blob[:12], blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def save_keys_file(keys):
    ensure_appfolder()
    mk = load_masterkey()
    akey = derive_aes_key(mk)
    data = json.dumps(keys, indent=1).encode()
    enc = aes_encrypt(akey, data)
    with open(KEYS_FILE, "wb") as f:
        f.write(enc)

def load_keys_file():
    if not os.path.exists(KEYS_FILE):
        return []
    mk = load_masterkey()
    akey = derive_aes_key(mk)
    try:
        with open(KEYS_FILE, "rb") as f:
            cdata = f.read()
        data = aes_decrypt(akey, cdata)
        return json.loads(data.decode())
    except Exception:
        return []

def generate_bip39_phrase(num_words=12):
    wordlist_path = os.path.join(os.path.dirname(__file__), "bip39_wordlist.txt")
    with open(wordlist_path, "r", encoding="utf-8") as f:
        words = [w.strip() for w in f.readlines() if w.strip()]
    return " ".join(random.choice(words) for _ in range(num_words))