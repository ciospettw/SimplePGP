import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from core.crypto import pgp_decrypt
from core.storage import load_keys_file
from gui.helpers import update_combobox, fill_widget

class DecryptPage(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.keys = load_keys_file()
        ttk.Label(self, text="Decrypt", font=("Arial", 13, "bold")).pack(anchor="nw", padx=15, pady=9)
        t = ttk.Frame(self)
        t.pack(fill="x", padx=20, pady=3)
        ttk.Label(t, text="Select private key:").grid(row=0, column=0, sticky="w")
        self.key_combo = ttk.Combobox(t, width=40, state="readonly")
        self.key_combo.grid(row=0, column=1)
        update_combobox(self.key_combo, self.keys)
        self.key_combo.bind("<<ComboboxSelected>>", self.fill_privkey)

        self.privkey = scrolledtext.ScrolledText(self, height=6)
        self.privkey.pack(fill="x", padx=15)
        ttk.Label(self, text="Passphrase (if present):").pack(anchor="nw", padx=15)
        self.passw = ttk.Entry(self, show="\u2022")
        self.passw.pack(fill="x", padx=20)
        ttk.Label(self, text="Encrypted message:").pack(anchor="nw", padx=15)
        self.message = scrolledtext.ScrolledText(self, height=6)
        self.message.pack(fill="x", padx=15)
        ttk.Button(self, text="Decrypt", command=self.do_decrypt).pack(padx=15,pady=9)
        ttk.Label(self, text="Decrypted text:").pack(anchor="nw", padx=15)
        self.output = scrolledtext.ScrolledText(self, height=5)
        self.output.pack(fill="x", padx=15)

    def reload_keys(self):
        self.keys = load_keys_file()
        update_combobox(self.key_combo, self.keys)

    def fill_privkey(self, event=None):
        idx = self.key_combo.current()
        if idx >= 0:
            fill_widget(self.privkey, self.keys[idx]["priv"])

    def do_decrypt(self):
        privkey_txt = self.privkey.get("1.0", "end")
        passw = self.passw.get().strip()
        enc_txt = self.message.get("1.0", "end")
        try:
            txt = pgp_decrypt(enc_txt, privkey_txt, passw)
            fill_widget(self.output, txt)
        except Exception as e:
            messagebox.showerror("Error", str(e))