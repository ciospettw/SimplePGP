from tkinter import ttk, scrolledtext, messagebox
from core.crypto import pgp_sign, pgp_verify
from core.storage import load_keys_file
from gui.helpers import update_combobox, fill_widget

class SignPage(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.keys = load_keys_file()
        frame1 = ttk.Labelframe(self, text="Sign")
        frame1.pack(fill="both", padx=14, pady=(10,6))
        ttk.Label(frame1, text="Select private key:").grid(row=0, column=0, sticky="w")
        self.cmb = ttk.Combobox(frame1, width=38, state="readonly")
        self.cmb.grid(row=0, column=1)
        update_combobox(self.cmb, self.keys)
        self.cmb.bind("<<ComboboxSelected>>", self.fill_privkey)
        self.privkey = scrolledtext.ScrolledText(frame1, height=4)
        self.privkey.grid(row=1, columnspan=2, pady=(2,3), sticky="ew")
        ttk.Label(frame1, text="Passphrase (if any):").grid(row=2,column=0,sticky="w")
        self.passw = ttk.Entry(frame1, show="\u2022")
        self.passw.grid(row=2, column=1,pady=2)
        ttk.Label(frame1, text="Message to sign:").grid(row=3,column=0,sticky="w")
        self.message = scrolledtext.ScrolledText(frame1, height=3)
        self.message.grid(row=3, column=1, pady=2)
        ttk.Button(frame1, text="Sign", command=self.do_sign).grid(row=4, column=0, columnspan=2, pady=8)
        ttk.Label(frame1, text="Digital signature:").grid(row=5,column=0,sticky="w")
        self.signature = scrolledtext.ScrolledText(frame1, height=4)
        self.signature.grid(row=5,column=1)

        frame2 = ttk.Labelframe(self, text="Verify a signature")
        frame2.pack(fill="both", padx=14, pady=12)
        ttk.Label(frame2, text="Select public key:").grid(row=0,column=0,sticky="w")
        self.cmb2 = ttk.Combobox(frame2, width=38, state="readonly")
        self.cmb2.grid(row=0, column=1)
        update_combobox(self.cmb2, self.keys)
        self.cmb2.bind("<<ComboboxSelected>>", self.fill_pubkey)
        self.pubkey = scrolledtext.ScrolledText(frame2, height=4)
        self.pubkey.grid(row=1, columnspan=2, pady=(2,3), sticky="ew")
        ttk.Label(frame2, text="Original message:").grid(row=2,column=0,sticky="w")
        self.ver_msg = scrolledtext.ScrolledText(frame2, height=3)
        self.ver_msg.grid(row=2, column=1, pady=2)
        ttk.Label(frame2, text="Digital signature:").grid(row=3,column=0,sticky="w")
        self.ver_signature = scrolledtext.ScrolledText(frame2, height=4)
        self.ver_signature.grid(row=3, column=1)
        ttk.Button(frame2, text="Verify signature", command=self.do_verify).grid(row=4, column=0, columnspan=2, pady=8)
        self.result_lbl = ttk.Label(frame2, text="", font=("Arial", 10, "bold"))
        self.result_lbl.grid(row=5, column=0, columnspan=2, pady=6)

    def fill_privkey(self, event=None):
        idx = self.cmb.current()
        if idx >= 0:
            fill_widget(self.privkey, self.keys[idx]["priv"])
    def fill_pubkey(self, event=None):
        idx = self.cmb2.current()
        if idx >= 0:
            fill_widget(self.pubkey, self.keys[idx]["pub"])
    def do_sign(self):
        privkey = self.privkey.get("1.0", "end")
        msg = self.message.get("1.0", "end")
        psw = self.passw.get().strip()
        try:
            sig = pgp_sign(msg, privkey, psw)
            fill_widget(self.signature, sig)
        except Exception as e:
            messagebox.showerror("Error", str(e))
    def do_verify(self):
        pubkey = self.pubkey.get("1.0", "end")
        msg = self.ver_msg.get("1.0", "end")
        sig = self.ver_signature.get("1.0", "end")
        try:
            ok = pgp_verify(msg, sig, pubkey)
            if ok:
                self.result_lbl.config(text="Signature valid", foreground='green')
                messagebox.showinfo("Verification Result", "Signature is VALID.")
            else:
                self.result_lbl.config(text="Signature NOT valid", foreground='red')
                messagebox.showwarning("Verification Result", "Signature is NOT valid.")
        except Exception as e:
            self.result_lbl.config(text="Error: %s" % e, foreground='red')
            messagebox.showerror("Verification Error", str(e))