import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import tkinter.simpledialog
from core.crypto import pgp_encrypt
from core.storage import load_keys_file
from gui.helpers import update_combobox, fill_widget

class EncryptPage(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.keys = load_keys_file()

        ttk.Label(self, text="Encrypt", font=("Arial", 13, "bold")).pack(anchor="nw", padx=15, pady=9)
        t = ttk.Frame(self)
        t.pack(fill="x", padx=20, pady=3)
        ttk.Label(t, text="Select public key:").grid(row=0, column=0, sticky="w")
        self.key_combo = ttk.Combobox(t, width=40, state="readonly")
        self.key_combo.grid(row=0, column=1)
        update_combobox(self.key_combo, self.keys)
        self.key_combo.bind("<<ComboboxSelected>>", self.fill_pubkey)
        self.pubkey = scrolledtext.ScrolledText(self, height=6)
        self.pubkey.pack(fill="x", padx=15)
        ttk.Label(self, text="Message:").pack(anchor="nw", padx=15)
        self.message = scrolledtext.ScrolledText(self, height=5)
        self.message.pack(fill="x", padx=15)

        self.sign_frame = ttk.Frame(self)
        self.sign_frame.pack(fill="x", padx=15, pady=(5, 0))
        self.want_sign = tk.BooleanVar()
        self.sign_cb = ttk.Checkbutton(self.sign_frame, text="Want to sign it too?", variable=self.want_sign, command=self.toggle_signing)
        self.sign_cb.grid(row=0, column=0, sticky="w")
        ttk.Label(self.sign_frame, text="Select private key:").grid(row=0, column=1, sticky="w", padx=(15,0))
        self.sign_key_combo = ttk.Combobox(self.sign_frame, width=35, state="readonly")
        self.sign_key_combo.grid(row=0, column=2, padx=(2,0))
        self.sign_key_combo.bind("<<ComboboxSelected>>", self.fill_privkey)
        ttk.Label(self.sign_frame, text="Passphrase (if any):").grid(row=0, column=3, sticky="w", padx=(15,0))
        self.sign_pass = ttk.Entry(self.sign_frame, show="\u2022", width=16)
        self.sign_pass.grid(row=0, column=4, padx=(2,0))
        self.add_priv_btn = ttk.Button(self.sign_frame, text="Add Private Key", command=self.add_private_key_dialog)
        self.add_priv_btn.grid(row=0, column=5, padx=(10,0))
        self.hide_signing_widgets()
        self.sign_cb.grid(row=0, column=0, sticky="w")
        self.key_combo.bind("<<ComboboxSelected>>", self.on_pubkey_selected)

        self.encrypt_btn = ttk.Button(self, text="Encrypt", command=self.do_encrypt)
        self.encrypt_btn.pack(padx=15, pady=9)
        self.signature_label = ttk.Label(self, text="Signature:")
        self.signature_output = scrolledtext.ScrolledText(self, height=6)
        self.signature_label.pack_forget()
        self.signature_output.pack_forget()
        ttk.Label(self, text="Encrypted:").pack(anchor="nw", padx=15)
        self.output = scrolledtext.ScrolledText(self, height=6)
        self.output.pack(fill="x", padx=15)
        self.update_sign_key_combo()
    def on_pubkey_selected(self, event=None):
        self.fill_pubkey()
        if self.want_sign.get():
            self.update_sign_key_combo()
            self.show_signing_widgets()
    def update_sign_key_combo(self):
        pub_idx = self.key_combo.current()
        recommended_idx = None
        recommended_key = None
        keys_with_priv = [k for k in self.keys if k.get('priv')]
        display_keys = []
        if pub_idx >= 0:
            selected_pub = self.keys[pub_idx].get('pub', '').strip()
            for i, k in enumerate(keys_with_priv):
                if k.get('pub', '').strip() == selected_pub and selected_pub:
                    recommended_idx = i
                    recommended_key = k
                    break
        if recommended_key:
            display_keys.append(recommended_key)
        for k in keys_with_priv:
            if k is not recommended_key:
                display_keys.append(k)
        display_names = []
        for i, k in enumerate(display_keys):
            name = k.get('name', 'Unnamed')
            if i == 0 and recommended_key:
                name += ' (recommended)'
            display_names.append(name)
        self.sign_key_combo['values'] = display_names
        if display_names:
            self.sign_key_combo.current(0)
        else:
            self.sign_key_combo.set('')

    def show_signing_widgets(self):
        for child in self.sign_frame.winfo_children():
            info = child.grid_info()
            if 'column' in info and info['column'] in (1,2,3,4):
                child.grid()
        pub_idx = self.key_combo.current()
        if pub_idx >= 0:
            pub_name = self.keys[pub_idx]['name']
            match_idx = next((i for i, k in enumerate(self.keys) if k['name'] == pub_name and 'priv' in k), None)
            if match_idx is not None:
                self.sign_key_combo.current(match_idx)
        if not hasattr(self, 'add_priv_btn'):
            self.add_priv_btn = ttk.Button(self.sign_frame, text="Add Private Key", command=self.add_private_key_dialog)
            self.add_priv_btn.grid(row=0, column=5, padx=(10,0))
        else:
            self.add_priv_btn.grid()

    def hide_signing_widgets(self):
        for child in self.sign_frame.winfo_children():
            info = child.grid_info()
            if 'column' in info and info['column'] in (1,2,3,4):
                child.grid_remove()
        if hasattr(self, 'add_priv_btn'):
            self.add_priv_btn.grid_remove()

    def toggle_signing(self):
        if self.want_sign.get():
            self.show_signing_widgets()
        else:
            self.hide_signing_widgets()

    def fill_privkey(self, event=None):
        idx = self.sign_key_combo.current()
        if idx is not None and idx >= 0:
            fill_widget(self.sign_pass, "")

    def reload_keys(self):
        self.keys = load_keys_file()
        update_combobox(self.key_combo, self.keys)
        self.update_sign_key_combo()

    def fill_pubkey(self, event=None):
        idx = self.key_combo.current()
        if idx >= 0:
            fill_widget(self.pubkey, self.keys[idx]["pub"])

    def do_encrypt(self):
        try:
            pubkey_txt = self.pubkey.get("1.0", "end")
            message = self.message.get("1.0", "end")
            if self.want_sign.get():
                idx = self.sign_key_combo.current()
                if idx is None or idx < 0 or not hasattr(self, 'display_sign_keys') or idx >= len(self.display_sign_keys):
                    messagebox.showerror(
                        "No Private Key Selected",
                        "You have checked 'Want to sign it too?' but have not selected a private key.\n\nPlease add or select a private key to sign the message."
                    )
                    return
                privkey_obj = self.display_sign_keys[idx]
                privkey_txt = privkey_obj["priv"]
                passphrase = privkey_obj.get("passphrase", "")
                if privkey_obj.get("protected", False) and not passphrase:
                    messagebox.showerror(
                        "Passphrase Required",
                        f"The selected private key ('{privkey_obj.get('name','') or 'Manual'}') is protected by a passphrase, but you have not provided one.\n\nPlease edit the key in 'Add Private Key' and enter the correct passphrase."
                    )
                    return
                from core.crypto import pgp_sign
                signature = pgp_sign(message, privkey_txt, passphrase)
                signed_message = signature + "\n" + message
                code = pgp_encrypt(signed_message, pubkey_txt)
                fill_widget(self.output, code)
                self.signature_label.pack(anchor="nw", padx=15)
                self.signature_output.pack(fill="x", padx=15)
                fill_widget(self.signature_output, signature)
            else:
                code = pgp_encrypt(message, pubkey_txt)
                fill_widget(self.output, code)
                self.signature_label.pack_forget()
                self.signature_output.pack_forget()
                fill_widget(self.signature_output, "")
        except Exception as e:
            import traceback
            traceback.print_exc()
            messagebox.showerror("Error", f"Encrypt failed: {e}")

    def add_private_key_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Add Private Key")
        dialog.geometry("420x320")
        dialog.transient(self)
        dialog.grab_set()

        tk.Label(dialog, text="Select a saved private key:").pack(anchor="w", padx=15, pady=(12,2))
        pub_idx = self.key_combo.current()
        recommended_idx = None
        keys_for_dropdown = []
        if pub_idx >= 0:
            pub_name = self.keys[pub_idx]['name']
            for i, k in enumerate(self.keys):
                if k['name'] == pub_name and k.get('priv'):
                    recommended_idx = i
                    break
        added = set()
        dropdown_items = []
        if recommended_idx is not None:
            dropdown_items.append(f"{self.keys[recommended_idx]['name']} (Recommended)")
            keys_for_dropdown.append(self.keys[recommended_idx])
            added.add(recommended_idx)
        for i, k in enumerate(self.keys):
            if i not in added and k.get('priv'):
                dropdown_items.append(k['name'])
                keys_for_dropdown.append(k)
        privkey_var = tk.StringVar()
        privkey_combo = ttk.Combobox(dialog, textvariable=privkey_var, values=dropdown_items, state="readonly", width=35)
        privkey_combo.pack(fill="x", padx=15, pady=(0,8))
        if dropdown_items:
            privkey_combo.current(0)

        tk.Label(dialog, text="Or paste your PRIVATE key:").pack(anchor="w", padx=15, pady=(8,2))
        key_text = tk.Text(dialog, height=6)
        key_text.pack(fill="both", padx=15, pady=(0,8), expand=True)


        tk.Label(dialog, text="Passphrase (if any):").pack(anchor="w", padx=15, pady=(8,2))

        passphrase_row = ttk.Frame(dialog)
        passphrase_row.pack(fill="x", padx=15, pady=(0,4))
        pass_entry = ttk.Entry(passphrase_row, show="\u2022", width=30)
        pass_entry.pack(side="left", fill="x", expand=True)
        check_btn = ttk.Button(passphrase_row, text="Check Passphrase")
        check_btn.pack(side="left", padx=(8,0))
        pass_status = tk.Label(dialog, text="", fg="red", font=("Arial", 9))
        pass_status.pack(anchor="w", padx=15, pady=(0,4))

        def check_passphrase():
            priv = None
            priv_name = None
            # Use selected key or manual
            sel_idx = privkey_combo.current()
            if sel_idx >= 0 and sel_idx < len(keys_for_dropdown):
                priv = keys_for_dropdown[sel_idx].get('priv', '').strip()
                priv_name = keys_for_dropdown[sel_idx].get('name', 'Manual')
            manual_priv = key_text.get("1.0", "end").strip()
            if manual_priv:
                priv = manual_priv
                priv_name = 'Manual'
            passphrase = pass_entry.get().strip()
            if not priv:
                pass_status.config(text="Paste or select a private key first.", fg="red")
                return
            # Try unlocking with pgpy
            try:
                import pgpy
                key, _ = pgpy.PGPKey.from_blob(priv)
                if key.is_protected:
                    with key.unlock(passphrase):
                        if key.is_unlocked:
                            pass_status.config(text="Passphrase OK!", fg="green")
                            # Save passphrase immediately to self.keys for this key
                            # Remove any previous 'Manual' keys to avoid duplicates
                            self.keys = [k for k in self.keys if not (k.get('name') == priv_name and k.get('priv') == priv)]
                            self.keys.append({"name": priv_name, "priv": priv, "pub": "", "protected": True, "date": priv_name, "passphrase": passphrase or ""})
                            self.update_sign_key_combo()
                        else:
                            pass_status.config(text="Incorrect passphrase.", fg="red")
                else:
                    pass_status.config(text="Key is not protected.", fg="gray")
            except Exception as e:
                pass_status.config(text=f"Error: {e}", fg="red")
        check_btn.config(command=check_passphrase)

        def do_add():
            priv = None
            priv_name = None
            # If a dropdown selection is made and not empty, use that key
            sel_idx = privkey_combo.current()
            if sel_idx >= 0 and sel_idx < len(keys_for_dropdown):
                priv = keys_for_dropdown[sel_idx].get('priv', '').strip()
                priv_name = keys_for_dropdown[sel_idx].get('name', 'Manual')
            # If manual entry is provided, use that instead
            manual_priv = key_text.get("1.0", "end").strip()
            if manual_priv:
                priv = manual_priv
                priv_name = 'Manual'
            if not priv:
                messagebox.showerror("Error", "Private key cannot be empty.")
                return
            passphrase = pass_entry.get().strip()
            # Check passphrase validity before saving
            try:
                import pgpy
                key, _ = pgpy.PGPKey.from_blob(priv)
                if key.is_protected:
                    with key.unlock(passphrase):
                        if not key.is_unlocked:
                            messagebox.showerror("Error", "Incorrect passphrase for this private key.")
                            return
                # If not protected, or unlocked, save
                # Remove any previous 'Manual' keys to avoid duplicates
                self.keys = [k for k in self.keys if not (k.get('name') == priv_name and k.get('priv') == priv)]
                self.keys.append({"name": priv_name, "priv": priv, "pub": "", "protected": key.is_protected, "date": priv_name, "passphrase": passphrase or ""})
                self.update_sign_key_combo()
                dialog.destroy()
                # Show confirmation label beside the Add Private Key button
                self.show_signing_confirmation(priv_name)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add key: {e}")

        # Place the confirm/add button at the bottom of the dialog
        btn_row = ttk.Frame(dialog)
        btn_row.pack(fill="x", padx=15, pady=(0,8))
        ttk.Button(btn_row, text="Confirm", command=do_add, width=12).pack(side="right")

    def show_signing_confirmation(self, priv_name):
        # Remove previous confirmation if exists
        if hasattr(self, '_signing_confirm_label') and self._signing_confirm_label:
            self._signing_confirm_label.destroy()
        msg = f"Using Private key ({priv_name})"
        self._signing_confirm_label = tk.Label(self.sign_frame, text=msg, fg="green", font=("Arial", 9, "bold"))
        self._signing_confirm_label.grid(row=0, column=6, padx=(10,0), sticky="w")
