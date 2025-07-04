import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from core.crypto import generate_keypair
from core.storage import load_keys_file, save_keys_file
from gui.helpers import fill_widget

class KeysPage(ttk.Frame):
    def __init__(self, master, encrypt_page=None, decrypt_page=None):
        super().__init__(master)
        self.keys = load_keys_file()
        self.encrypt_page = encrypt_page
        self.decrypt_page = decrypt_page

        title = ttk.Label(self, text="Manage PGP Keys", font=("Arial", 13, "bold"))
        title.pack(anchor="w", padx=15, pady=9)

        box = ttk.Frame(self)
        box.pack(fill="x", padx=25, pady=8)
        ttk.Label(box, text="Key name:").grid(row=0, column=0, sticky="w")
        self.name_entry = ttk.Entry(box, width=20)
        self.name_entry.grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Label(box, text="Passphrase (optional):").grid(row=1, column=0, sticky="w")
        self.pass_entry = ttk.Entry(box, show="\u2022", width=20)
        self.pass_entry.grid(row=1, column=1, padx=5, sticky="ew")
        ttk.Button(box, text="Create key", command=self.add_key).grid(row=0, column=2, rowspan=2, padx=10)
        ttk.Button(box, text="Import key", command=self.import_key_dialog).grid(row=0, column=3, rowspan=2, padx=10)

        self.frame_keys = ttk.LabelFrame(self, text="Saved keys")
        self.frame_keys.pack(fill="both", expand=True, padx=15, pady=(10,8))
        self.list = tk.Listbox(self.frame_keys)
        self.list.pack(side="left", fill="y", expand=True, padx=(0, 5))
        self.details = scrolledtext.ScrolledText(self.frame_keys, height=12)
        self.details.pack(side="left", fill="both", expand=True)
        self.details.config(state="disabled")
        self.list.bind("<<ListboxSelect>>", self.show_key)
        self.list.bind("<Button-3>", self.show_list_context_menu)
        self.details.bind("<Button-3>", self.show_details_context_menu)

        self.reload()
    
    def import_key_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Import Key")
        dialog.geometry("480x420")
        dialog.transient(self)
        dialog.grab_set()

        ttk.Label(dialog, text="Key name (optional):").pack(anchor="w", padx=15, pady=(12,2))
        name_entry = ttk.Entry(dialog, width=30)
        name_entry.pack(fill="x", padx=15)

        ttk.Label(dialog, text="Paste your PUBLIC key (optional):").pack(anchor="w", padx=15, pady=(10,2))
        pub_text = tk.Text(dialog, height=5)
        pub_text.pack(fill="both", padx=15, pady=(0,8), expand=False)

        ttk.Label(dialog, text="Paste your PRIVATE key (optional):").pack(anchor="w", padx=15, pady=(10,2))
        priv_text = tk.Text(dialog, height=5)
        priv_text.pack(fill="both", padx=15, pady=(0,8), expand=False)

        protected_var = tk.BooleanVar()
        def toggle_pass():
            if protected_var.get():
                pass_entry.pack(fill="x", padx=15, pady=(0,8))
            else:
                pass_entry.pack_forget()

        prot_cb = ttk.Checkbutton(dialog, text="Key is protected by a passphrase", variable=protected_var, command=toggle_pass)
        prot_cb.pack(anchor="w", padx=15, pady=(0,2))
        pass_entry = ttk.Entry(dialog, show="\u2022", width=30)

        def do_import():
            name = name_entry.get().strip() or "Imported"
            pub = pub_text.get("1.0", "end").strip()
            priv = priv_text.get("1.0", "end").strip()
            passphrase = pass_entry.get().strip() if protected_var.get() else ""
            if not pub and not priv:
                messagebox.showerror("Error", "You must provide at least a public or a private key.", parent=dialog)
                return
            protected = False
            try:
                if priv:
                    if not (priv.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----") and priv.endswith("-----END PGP PRIVATE KEY BLOCK-----")):
                        messagebox.showerror("Error", "The private key must start with '-----BEGIN PGP PRIVATE KEY BLOCK-----' and end with '-----END PGP PRIVATE KEY BLOCK-----'.", parent=dialog)
                        return
                    from core.crypto import pgpy
                    key, _ = pgpy.PGPKey.from_blob(priv)
                    if not pub:
                        pub = str(key.pubkey)
                    protected = key.is_protected or bool(passphrase)
                if pub:
                    if not (pub.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----") and pub.endswith("-----END PGP PUBLIC KEY BLOCK-----")):
                        messagebox.showerror("Error", "The public key must start with '-----BEGIN PGP PUBLIC KEY BLOCK-----' and end with '-----END PGP PUBLIC KEY BLOCK-----'.", parent=dialog)
                        return
                import datetime
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                keydata = {"name": name, "priv": priv, "pub": pub, "protected": protected, "date": now}
                if protected:
                    keydata["passphrase"] = passphrase
                self.keys.append(keydata)
                save_keys_file(self.keys)
                messagebox.showinfo("Key imported", f"Key '{name}' imported and saved!", parent=dialog)
                dialog.destroy()
                self.reload()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import key: {e}", parent=dialog)

        btns = ttk.Frame(dialog)
        btns.pack(fill="x", padx=15, pady=(0,10))
        ttk.Button(btns, text="Import", command=do_import).pack(side="right")
        ttk.Button(btns, text="Cancel", command=dialog.destroy).pack(side="right", padx=(0,8))

    def add_key(self):
        name = self.name_entry.get().strip()
        passw = self.pass_entry.get().strip()
        if not name:
            return
        dialog = tk.Toplevel(self)
        dialog.title("Key Options")
        dialog.geometry("340x260")
        dialog.transient(self)
        dialog.grab_set()

        ttk.Label(dialog, text="Key length:").pack(anchor="w", padx=15, pady=(14,2))
        keylen_var = tk.StringVar(value="2048")
        keylen_box = ttk.Combobox(dialog, textvariable=keylen_var, values=["2048", "3072", "4096"], state="readonly", width=10)
        keylen_box.pack(fill="x", padx=15)
        keylen_box.current(0)

        ttk.Label(dialog, text="Comment (optional):").pack(anchor="w", padx=15, pady=(10,2))
        comment_entry = ttk.Entry(dialog, width=30)
        comment_entry.pack(fill="x", padx=15)

        include_info_var = tk.BooleanVar(value=True)
        info_cb = ttk.Checkbutton(dialog, text="Include SimplePGP's infos.", variable=include_info_var)
        info_cb.pack(anchor="w", padx=15, pady=(10,2))

        def do_create():
            keylen = keylen_var.get()
            comment = comment_entry.get().strip()
            include_info = include_info_var.get()
            dialog.destroy()
            keydata = generate_keypair(name, passw, keylen, comment, include_info)
            self.keys.append(keydata)
            save_keys_file(self.keys)
            messagebox.showinfo("Key created", f"Key '{name}' created and saved!")
            self.name_entry.delete(0, 'end')
            self.pass_entry.delete(0, 'end')
            self.reload()

        btns = ttk.Frame(dialog)
        btns.pack(fill="x", padx=15, pady=(18,8))
        ttk.Button(btns, text="Create", command=do_create, width=10).pack(side="right")
        ttk.Button(btns, text="Cancel", command=dialog.destroy, width=10).pack(side="right", padx=(0,8))

    def show_key(self, event=None):
        sel = self.list.curselection()
        if sel:
            idx = sel[0]
            k = self.keys[idx]
            info = (
                f"Name: {k['name']}\nDate: {k['date']}\n"
                f"{'Protected by passphrase' if k['protected'] else 'No passphrase'}\n"
                f"\n--- PUBLIC KEY ---\n{k['pub']}\n\n--- PRIVATE KEY ---\n{k['priv']}"
            )
            self.details.config(state="normal")
            self.details.delete("1.0", "end")
            self.details.insert("1.0", info)
            self.details.config(state="disabled")
    
    def reload(self):
        self.keys = load_keys_file()
        self.list.delete(0, "end")
        if self.keys:
            for k in self.keys:
                self.list.insert("end", f"{k['name']} ({k['date']})")
            self.details.config(state="normal")
            self.details.delete("1.0", "end")
            self.details.config(state="disabled")
        else:
            self.details.config(state="normal")
            self.details.delete("1.0", "end")
            self.details.insert("1.0", "No keys saved yet.")
            self.details.config(state="disabled")
        if self.encrypt_page:
            self.encrypt_page.reload_keys()
        if self.decrypt_page:
            self.decrypt_page.reload_keys()

    def show_list_context_menu(self, event):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Delete key", command=lambda: self.delete_selected_key())
        menu.tk_popup(event.x_root, event.y_root)

    def delete_selected_key(self):
        sel = self.list.curselection()
        if not sel:
            return
        idx = sel[0]
        key = self.keys[idx]
        if messagebox.askyesno("Delete key", f"Are you sure you want to delete the key '{key['name']}'?"):
            del self.keys[idx]
            save_keys_file(self.keys)
            self.reload()

    def show_details_context_menu(self, event):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Copy", command=lambda: self.copy_details())
        menu.tk_popup(event.x_root, event.y_root)

    def copy_details(self):
        try:
            text = self.details.get("sel.first", "sel.last")
        except tk.TclError:
            text = self.details.get("1.0", "end").strip()
        self.clipboard_clear()
        self.clipboard_append(text)