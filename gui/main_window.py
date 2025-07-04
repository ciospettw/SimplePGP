import tkinter as tk
from tkinter import ttk, messagebox
import os
from core.storage import load_keys_file, save_keys_file, save_lock_code, load_lock_code, clear_lock_code, generate_bip39_phrase
from theming.theme import set_theme
from gui.page_keys import KeysPage
from gui.page_encrypt import EncryptPage
from gui.page_decrypt import DecryptPage
from gui.page_sign import SignPage

def run_app():
    root = tk.Tk()
    root.title("SimplePGP Client")
    root.geometry("950x700")
    icon_path = os.path.join(os.path.dirname(__file__), 'favicon.ico')
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
        
        try:
            import sys
            if sys.platform == 'win32':
                import ctypes
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(u"mypgp.simplepgp")
                hwnd = ctypes.windll.user32.GetForegroundWindow()
                
                ctypes.windll.user32.SendMessageW(hwnd, 0x80, 0, icon_path)
        except Exception as e:
            print(f"[INFO] Could not set taskbar icon: {e}")
    else:
        print("WARNING: favicon.ico not found in the main_window.py directory!")

    set_theme(root, "dark")

    tabs = ttk.Notebook(root)
    tabs.pack(fill="both", expand=True)

    encrypt_page = EncryptPage(tabs)
    decrypt_page = DecryptPage(tabs)
    keys_page = KeysPage(tabs, encrypt_page=encrypt_page, decrypt_page=decrypt_page)
    sign_page = SignPage(tabs)

    tabs.add(keys_page, text="My Keys")
    tabs.add(encrypt_page, text="Encrypt")
    tabs.add(decrypt_page, text="Decrypt")
    tabs.add(sign_page, text="Sign / Verify")

    lock_data = load_lock_code()
    if lock_data:
        def show_unlock_dialog():
            unlock_win = tk.Toplevel(root)
            unlock_win.title("Unlock App")
            unlock_win.geometry("340x180")
            unlock_win.transient(root)
            unlock_win.grab_set()
            tk.Label(unlock_win, text="Enter lock code or recovery phrase to unlock:").pack(pady=(16,4))
            code_entry = tk.Entry(unlock_win, show="\u2022", width=24)
            code_entry.pack(pady=2)
            phrase_entry = tk.Entry(unlock_win, width=40)
            phrase_entry.pack(pady=2)
            phrase_entry.insert(0, "Enter recovery phrase (if needed)")
            def try_unlock():
                code = code_entry.get()
                phrase = phrase_entry.get()
                if code == lock_data['lock_code'] or phrase == lock_data['recovery_phrase']:
                    unlock_win.destroy()
                else:
                    messagebox.showerror("Error", "Incorrect code or phrase.")
            tk.Button(unlock_win, text="Unlock", command=try_unlock).pack(pady=16)
            unlock_win.protocol("WM_DELETE_WINDOW", root.destroy)
        show_unlock_dialog()


    options_frame = ttk.Frame(tabs)
    tabs.add(options_frame, text="Options")

    def show_options_menu():
        for widget in options_frame.winfo_children():
            widget.destroy()
        ttk.Button(options_frame, text="Set Lock Code", command=set_lock_code).pack(pady=8)
        ttk.Button(options_frame, text="Unlock App", command=unlock_app).pack(pady=8)
        ttk.Button(options_frame, text="Clear Lock", command=clear_lock).pack(pady=8)

    def set_lock_code():
        for widget in options_frame.winfo_children():
            widget.destroy()
        tk.Label(options_frame, text="Set Lock Code", font=("Arial", 13, "bold")).pack(pady=(12,2))
        code_entry = tk.Entry(options_frame, show="\u2022", width=24)
        code_entry.pack(pady=2)
        phrase = generate_bip39_phrase()
        tk.Label(options_frame, text="Your recovery phrase (write it down and keep it safe):").pack(pady=(12,2))
        phrase_box = tk.Text(options_frame, height=2, width=40)
        phrase_box.pack(pady=2)
        phrase_box.insert("1.0", phrase)
        phrase_box.config(state="disabled")
        def save_code():
            code = code_entry.get()
            if len(code) < 4:
                messagebox.showerror("Error", "Lock code must be at least 4 characters.")
                return
            save_lock_code(code, phrase)
            messagebox.showinfo("Success", "Lock code set and encrypted. Recovery phrase shown above.")
            show_options_menu()
        tk.Button(options_frame, text="Save Lock Code", command=save_code).pack(pady=16)
        ttk.Button(options_frame, text="← Back", command=show_options_menu).pack(pady=8)

    def unlock_app():
        for widget in options_frame.winfo_children():
            widget.destroy()
        lock_data = load_lock_code()
        if not lock_data:
            tk.Label(options_frame, text="No lock code is set.").pack(pady=12)
            ttk.Button(options_frame, text="← Back", command=show_options_menu).pack(pady=8)
            return
        tk.Label(options_frame, text="Unlock App", font=("Arial", 13, "bold")).pack(pady=(12,2))
        code_entry = tk.Entry(options_frame, show="\u2022", width=24)
        code_entry.pack(pady=2)
        phrase_entry = tk.Entry(options_frame, width=40)
        phrase_entry.pack(pady=2)
        phrase_entry.insert(0, "Enter recovery phrase (if needed)")
        def try_unlock():
            code = code_entry.get()
            phrase = phrase_entry.get()
            if code == lock_data['lock_code'] or phrase == lock_data['recovery_phrase']:
                messagebox.showinfo("Unlocked", "App unlocked!")
                show_options_menu()
            else:
                messagebox.showerror("Error", "Incorrect code or phrase.")
        tk.Button(options_frame, text="Unlock", command=try_unlock).pack(pady=16)
        ttk.Button(options_frame, text="← Back", command=show_options_menu).pack(pady=8)

    def clear_lock():
        clear_lock_code()
        messagebox.showinfo("Lock Cleared", "Lock code and recovery phrase removed.")
        show_options_menu()

    show_options_menu()

    root.mainloop()