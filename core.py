import base64
import os
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

PBKDF2_ITERATIONS = 390_000
SALT_LEN = 16


_dirty = False

def set_dirty(value: bool):
    global _dirty
    _dirty = value

def is_dirty() -> bool:
    return _dirty

# --- CRYPTO CORE ---

def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

def encrypt_text(data: str, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(data.encode("utf-8"))
    return salt + encrypted

def decrypt_text(data: bytes, password: str) -> str:
    salt = data[:SALT_LEN]
    encrypted = data[SALT_LEN:]
    key = derive_key(password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted).decode("utf-8")

# --- UI HELPERS ---

def ask_password(parent, title, prompt):
    pwd = simpledialog.askstring(title, prompt, show="*", parent=parent)
    return pwd if pwd else None

def show_about(parent):
    messagebox.showinfo("About", "NotepadSecure\n\nContact: bnu.dorian@gmail.com", parent=parent)

# --- FILE ACTIONS ---

def open_file(parent, edit_zone):
    path = filedialog.askopenfilename()
    if not path:
        return
    with open(path, "rb") as f:
        raw = f.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("cp1252", errors="replace")
    edit_zone.delete(1.0, tk.END)
    edit_zone.insert(tk.END, text)
    set_dirty(False)

def save_file(parent, edit_zone):
    path = filedialog.asksaveasfilename(
        parent=parent,
        defaultextension=".txt",
        filetypes=[("Fichier texte", "*.txt"), ("Tous les fichiers", "*.*")]
    )
    if not path:
        return

    with open(path, "w", encoding="utf-8") as f:
        f.write(edit_zone.get(1.0, tk.END))

    set_dirty(False)

def encrypt_and_save_file(parent, edit_zone):
    password = ask_password(parent, "Cryptage", "Mot de passe pour chiffrer :")
    if not password:
        return

    path = filedialog.asksaveasfilename(
        parent=parent,
        defaultextension=".enc",
        filetypes=[("Fichier chiffré", "*.enc"), ("Tous les fichiers", "*.*")]
    )
    if not path:
        return

    if os.path.exists(path):
        if not messagebox.askyesno("Attention",
                                   "Le fichier existe déjà.\nVoulez-vous l’écraser ?",
                                   parent=parent):
            return

    data = edit_zone.get(1.0, tk.END)
    encrypted = encrypt_text(data, password)

    with open(path, "wb") as f:
        f.write(encrypted)

    set_dirty(False)

def open_encrypted_file(parent, edit_zone):
    path = filedialog.askopenfilename(
        parent=parent,
        defaultextension=".enc",
        filetypes=[("Fichier chiffré", "*.enc"), ("Tous les fichiers", "*.*")]
    )
    if not path:
        return

    password = ask_password(parent, "Cryptage", "Mot de passe pour déchiffrer :")
    if not password:
        return

    try:
        with open(path, "rb") as f:
            raw = f.read()
        decrypted = decrypt_text(raw, password)
        edit_zone.delete(1.0, tk.END)
        edit_zone.insert(tk.END, decrypted)
        set_dirty(False)
    except InvalidToken:
        messagebox.showerror("Erreur", "Mot de passe incorrect (ou fichier corrompu).", parent=parent)



def confirm_discard_or_save(parent, edit_zone, save_callback) -> bool:
    """
    Returns True if the caller can continue (discard changes or saved),
    Returns False if the user cancelled the action.
    """
    if not is_dirty():
        return True

    choice = messagebox.askyesnocancel(
        "Unsaved changes",
        "You have unsaved changes.\nDo you want to save before continuing?",
        parent=parent
    )

    if choice is None:  # Cancel
        return False

    if choice is True:  # Yes => Save
        save_callback(parent, edit_zone)
        # If user cancelled the save dialog, we consider it "not saved" => don't continue
        return not is_dirty()

    return True

def mark_dirty():
    set_dirty(True)
