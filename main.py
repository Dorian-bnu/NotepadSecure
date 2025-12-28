import base64
import sys, os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox


def resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.abspath("."))
    return os.path.join(base_path, relative_path)


def show_about():
    messagebox.showinfo(
        "About",
        "NotepadSecure\n\nContact: bnu.dorian@gmail.com",
        parent=window
    )

#key and pwd generation
def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

#Encryp/decrypt text 
def encrypt_text(data: str, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(data.encode())
    return salt + encrypted

def decrypt_text(data: bytes, password: str) -> str:
    salt = data[:16]
    encrypted = data[16:]
    key = derive_key(password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted).decode()

def ask_password(title: str, prompt: str) -> str | None:
    pwd = simpledialog.askstring(title, prompt, show="*", parent=window)
    return pwd if pwd else None

#Open file(not encrypt)
def open_file():
    path = filedialog.askopenfilename(
        defaultextension=".txt",
        filetypes=[("Fichier texte", "*.txt"), ("Tous les fichiers", "*.*")]
    )
    if not path:
        return

    try:
        with open(path, "rb") as f:
            raw = f.read()

        # 1) Try UTF-8
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            # 2) Fallback Windows 
            text = raw.decode("cp1252", errors="replace")

        edit_zone.delete(1.0, tk.END)
        edit_zone.insert(tk.END, text)

    except OSError as e:
        messagebox.showerror("Erreur", f"Impossible d'ouvrir :\n{e}", parent=window)


#Save file (not encrypt)
def save_file():
    path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Fichier texte", "*.txt"), ("Tous les fichiers", "*.*")]
    )
    if not path:
        return

    try:
        text = edit_zone.get(1.0, tk.END)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    except OSError as e:
        messagebox.showerror("Erreur", f"Impossible d'enregistrer :\n{e}", parent=window)



# --- CRYPTO ---

def encrypt_and_save_file():
    password = ask_password("Cryptage", "Mot de passe pour chiffrer :")
    if not password:
        return

    path = filedialog.asksaveasfilename(
        defaultextension=".enc",
        filetypes=[("Fichier chiffré", "*.enc"), ("Tous les fichiers", "*.*")]
    )
    if not path:
        return

    if os.path.exists(path):
        if not messagebox.askyesno("Attention",
                                   "Le fichier existe déjà.\nVoulez-vous l’écraser ?",
                                   parent=window):
            return

    data = edit_zone.get(1.0, tk.END)
    encrypted = encrypt_text(data, password)

    try:
        with open(path, "wb") as f:
            f.write(encrypted)
        messagebox.showinfo("Cryptage", "Fichier chiffré enregistré.", parent=window)
    except OSError as e:
        messagebox.showerror("Erreur", f"Impossible d'enregistrer :\n{e}", parent=window)


def open_encrypted_file():
    path = filedialog.askopenfilename(
        defaultextension=".enc",
        filetypes=[("Fichier chiffré", "*.enc"), ("Tous les fichiers", "*.*")]
    )
    if not path:
        return

    password = ask_password("Cryptage", "Mot de passe pour déchiffrer :")
    if not password:
        return

    try:
        with open(path, "rb") as f:
            raw = f.read()
        decrypted = decrypt_text(raw, password)
        edit_zone.delete(1.0, tk.END)
        edit_zone.insert(tk.END, decrypted)
        messagebox.showinfo("Cryptage", "Fichier déchiffré et chargé.")
    except InvalidToken:
        messagebox.showerror("Erreur", "Mot de passe incorrect (ou fichier corrompu).")
    except OSError as e:
        messagebox.showerror("Erreur", f"Impossible d'ouvrir :\n{e}")


#Window
window = tk.Tk()
window.title("NotepadSecure") 
window.iconbitmap(resource_path("favicon.ico"))

# text edit zone + scrollbar
text_frame = tk.Frame(window)
text_frame.pack(expand=True, fill="both")

scrollbar_y = tk.Scrollbar(text_frame)
scrollbar_y.pack(side="right", fill="y")

edit_zone = tk.Text(text_frame, yscrollcommand=scrollbar_y.set)
edit_zone.pack(side="left", expand=True, fill="both")

scrollbar_y.config(command=edit_zone.yview)


# Menu 
menu_bar = tk.Menu(window)
window.config(menu=menu_bar)
menu_file = tk.Menu(menu_bar)
menu_crypto = tk.Menu(menu_bar)
menu_bar.add_cascade(label="Fichier", menu=menu_file) 
menu_bar.add_cascade(label="Cryptage", menu=menu_crypto) 

#Menu File option
menu_file.add_command(label="Ouvrir", command=open_file)
menu_file.add_command(label="Enregistrer", command=save_file)
menu_file.add_separator()
menu_file.add_command(label="Quitter", command=window.quit)

#Crypto Menu option
menu_crypto.add_command(label="Crypter et enregistrer (.enc)", command=encrypt_and_save_file)
menu_crypto.add_command(label="Décrypter un fichier (.enc)", command=open_encrypted_file)

# About menu 
menu_about = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="About", menu=menu_about)
menu_about.add_command(label="Contact", command=show_about)

window.mainloop()




