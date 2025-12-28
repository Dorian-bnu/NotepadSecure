import tkinter as tk
import sys, os
import core

def resource_path(relative_path):
    base_path = getattr(sys, "_MEIPASS", os.path.abspath("."))
    return os.path.join(base_path, relative_path)


# ----- Main window -----

window = tk.Tk()
window.title("NotepadSecure")
window.iconbitmap(resource_path("favicon.ico"))



# ----- Text area with vertical scrollbar -----

text_frame = tk.Frame(window)
text_frame.pack(expand=True, fill="both")

scrollbar = tk.Scrollbar(text_frame)
scrollbar.pack(side="right", fill="y")

edit_zone = tk.Text(text_frame, yscrollcommand=scrollbar.set)
edit_zone.pack(side="left", expand=True, fill="both")
scrollbar.config(command=edit_zone.yview)

def on_modified(event=None):
    # Tk sets a modified flag on the widget; we reset it after reading
    if edit_zone.edit_modified():
        core.mark_dirty()
        edit_zone.edit_modified(False)

edit_zone.bind("<<Modified>>", on_modified)
edit_zone.edit_modified(False)

# ----- Menu bar -----

menu_bar = tk.Menu(window)
window.config(menu=menu_bar)

menu_file = tk.Menu(menu_bar, tearoff=0)
menu_crypto = tk.Menu(menu_bar, tearoff=0)
menu_about = tk.Menu(menu_bar, tearoff=0)

menu_bar.add_cascade(label="Fichier", menu=menu_file)
menu_bar.add_cascade(label="Cryptage", menu=menu_crypto)
menu_bar.add_cascade(label="About", menu=menu_about)


# ----- File menu -----

menu_file.add_command(
    label="Ouvrir",
    command=lambda: (
        core.confirm_discard_or_save(window, edit_zone, core.save_file)
        and core.open_file(window, edit_zone)
    )
)
menu_file.add_command(label="Enregistrer", command=lambda: core.save_file(window, edit_zone))
menu_file.add_separator()
menu_file.add_command(
    label="Quitter",
    command=lambda: (
        core.confirm_discard_or_save(window, edit_zone, core.save_file)
        and window.quit()
    )
)


# ----- Crypto menu -----
menu_crypto.add_command(label="Crypter et enregistrer", command=lambda: core.encrypt_and_save_file(window, edit_zone))
menu_crypto.add_command(
    label="Décrypter un fichier",
    command=lambda: (
        core.confirm_discard_or_save(window, edit_zone, core.save_file)
        and core.open_encrypted_file(window, edit_zone)
    )
)



# ----- About menu -----
menu_about.add_command(label="Contact", command=lambda: core.show_about(window))

window.mainloop()
