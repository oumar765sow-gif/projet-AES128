
import tkinter as tk
from tkinter import ttk, messagebox
import secrets
import base64

from aes import encrypt_block, decrypt_block


# =====================================================
# PARTIE 1 : FONCTIONS DE CHIFFREMENT AES-CBC
# =====================================================

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def pad(data):
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def unpad(data):
    n = data[-1]

    if n < 1 or n > 16:
        raise ValueError("Remplissage invalide.")

    if data[-n:] != bytes([n]) * n:
        raise ValueError("Remplissage invalide.")

    return data[:-n]


def encrypt_cbc(plaintext, key):
    iv = secrets.token_bytes(16)
    data = pad(plaintext)
    result = b""
    previous = iv

    for i in range(0, len(data), 16):
        block = xor_bytes(data[i:i + 16], previous)
        encrypted = encrypt_block(block, key)
        result += encrypted
        previous = encrypted

    return base64.b64encode(iv + result).decode("ascii")


def decrypt_cbc(encoded, key):
    raw = base64.b64decode(encoded, validate=True)

    if len(raw) < 32 or len(raw) % 16 != 0:
        raise ValueError("Texte chiffre invalide.")

    iv = raw[:16]
    ciphertext = raw[16:]
    result = b""
    previous = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        decrypted = decrypt_block(block, key)
        result += xor_bytes(decrypted, previous)
        previous = block

    return unpad(result)


# =====================================================
# PARTIE 2 : COULEURS ET STYLE
# =====================================================

BG = "#101827"
PANEL = "#1C293B"
WHITE = "#F5F7FA"
MUTED = "#AAB8C8"
BLUE = "#2878D0"
GREEN = "#15966B"
RED = "#D94B55"
ENTRY_BG = "#111C2B"


# =====================================================
# PARTIE 3 : FONCTIONS DE L'APPLICATION
# =====================================================

def get_key():
    value = key_entry.get().strip()

    if len(value) != 32:
        raise ValueError(
            "La cle doit contenir exactement 32 caracteres hexadecimaux."
        )

    try:
        key = bytes.fromhex(value)
    except ValueError:
        raise ValueError("La cle contient des caracteres invalides.")

    if len(key) != 16:
        raise ValueError("La cle doit faire 128 bits.")

    return key


def generate_key():
    key_entry.delete(0, tk.END)
    key_entry.insert(0, secrets.token_bytes(16).hex())
    set_status("Nouvelle cle AES-128 generee.", GREEN)


def toggle_key():
    if key_entry.cget("show") == "*":
        key_entry.config(show="")
        show_button.config(text="Masquer")
    else:
        key_entry.config(show="*")
        show_button.config(text="Afficher")


def encrypt_text():
    try:
        plaintext = input_text.get("1.0", "end-1c")

        if not plaintext:
            raise ValueError("Veuillez saisir un texte clair.")

        key = get_key()
        encrypted = encrypt_cbc(
            plaintext.encode("utf-8"), key
        )

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, encrypted)

        set_status("Chiffrement termine avec succes.", GREEN)

    except Exception as error:
        set_status("Echec du chiffrement.", RED)
        messagebox.showerror("Erreur", str(error))


def decrypt_text():
    try:
        ciphertext = output_text.get("1.0", "end-1c").strip()

        if not ciphertext:
            raise ValueError(
                "Aucun texte chiffre dans la zone de resultat."
            )

        key = get_key()
        decrypted = decrypt_cbc(ciphertext, key)

        plaintext = decrypted.decode("utf-8")

        input_text.delete("1.0", tk.END)
        input_text.insert(tk.END, plaintext)

        set_status("Dechiffrement termine avec succes.", GREEN)

    except Exception as error:
        set_status("Echec du dechiffrement.", RED)
        messagebox.showerror("Erreur", str(error))


def clear_fields():
    input_text.delete("1.0", tk.END)
    output_text.delete("1.0", tk.END)
    set_status("Zones de texte effacees.", MUTED)


def copy_result():
    result = output_text.get("1.0", "end-1c")

    if not result:
        messagebox.showwarning(
            "Attention", "Aucun resultat a copier."
        )
        return

    root.clipboard_clear()
    root.clipboard_append(result)
    set_status("Resultat copie dans le presse-papiers.", GREEN)


def set_status(message, color):
    status_label.config(text=message, fg=color)


# =====================================================
# PARTIE 4 : FENETRE PRINCIPALE
# =====================================================

root = tk.Tk()
root.title("Application AES-128")
root.geometry("1000x780")
root.minsize(800, 680)
root.configure(bg=BG)


# Style des boutons
style = ttk.Style()
style.theme_use("clam")

style.configure(
    "Blue.TButton",
    background=BLUE,
    foreground=WHITE,
    padding=10,
    font=("Arial", 10, "bold")
)

style.map(
    "Blue.TButton",
    background=[("active", "#398CE5")]
)

style.configure(
    "Green.TButton",
    background=GREEN,
    foreground=WHITE,
    padding=10,
    font=("Arial", 10, "bold")
)

style.map(
    "Green.TButton",
    background=[("active", "#20B985")]
)

style.configure(
    "Gray.TButton",
    background="#394A60",
    foreground=WHITE,
    padding=10,
    font=("Arial", 10, "bold")
)


# =====================================================
# PARTIE 5 : EN-TETE
# =====================================================

header = tk.Frame(root, bg=BG)
header.pack(fill="x", padx=30, pady=(25, 15))

tk.Label(
    header,
    text="AES-128",
    bg=BG,
    fg=WHITE,
    font=("Arial", 27, "bold")
).pack()

tk.Label(
    header,
    text="APPLICATION DE CHIFFREMENT ET DE DECHIFFREMENT",
    bg=BG,
    fg=MUTED,
    font=("Arial", 10)
).pack(pady=5)


# =====================================================
# PARTIE 6 : PANNEAU DE LA CLE
# =====================================================

key_panel = tk.Frame(root, bg=PANEL, padx=20, pady=18)
key_panel.pack(fill="x", padx=30, pady=10)

tk.Label(
    key_panel,
    text="CLE SECRETE AES-128",
    bg=PANEL,
    fg=WHITE,
    font=("Arial", 11, "bold")
).pack(anchor="w")

key_row = tk.Frame(key_panel, bg=PANEL)
key_row.pack(fill="x", pady=10)

key_entry = tk.Entry(
    key_row,
    font=("Consolas", 12),
    bg=ENTRY_BG,
    fg=WHITE,
    insertbackground=WHITE,
    relief="flat",
    show="*"
)
key_entry.pack(side="left", fill="x", expand=True, ipady=10)

show_button = tk.Button(
    key_row,
    text="Afficher",
    command=toggle_key,
    bg="#394A60",
    fg=WHITE,
    relief="flat",
    padx=12
)
show_button.pack(side="left", padx=8)

ttk.Button(
    key_row,
    text="Generer une cle",
    style="Blue.TButton",
    command=generate_key
).pack(side="left")

tk.Label(
    key_panel,
    text="128 bits = 16 octets = 32 caracteres hexadecimaux",
    bg=PANEL,
    fg=MUTED,
    font=("Arial", 9)
).pack(anchor="w")


# =====================================================
# PARTIE 7 : ZONES DE TEXTE
# =====================================================

content = tk.Frame(root, bg=BG)
content.pack(fill="both", expand=True, padx=30, pady=15)

content.columnconfigure(0, weight=1)
content.columnconfigure(1, weight=1)
content.rowconfigure(1, weight=1)

tk.Label(
    content,
    text="TEXTE CLAIR",
    bg=BG,
    fg=WHITE,
    font=("Arial", 11, "bold")
).grid(row=0, column=0, sticky="w", pady=8)

tk.Label(
    content,
    text="TEXTE CHIFFRE (BASE64)",
    bg=BG,
    fg=WHITE,
    font=("Arial", 11, "bold")
).grid(row=0, column=1, sticky="w", pady=8)

input_text = tk.Text(
    content,
    height=12,
    wrap="word",
    font=("Consolas", 11),
    bg=ENTRY_BG,
    fg=WHITE,
    insertbackground=WHITE,
    relief="flat",
    padx=12,
    pady=12
)
input_text.grid(
    row=1, column=0, sticky="nsew", padx=(0, 8)
)

output_text = tk.Text(
    content,
    height=12,
    wrap="word",
    font=("Consolas", 11),
    bg=ENTRY_BG,
    fg="#67D9B0",
    insertbackground=WHITE,
    relief="flat",
    padx=12,
    pady=12
)
output_text.grid(
    row=1, column=1, sticky="nsew", padx=(8, 0)
)


# =====================================================
# PARTIE 8 : BOUTONS D'ACTION
# =====================================================

actions = tk.Frame(root, bg=BG)
actions.pack(pady=15)

ttk.Button(
    actions,
    text="CHIFFRER",
    style="Blue.TButton",
    command=encrypt_text
).grid(row=0, column=0, padx=8)

ttk.Button(
    actions,
    text="DECHIFFRER",
    style="Green.TButton",
    command=decrypt_text
).grid(row=0, column=1, padx=8)

ttk.Button(
    actions,
    text="COPIER RESULTAT",
    style="Gray.TButton",
    command=copy_result
).grid(row=0, column=2, padx=8)

ttk.Button(
    actions,
    text="EFFACER",
    style="Gray.TButton",
    command=clear_fields
).grid(row=0, column=3, padx=8)


# =====================================================
# PARTIE 9 : BARRE D'ETAT ET PIED DE PAGE
# =====================================================

status_label = tk.Label(
    root,
    text="Application prete.",
    bg=BG,
    fg=MUTED,
    font=("Arial", 10)
)
status_label.pack(pady=10)

tk.Label(
    root,
    text="PROJET UNIVERSITAIRE | IMPLEMENTATION MANUELLE AES-128",
    bg=BG,
    fg="#718096",
    font=("Arial", 9)
).pack(pady=(5, 18))


# Lancement de l'application
root.mainloop()
