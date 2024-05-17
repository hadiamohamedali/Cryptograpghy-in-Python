# ===================================================================
# Student Name : Hadia Mohamed Ali Heragy...                        =
# Project Name : Algorithms in Cryptography with Python....         =
# ===================================================================

# Export Important Libraries To Create My Project...
from tkinter import *
from tkinter import messagebox
from pyDes import des, ECB, PAD_PKCS5  # This Library for Des Cipher Algorithm..
import base64  # This Library Related With Ascii Code..


# =============================================================================================================

# ========================== Implementation of Algorithms =====================================================
# First Algorithm : Ceaser Cipher Algorithm..
# Encryption in Ceaser Algorithm...
def caesar_encrypt(plaintext, key):
    if key > 25 or key < 1:
        messagebox.showerror("Error", "Key must be in the range from 1 to 25")
        return ''

    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            if char.islower():
                ciphered_char = chr((ord(char) - 97 + key) % 26 + 97)
            else:
                ciphered_char = chr((ord(char) - 65 + key) % 26 + 65)
        else:
            ciphered_char = char
        ciphertext += ciphered_char

    return ciphertext


# GUI of Encryption in Ceaser...
def encrypt_caesar():
    plaintext = caesar_text.get(1.0, END)
    key_str = caesar_key.get()

    try:
        key = int(key_str)
    except ValueError:
        messagebox.showerror("Error", "Key must be an integer")
        return

    if key > 25 or key < 1:
        messagebox.showerror("Error", "Key must be in the range from 1 to 25")
        return

    ciphertext = caesar_encrypt(plaintext, key)
    if ciphertext:
        result_window = Toplevel(screen)
        result_window.title("Encryption Result")
        result_window.geometry("400x200")

        Label(result_window, text="ENCRYPTED MESSAGE", font="Arial 12 bold").pack()
        Text(result_window, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0).pack(fill=BOTH, expand=True)

        result_text = result_window.winfo_children()[1]
        result_text.insert(END, ciphertext)


# Decryption in Ceaser Algorithm...
def caesar_decrypt(ciphertext, key):
    if not (1 <= key <= 25):
        messagebox.showerror("Error", "Key must be in the range from 1 to 25")
        return ''

    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            if char.islower():
                plain_char = chr((ord(char) - 97 - key) % 26 + 97)
            else:
                plain_char = chr((ord(char) - 65 - key) % 26 + 65)
        else:
            plain_char = char
        plaintext += plain_char

    return plaintext


# GUI of Decryption in Ceaser...
def decrypt_caesar():
    ciphertext = caesar_text.get(1.0, END)
    key_str = caesar_key.get()

    try:
        key = int(key_str)
    except ValueError:
        messagebox.showerror("Error", "Key must be an integer")
        return

    if key > 25 or key < 1:
        messagebox.showerror("Error", "Key must be in the range from 1 to 25")
        return

    plaintext = caesar_decrypt(ciphertext, key)
    if plaintext:
        result_window = Toplevel(screen)
        result_window.title("Decryption Result")
        result_window.geometry("400x200")

        Label(result_window, text="DECRYPTED MESSAGE", font="Arial 12 bold").pack()
        Text(result_window, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0).pack(fill=BOTH, expand=True)

        result_text = result_window.winfo_children()[1]
        result_text.insert(END, plaintext)


# ============================================================================================================================================================
# ============================================================================================================================================================

# Second Algorithm : Vigenere Cipher Algorithm
# Encryption in Vigenere Algorithm...
def vigenere_encrypt(plaintext, key):
    lenp = len(plaintext)  # lenp => Length of Plaintext
    lenk = len(key)  # lenk => Length of Key

    ciphertext = ""
    for i in range(lenp):
        char = plaintext[i]
        if char.isalpha():
            shift = ord(key[i % lenk].lower()) - 97
            if char.islower():
                ciphered_char = chr((ord(char) - 97 + shift) % 26 + 97)
            else:
                ciphered_char = chr((ord(char) - 65 + shift) % 26 + 65)
        else:
            ciphered_char = char
        ciphertext += ciphered_char

    return ciphertext


# GUI of Encryption in Vigenere...
def encrypt_vigenere():
    plaintext = vigenere_text.get(1.0, END)
    key = vigenere_key.get()

    ciphertext = vigenere_encrypt(plaintext, key)
    if ciphertext:
        result_window = Toplevel(screen)
        result_window.title("Encryption Result")
        result_window.geometry("400x200")

        Label(result_window, text="ENCRYPTED MESSAGE", font="Arial 12 bold").pack()
        Text(result_window, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0).pack(fill=BOTH, expand=True)

        result_text = result_window.winfo_children()[1]
        result_text.insert(END, ciphertext)


# Decryption in Vigenere Algorithm...
def vigenere_decrypt(ciphertext, key):
    lenp = len(ciphertext)
    lenk = len(key)

    plaintext = ""
    for i in range(lenp):
        char = ciphertext[i]
        if char.isalpha():
            shift = ord(key[i % lenk].lower()) - 97
            if char.islower():
                plain_char = chr((ord(char) - 97 - shift) % 26 + 97)
            else:
                plain_char = chr((ord(char) - 65 - shift) % 26 + 65)
        else:
            plain_char = char
        plaintext += plain_char

    return plaintext


# GUI of Decryption in Vigenere...
def decrypt_vigenere():
    ciphertext = vigenere_text.get(1.0, END)
    key = vigenere_key.get()

    plaintext = vigenere_decrypt(ciphertext, key)
    if plaintext:
        result_window = Toplevel(screen)
        result_window.title("Decryption Result")
        result_window.geometry("400x200")

        Label(result_window, text="DECRYPTED MESSAGE", font="Arial 12 bold").pack()
        Text(result_window, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0).pack(fill=BOTH, expand=True)

        result_text = result_window.winfo_children()[1]
        result_text.insert(END, plaintext)


# =============================================================================================================================
# =============================================================================================================================

# Third Algorithm : Playfair Cipher Algorithm...
# Implementation of Algorithm Mechanism
def generate_key_square(key):
    key = key.replace(" ", "").upper()
    key_square = ""
    for char in key:
        if char not in key_square and char != "J":
            key_square += char
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in key_square:
            key_square += char
    return key_square


def prepare_text(text):
    text = text.replace(" ", "").upper()
    text = text.replace("J", "I")
    if len(text) % 2 != 0:
        text += "X"
    return text


def generate_playfair_pairs(text):
    pairs = []
    for i in range(0, len(text), 2):
        pairs.append(text[i:i + 2])
    return pairs


def find_char_position(square, char):
    try:
        index = square.index(char)
        row = index // 5
        col = index % 5
        return row, col
    except ValueError:
        return None, None


def encrypt_pair(square, pair):
    char1, char2 = pair
    row1, col1 = find_char_position(square, char1)
    row2, col2 = find_char_position(square, char2)
    if row1 == row2:
        return square[row1 * 5 + (col1 + 1) % 5] + square[row2 * 5 + (col2 + 1) % 5]
    elif col1 == col2:
        return square[((row1 + 1) % 5) * 5 + col1] + square[((row2 + 1) % 5) * 5 + col2]
    else:
        return square[row1 * 5 + col2] + square[row2 * 5 + col1]


def decrypt_pair(square, pair):
    char1, char2 = pair
    row1, col1 = find_char_position(square, char1)
    row2, col2 = find_char_position(square, char2)
    if row1 == row2:
        return square[row1 * 5 + (col1 - 1) % 5] + square[row2 * 5 + (col2 - 1) % 5]
    elif col1 == col2:
        return square[((row1 - 1) % 5) * 5 + col1] + square[((row2 - 1) % 5) * 5 + col2]
    else:
        return square[row1 * 5 + col2] + square[row2 * 5 + col1]


# =================================================================== #
# Encryption in Playfair Algorithm...
def encrypt_playfair(plaintext, key):
    key_square = generate_key_square(key)
    plaintext = prepare_text(plaintext)
    pairs = generate_playfair_pairs(plaintext)
    ciphertext = ""
    for pair in pairs:
        ciphertext += encrypt_pair(key_square, pair)
    return ciphertext


# Decryption in Playfair Algorithm...
def decrypt_playfair(ciphertext, key):
    key_square = generate_key_square(key)
    pairs = generate_playfair_pairs(ciphertext)
    plaintext = ""
    for pair in pairs:
        plaintext += decrypt_pair(key_square, pair)
    return plaintext


# GUI of Encryption in Playfair...
def encrypt_playfair_gui():
    plaintext = playfair_text.get(1.0, END)
    key = playfair_key.get()

    if not plaintext.strip() or not key.strip():
        messagebox.showerror("Error", "Please enter both plaintext and key")
        return

    ciphertext = encrypt_playfair(plaintext.strip(), key.strip())
    if ciphertext:
        result_window = Toplevel(screen)
        result_window.title("Encryption Result")
        result_window.geometry("400x200")

        Label(result_window, text="ENCRYPTED MESSAGE", font="Arial 12 bold").pack()
        Text(result_window, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0).pack(fill=BOTH, expand=True)

        result_text = result_window.winfo_children()[1]
        result_text.insert(END, ciphertext)


# GUI of Decryption in Playfair...
def decrypt_playfair_gui():
    ciphertext = playfair_text.get(1.0, END)
    key = playfair_key.get()

    if not ciphertext.strip() or not key.strip():
        messagebox.showerror("Error", "Please enter both ciphertext and key")
        return

    plaintext = decrypt_playfair(ciphertext.strip(), key.strip())
    if plaintext:
        result_window = Toplevel(screen)
        result_window.title("Decryption Result")
        result_window.geometry("400x200")

        Label(result_window, text="DECRYPTED MESSAGE", font="Arial 12 bold").pack()
        Text(result_window, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0).pack(fill=BOTH, expand=True)

        result_text = result_window.winfo_children()[1]
        result_text.insert(END, plaintext)


# =============================================================================================================================
# =============================================================================================================================

# Fourth Algorithm : DES Cipher Algorithm...
# Encryption in DES Algorithm...
def encrypt_des():
    plaintext = des_text.get(1.0, END).strip()
    key = des_key.get().strip()

    if not plaintext or not key:
        messagebox.showerror("Error", "Please enter both plaintext and key")
        return

    try:
        k = des(key, ECB, padmode=PAD_PKCS5)
        ciphertext = base64.b64encode(k.encrypt(plaintext.encode())).decode()
        result_window = Toplevel(screen)
        result_window.title("Encryption Result")
        result_window.geometry("400x200")

        Label(result_window, text="ENCRYPTED MESSAGE", font="Arial 12 bold").pack()
        Text(result_window, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0).pack(fill=BOTH, expand=True)

        result_text = result_window.winfo_children()[1]
        result_text.insert(END, ciphertext)

    except Exception as e:
        messagebox.showerror("Error", str(e))


def decrypt_des():
    ciphertext = des_text.get(1.0, END).strip()
    key = des_key.get().strip()

    if not ciphertext or not key:
        messagebox.showerror("Error", "Please enter both ciphertext and key")
        return

    try:
        k = des(key, ECB, padmode=PAD_PKCS5)
        plaintext = k.decrypt(base64.b64decode(ciphertext)).decode().strip()
        result_window = Toplevel(screen)
        result_window.title("Decryption Result")
        result_window.geometry("400x200")

        Label(result_window, text="DECRYPTED MESSAGE", font="Arial 12 bold").pack()
        Text(result_window, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0).pack(fill=BOTH, expand=True)

        result_text = result_window.winfo_children()[1]
        result_text.insert(END, plaintext)

    except Exception as e:
        messagebox.showerror("Error", str(e))


# =============================================================================================================================
# =============================================================================================================================

# Functions Related With Rest Button...
# ----------------------------------------
# Reset1 Button of Reset Caeser...
def reset1():
    caesar_key.set("")
    caesar_text.delete(1.0, END)
# ========================================================
# Reset2 Button of Reset Vigenere...
def reset2():
    vigenere_key.set("")
    vigenere_text.delete(1.0, END)
# ========================================================
# Reset3 Button of Reset Playfair...
def reset3():
    playfair_key.set("")
    playfair_text.delete(1.0, END)
# ========================================================
# Reset4 Button of Reset DES...
def reset4():
    des_key.set("")
    des_text.delete(1.0, END)


# =============================================================================================================================
# =============================================================================================================================

# ==================Main Code======================
def main_screen():
    # Global Variables To Create GUI
    global screen
    global caesar_key, vigenere_key
    global caesar_text, vigenere_text
    global playfair_key, playfair_text
    global des_key, des_text

    # Functions Related With GUI Screen...
    screen = Tk()
    screen.geometry("375x800")
    screen.title("PctApp")

    caesar_key = StringVar()
    vigenere_key = StringVar()
    playfair_key = StringVar()
    des_key = StringVar()

    # =======================================================================================================================

    # GUI Related With First Algorithm: Ceaser Cipher.....

    Label(text="Caesar Cipher Algorithm", fg="black", font=("calibri", 13)).place(x=10, y=10)
    caesar_text = Text(font="Roboto 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    caesar_text.place(x=10, y=50, width=355, height=100)

    Label(text="Enter Secret Key, Please", fg="black", font=("calibri", 13)).place(x=10, y=170)

    caesar_key = StringVar()
    Entry(textvariable=caesar_key, width=19, bd=0, font=("arial", 25), show="#").place(x=10, y=200)

    Button(text="ENCRYPT", height="2", width=23, bg="#ed3833", fg="white", bd=0, command=encrypt_caesar).place(x=10,
                                                                                                               y=250)
    Button(text="DECRYPT", height="2", width=23, bg="#00bd56", fg="white", bd=0, command=decrypt_caesar).place(x=200,
                                                                                                               y=250)
    Button(text="RESET", height="2", width=50, bg="#1089ff", fg="white", bd=0, command=reset1).place(x=10, y=300)

    Label(text="").place(x=10, y=330)

    # ========================================================================================================================

    # GUI Related With Second Algorithm: Vigenere Cipher Algorithm....

    Label(text="Vigenere Cipher Algorithm", fg="black", font=("calibri", 13)).place(x=10, y=350)
    vigenere_text = Text(font="Roboto 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    vigenere_text.place(x=10, y=390, width=355, height=100)

    Label(text="Enter Secret Key, Please", fg="black", font=("calibri", 13)).place(x=10, y=510)

    vigenere_key = StringVar()
    Entry(textvariable=vigenere_key, width=19, bd=0, font=("arial", 25), show="#").place(x=10, y=540)

    Button(text="ENCRYPT", height="2", width=23, bg="#ed3833", fg="white", bd=0, command=encrypt_vigenere).place(x=10,
                                                                                                                 y=590)
    Button(text="DECRYPT", height="2", width=23, bg="#00bd56", fg="white", bd=0, command=decrypt_vigenere).place(x=200,
                                                                                                                 y=590)
    Button(text="RESET", height="2", width=50, bg="#1089ff", fg="white", bd=0, command=reset2).place(x=10, y=640)
    # ================================================================================
    Label(text="").place(x=10, y=670)  # This Space To Make Playfair Beside Ceaser =
    # ================================================================================
    # ========================================================================================================================

    # GUI Related with Third Algorithm : Playfair Cipher Algorithm...

    Label(text="Playfair Cipher Algorithm", fg="black", font=("calibri", 13)).place(x=385, y=10)
    playfair_text = Text(font="Roboto 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    playfair_text.place(x=385, y=50, width=355, height=100)

    Label(text="Enter Secret Key, Please", fg="black", font=("calibri", 13)).place(x=385, y=170)

    playfair_key = StringVar()
    Entry(textvariable=playfair_key, width=19, bd=0, font=("arial", 25), show="#").place(x=385, y=200)

    Button(text="ENCRYPT", height="2", width="23", bg="#ed3833", fg="white", bd=0, command=encrypt_playfair_gui).place(
        x=385,
        y=250)
    Button(text="DECRYPT", height="2", width="23", bg="#00bd56", fg="white", bd=0, command=decrypt_playfair_gui).place(
        x=575,
        y=250)
    Button(text="RESET", height="2", width="50", bg="#1089ff", fg="white", bd=0, command=reset3).place(x=385, y=300)
    # ========================================================================================================================

    # GUI Related with Fourth Algorithm : DES Cipher Algorithm...

    Label(screen, text="DES Cipher Algorithm", fg="black", font=("calibri", 13)).place(x=385, y=350)
    des_text = Text(screen, font="Roboto 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    des_text.place(x=385, y=390, width=355, height=100)

    Label(screen, text="Enter Secret Key, Please", fg="black", font=("calibri", 13)).place(x=385, y=510)

    des_key = StringVar()
    Entry(screen, textvariable=des_key, width=19, bd=0, font=("arial", 25), show="#").place(x=385, y=540)

    Button(screen, text="ENCRYPT", height="2", width=23, bg="#ed3833", fg="white", bd=0, command=encrypt_des).place(
        x=385,
        y=590)
    Button(screen, text="DECRYPT", height="2", width=23, bg="#00bd56", fg="white", bd=0, command=decrypt_des).place(
        x=575,
        y=590)
    Button(screen, text="RESET", height="2", width="50", bg="#1089ff", fg="white", bd=0, command=reset4).place(x=385,
                                                                                                               y=640)

    # ======================================================================================================================
    screen.mainloop()


main_screen()
