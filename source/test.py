from flask import Flask, request, render_template, redirect, url_for, flash, session, send_from_directory
import os
import pyodbc
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from CryptoAPI import *
import base64

def load_key(file_path):
    with open(file_path, 'r') as file:
        base64_str = file.read().strip()
        try:
            bytes_data = base64.b64decode(base64_str)
            return bytes_data
        except Exception as e:
            print(f"Error decoding base64: {str(e)}")
    return None
def encrypt_file(file_path, key_file, output_path):
    key = load_key(key_file)
    with open(file_path, 'rb') as f:
        data = f.read()

    ciphertext = encrypt(key, data)
    
    with open(output_path, 'wb') as f:
        f.write(ciphertext.encode('utf-8'))

def decrypt_file(file_path, key_file, output_path):
    key = load_key(key_file)
    with open(file_path, 'rb') as f:
        ciphertext = f.read()
        
    data = decrypt(key, ciphertext)

    with open(output_path, 'wb') as f:
        f.write(ciphertext.encode(data))

filepath = "D:\\Hoc_tap\\Ki_6\\Cryptography\\Projects\\testdb\\uploads\\vlcsnap-2022-04-13-14h52m41s211.png"

encrypted_filepath = "D:\\Hoc_tap\\Ki_6\\Cryptography\\Projects\\testdb\\uploads\\vlcsnap.png"
decrypted_filepath = "D:\\Hoc_tap\\Ki_6\\Cryptography\\Projects\\testdb\\uploads\\vdeclcsnap.png"
encrypt_file(filepath, 'prisecretkey.pem', encrypted_filepath)
print("'''''''''''''''''''''''''''''''''''''''''''''''")
decrypt_file(filepath, 'prisecretkey.pem', decrypted_filepath)