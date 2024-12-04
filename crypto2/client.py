import socket
import threading
import sys
import signal
import time
import json
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

MAX_LEN = 200
AES_KEY = None  # Will be set after login
exit_flag = False

# AES Key Derivation (matching server's method)
def derive_aes_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use hashes.SHA256 instead of SHA256
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# AES encryption and decryption
def encrypt_message(key, message):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    return base64.b64encode(iv + encrypted_message).decode()

def decrypt_message(key, encrypted_message):
    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:16]
    encrypted_message = encrypted_data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    
    return message.decode()

# Handle sending messages from the client
def send_message(client_socket):
    global exit_flag
    while not exit_flag:
        try:
            message = input("You: ")
            if message == "#exit":
                exit_flag = True
                client_socket.sendall(message.encode())
                client_socket.close()
                return
            elif message.startswith("#history"):
                target_user = message.split(" ")[1]
                client_socket.sendall(message.encode())
            else:
                encrypted_message = encrypt_message(AES_KEY, message)
                client_socket.sendall(encrypted_message.encode())
        except OSError:
            print("Error sending message.")
            break

# Handle receiving messages from the server
def recv_message(client_socket):
    global exit_flag
    while not exit_flag:
        try:
            encrypted_message = client_socket.recv(MAX_LEN).decode()
            if encrypted_message:
                decrypted_message = decrypt_message(AES_KEY, encrypted_message)
                print(f"\r{decrypted_message}")
            print("You: ", end="", flush=True)
        except:
            break
    print("Disconnected from server.")

# Clean exit when Ctrl+C is pressed
def signal_handler(sig, frame):
    global exit_flag
    if not exit_flag:
        print("\nDisconnecting...")
        exit_flag = True
        try:
            client_socket.sendall("#exit".encode())
        except OSError:
            pass
        client_socket.close()
        sys.exit(0)

# Handle user login or registration
def login_or_register(client_socket):
    while True:
        choice = input("Type '1' to Login or '2' to Create a new account: ")
        if choice not in ['1', '2']:
            print("Invalid choice. Please enter '1' for Login or '2' to Register.")
            continue

        username = input("Username: ")
        password = input("Password: ")

        action = "login" if choice == '1' else "register"
        credentials = {
            "username": username,
            "password": password,
            "action": action
        }

        client_socket.sendall(json.dumps(credentials).encode())
        response = client_socket.recv(MAX_LEN).decode()

        if response == "LOGIN_SUCCESS":
            print("Login successful!")
            AES_KEY = derive_aes_key(password, base64.b64decode(response.split(':')[1]))  # Get AES key from server
            break
        elif response == "REGISTER_SUCCESS":
            print("Registration successful! You can now log in.")
            break
        else:
            print("Login/Registration failed. Please try again.")

# Main function
def main():
    global client_socket
    global AES_KEY

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 10000))

    # Handle user login or registration
    login_or_register(client_socket)

    # Start threads for sending and receiving messages
    threading.Thread(target=send_message, args=(client_socket,), daemon=True).start()
    threading.Thread(target=recv_message, args=(client_socket,), daemon=True).start()

    # Catch CTRL+C to exit cleanly
    signal.signal(signal.SIGINT, signal_handler)

    # Keep the client running
    while not exit_flag:
        time.sleep(1)

if __name__ == "__main__":
    main()
