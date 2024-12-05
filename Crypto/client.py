import socket
import threading
import sys
import signal
import time
import json
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os

MAX_LEN = 200
exit_flag = False

# Diffie-Hellman parameters (must match the server)
DH_P = 23  # Use a large prime in production
DH_G = 5   # Generator

def encrypt_message(message, aes_key):
    """Encrypts a message using AES with the provided key."""
    iv = os.urandom(16)  # Generate a random IV for every message
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    return base64.b64encode(iv + encrypted_message).decode()

def decrypt_message(encrypted_message, aes_key):
    """Decrypts a message using AES with the provided key."""
    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:16]  # Extract the IV (first 16 bytes)
    encrypted_message = encrypted_data[16:]  # The rest is the encrypted data

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()

    return message.decode()

def perform_key_exchange(client_socket):
    """Perform Diffie-Hellman key exchange."""
    # Step 1: Generate client's private and public keys
    client_private_key = secrets.randbelow(DH_P)
    client_public_key = pow(DH_G, client_private_key, DH_P)

    # Step 2: Receive the server's public key
    server_public_key = int(client_socket.recv(MAX_LEN).decode())
    print(f"Received server public key: {server_public_key}")

    # Step 3: Send the client's public key to the server
    client_socket.sendall(str(client_public_key).encode())
    print(f"Sent client public key: {client_public_key}")

    # Step 4: Compute the shared secret
    shared_secret = pow(server_public_key, client_private_key, DH_P)
    print(f"Shared secret (client): {shared_secret}")

    # Step 5: Derive AES key from the shared secret
    aes_key = hashlib.sha256(str(shared_secret).encode()).digest()
    print(f"Derived AES key (client): {aes_key.hex()}")

    return aes_key

def send_message(aes_key):
    """Send encrypted messages to the server."""
    global exit_flag
    while not exit_flag:
        try:
            message = input("You: ")
            encrypted_message = encrypt_message(message, aes_key)
            client_socket.sendall(encrypted_message.encode())
            if message == "#exit":
                exit_flag = True
                client_socket.close()
                return
        except OSError:
            return

def recv_message(aes_key):
    """Receive and decrypt messages from the server, including chat history."""
    global exit_flag
    while not exit_flag:
        try:
            encrypted_message = client_socket.recv(MAX_LEN).decode()
            if not encrypted_message:
                continue
            # Check if the message is chat history
            if encrypted_message.startswith("Chat History:"):
                # This is chat history from the server
                chat_history = decrypt_message(encrypted_message, aes_key)
                print(f"Chat history:\n{chat_history}")
            else:
                # Normal message
                message = decrypt_message(encrypted_message, aes_key)
                print(f"\r{message}")
            print("You: ", end="", flush=True)
        except Exception as e:
            print(f"Error receiving message: {e}")
            break
    print("Disconnected from server.")


def signal_handler(sig, frame):
    """Handle Ctrl+C signal to gracefully disconnect."""
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

def login_or_register():
    """Login or register a new user."""
    while True:
        try:
            choice = input("Type '1' to Login or '2' to Create a new account: ")
            if choice not in ('1', '2'):
                print("Invalid choice. Please enter '1' or '2'.")
                continue
            username = input("Enter your username: ")
            password = input("Enter your password: ")
            credentials = json.dumps({
                "username": username,
                "password": password,
                "action": "login" if choice == '1' else "register"
            })
            client_socket.sendall(credentials.encode())
            response = client_socket.recv(MAX_LEN).decode()
            print(f"Response from server: {response}")  # Debug log
            if response == "LOGIN_SUCCESS":
                print("\n\t  ====== Welcome to the chat-room ======   ")
                return True
            elif response == "REGISTER_SUCCESS":
                print("Account created successfully. You are now logged in!")
                return True
            elif response == "LOGIN_FAILED":
                print("Login failed. Check your credentials.")
            elif response == "REGISTER_FAILED":
                print("Username already exists. Try again.")
            else:
                print("Unknown error occurred.")
        except Exception as e:
            print(f"Error during login/register: {e}")
            return False

def main():
    """Main function to handle client operations."""
    global client_socket
    signal.signal(signal.SIGINT, signal_handler)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('127.0.0.1', 10000)
    try:
        client_socket.connect(server_address)
    except ConnectionRefusedError:
        print("Failed to connect to the server. Is it running?")
        sys.exit(1)

    # Step 1: Perform Diffie-Hellman key exchange to generate AES key
    aes_key = perform_key_exchange(client_socket)

    # Step 2: Authenticate or register
    if not login_or_register():
        client_socket.close()
        sys.exit(0)

    # Step 3: Start message threads
    threading.Thread(target=send_message, args=(aes_key,), daemon=True).start()
    threading.Thread(target=recv_message, args=(aes_key,), daemon=True).start()

    try:
        while not exit_flag:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)

if __name__ == "__main__":
    main()