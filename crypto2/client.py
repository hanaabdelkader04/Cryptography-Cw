import socket
import threading
import sys
import signal
import time
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

MAX_LEN = 200
exit_flag = False

# Generate RSA key pair for the client
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Serialize the public key to send to the server
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# Decrypt received RSA-encrypted message
def rsa_decrypt_message(encrypted_message):
    return private_key.decrypt(
        encrypted_message,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

def send_message():
    global exit_flag
    while not exit_flag:
        try:
            message = input("You: ")
            client_socket.sendall(message.encode())
            if message == "#exit":
                exit_flag = True
                client_socket.close()
                return
        except OSError:
            return

def recv_message():
    global exit_flag
    while not exit_flag:
        try:
            encrypted_message = client_socket.recv(MAX_LEN)
            if not encrypted_message:
                continue
            try:
                # Attempt to decrypt using the private key
                message = rsa_decrypt_message(encrypted_message)
                print(f"\r{message}")
            except Exception as e:
                print(f"\r[ERROR Decrypting]: {e}")
            print("You: ", end="", flush=True)
        except:
            break
    print("Disconnected from server.")

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

def login_or_register():
    while True:
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
    return False

def main():
    global client_socket
    signal.signal(signal.SIGINT, signal_handler)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('127.0.0.1', 10000)
    try:
        client_socket.connect(server_address)
    except ConnectionRefusedError:
        print("Failed to connect to the server. Is it running?")
        sys.exit(1)

    # Send public key to server upon connecting
    client_socket.sendall(public_key_pem.encode())
    # Print the public key PEM to check its format before sending
    print("Public Key PEM (client side):")
    print(public_key_pem)


    if not login_or_register():
        client_socket.close()
        sys.exit(0)

    threading.Thread(target=send_message, daemon=True).start()
    threading.Thread(target=recv_message, daemon=True).start()

    try:
        while not exit_flag:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)

if __name__ == "__main__":
    main()
