import socket
import threading
from select import select
import hashlib
import os
import json
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

MAX_LEN = 200
NUM_COLORS = 6
clients = []
colors = ["\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[35m", "\033[36m"]
seed = 0
clients_lock = threading.Lock()
USER_DB_FILE = "users.json"
CHAT_HISTORY_DIR = "chat_histories"  # Directory to store chat history files

# Diffie-Hellman parameters
DH_P = 23  # Use a large prime in production
DH_G = 5   # Generator

# Ensure chat history directory exists
os.makedirs(CHAT_HISTORY_DIR, exist_ok=True)

# Load user data from JSON file
def load_users():
    if os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, 'r') as file:
            return json.load(file)
    return {}

# Save user data to JSON file
def save_users(users_db):
    with open(USER_DB_FILE, 'w') as file:
        json.dump(users_db, file)

# Initialize the user database
users_db = load_users()

def color(code):
    return colors[code % NUM_COLORS]

def encrypt_message(message, aes_key):
    iv = os.urandom(16)  # Generate a new IV for every message
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    return base64.b64encode(iv + encrypted_message).decode()

def decrypt_message(encrypted_message, aes_key):
    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:16]  # Extract the IV
    encrypted_message = encrypted_data[16:]  # The rest is the encrypted data

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()

    return message.decode()

def perform_key_exchange(client_socket):
    """Perform Diffie-Hellman key exchange."""
    # Step 1: Generate server's private and public keys
    server_private_key = secrets.randbelow(DH_P)
    server_public_key = pow(DH_G, server_private_key, DH_P)

    # Step 2: Send the server's public key to the client
    client_socket.sendall(str(server_public_key).encode())

    # Step 3: Receive the client's public key
    client_public_key = int(client_socket.recv(MAX_LEN).decode())

    # Step 4: Compute the shared secret
    shared_secret = pow(client_public_key, server_private_key, DH_P)

    # Step 5: Derive AES key from the shared secret
    aes_key = hashlib.sha256(str(shared_secret).encode()).digest()

    print(f"Shared secret (server): {shared_secret}")
    print(f"Derived AES key (server): {aes_key.hex()}")
    return aes_key

def save_user_chat_history(sender, recipient, message, aes_key):
    """Save the encrypted message to a file."""
    filename = f"{CHAT_HISTORY_DIR}/{sorted([sender, recipient])[0]}_{sorted([sender, recipient])[1]}_chat.txt"
    encrypted_message = encrypt_message(f"{sender}: {message}", aes_key)
    with open(filename, "a") as file:
        file.write(encrypted_message + "\n")

def retrieve_chat_history(user1, user2, aes_key):
    """Retrieve and decrypt chat history."""
    filename = f"{CHAT_HISTORY_DIR}/{sorted([user1, user2])[0]}_{sorted([user1, user2])[1]}_chat.txt"
    if not os.path.exists(filename):
        return "No chat history found."
    decrypted_history = []
    with open(filename, "r") as file:
        for line in file:
            decrypted_message = decrypt_message(line.strip(), aes_key)
            decrypted_history.append(decrypted_message)
    return "\n".join(decrypted_history)

def broadcast_message(message, sender_id, aes_key):
    """Broadcast a message to all clients except the sender."""
    sender_name = next(client['name'] for client in clients if client['id'] == sender_id)
    with clients_lock:
        for client in clients:
            if client['id'] != sender_id:
                try:
                    encrypted_message = encrypt_message(f"{sender_name}: {message}", client['aes_key'])
                    client['socket'].sendall(encrypted_message.encode())
                    save_user_chat_history(sender_name, client['name'], message, client['aes_key'])
                except OSError:
                    continue

def hash_password_sha256(password, salt):
    """Hash a password using SHA-256 with a salt."""
    return hashlib.sha256((salt + password).encode()).hexdigest()

def authenticate_or_register_user(client_socket):
    """Authenticate or register a user."""
    try:
        credentials = client_socket.recv(MAX_LEN).decode()
        credentials = json.loads(credentials)

        username = credentials.get("username")
        password = credentials.get("password")
        action = credentials.get("action")

        if action == "login":
            if username in users_db:
                stored_salt, stored_hash = users_db[username].split('$')
                if hash_password_sha256(password, stored_salt) == stored_hash:
                    client_socket.sendall("LOGIN_SUCCESS".encode())
                    return username
            client_socket.sendall("LOGIN_FAILED".encode())
            return None
        elif action == "register":
            if username in users_db:
                client_socket.sendall("REGISTER_FAILED".encode())
                return None
            else:
                salt = secrets.token_hex(16)
                password_hash = hash_password_sha256(password, salt)
                users_db[username] = f"{salt}${password_hash}"
                save_users(users_db)
                client_socket.sendall("REGISTER_SUCCESS".encode())
                return username
    except Exception as e:
        print(f"Error in authenticate_or_register_user: {e}")
        client_socket.sendall("ERROR".encode())
        return None

def handle_client(client_socket, client_address, client_id):
    """Handle a single client connection."""
    global clients
    name = None
    try:
        # Perform key exchange to derive an AES key
        aes_key = perform_key_exchange(client_socket)

        # Authenticate or register the user
        name = authenticate_or_register_user(client_socket)
        if not name:
            client_socket.close()
            return

        client_color = color(client_id)

        # Retrieve chat history
        chat_history = retrieve_chat_history(name, "other_user", aes_key)  # Replace "other_user" with actual contacts

        # Send chat history to the client
        client_socket.sendall(chat_history.encode())

        with clients_lock:
            clients.append({'id': client_id, 'name': name, 'socket': client_socket, 'color': client_color, 'aes_key': aes_key})

        welcome_message = f"{name} has joined"
        broadcast_message(welcome_message, client_id, aes_key)
        print(client_color + welcome_message + "\033[0m")

        while True:
            ready, _, _ = select([client_socket], [], [], 0.1)
            if ready:
                encrypted_message = client_socket.recv(MAX_LEN).decode()
                if not encrypted_message or encrypted_message == "#exit":
                    break
                message = decrypt_message(encrypted_message, aes_key)
                broadcast_message(message, client_id, aes_key)
                print(client_color + f"{name}: {message}" + "\033[0m")
    except Exception as e:
        print(f"Error handling client {name}: {e}")
    finally:
        if name:
            with clients_lock:
                clients = [c for c in clients if c['id'] != client_id]
            client_socket.close()
            leave_message = f"{name} has left"
            broadcast_message(leave_message, client_id, aes_key)
            print(client_color + leave_message + "\033[0m")
        else:
            client_socket.close()


def main():
    """Main server loop."""
    global seed
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 10000))
    server_socket.listen(8)
    print(colors[NUM_COLORS - 1] + "\n\t  ====== Welcome to the chat-room ======   " + "\033[0m")
    while True:
        client_socket, client_address = server_socket.accept()
        seed += 1
        threading.Thread(target=handle_client, args=(client_socket, client_address, seed), daemon=True).start()

if __name__ == "__main__":
    main()