# secure_file_transfer/sender_gui.py
import os
import socket
import json
import base64
import time
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Cipher import DES3, PKCS1_v1_5
from Crypto.Random import get_random_bytes

KEY_SIZE = 2048
SESSION_KEY_SIZE = 24
IV_SIZE = 8


def generate_keys(private_file, public_file):
    key = RSA.generate(KEY_SIZE)
    with open(private_file, 'wb') as f:
        f.write(key.export_key())
    with open(public_file, 'wb') as f:
        f.write(key.publickey().export_key())


def load_key(file):
    with open(file, 'rb') as f:
        return RSA.import_key(f.read())


def create_metadata(file_path):
    filename = os.path.basename(file_path)
    timestamp = int(time.time())
    size = os.path.getsize(file_path)
    return {
        "filename": filename,
        "timestamp": timestamp,
        "size": size
    }


def sign_data(private_key, data_bytes):
    h = SHA512.new(data_bytes)
    return pkcs1_15.new(private_key).sign(h)


def send_json(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(len(data).to_bytes(4, 'big') + data)


def recv_response(sock):
    length = int.from_bytes(sock.recv(4), 'big')
    return sock.recv(length).decode()


def split_file(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
    part_size = len(content) // 3
    return [
        content[:part_size],
        content[part_size:2*part_size],
        content[2*part_size:]
    ]


def encrypt_part(session_key, part):
    iv = get_random_bytes(IV_SIZE)
    cipher = DES3.new(session_key, DES3.MODE_CBC, iv)
    padded = part + b' ' * (8 - len(part) % 8)
    ciphertext = cipher.encrypt(padded)
    return iv, ciphertext


def build_part_packet(private_key, iv, cipher):
    hash_val = SHA512.new(iv + cipher).digest()
    signature = pkcs1_15.new(private_key).sign(SHA512.new(hash_val))
    return {
        "iv": base64.b64encode(iv).decode(),
        "cipher": base64.b64encode(cipher).decode(),
        "hash": base64.b64encode(hash_val).decode(),
        "sig": base64.b64encode(signature).decode()
    }


def send_file(ip, port, file_path, log_widget):
    try:
        if not os.path.exists('sender_private_key.pem'):
            generate_keys('sender_private_key.pem', 'sender_public_key.pem')

        if not os.path.exists('receiver_public_key.pem'):
            messagebox.showerror("Error", "Missing receiver_public_key.pem")
            return

        sender_priv = load_key('sender_private_key.pem')
        receiver_pub = load_key('receiver_public_key.pem')

        s = socket.socket()
        s.connect((ip, port))
        s.sendall(b"Hello!")
        if s.recv(6) != b"Ready!":
            log_widget.insert(tk.END, "Handshake failed\n")
            return

        metadata = create_metadata(file_path)
        metadata_bytes = json.dumps(metadata).encode()
        signature = sign_data(sender_priv, metadata_bytes)

        session_key = get_random_bytes(SESSION_KEY_SIZE)
        cipher_rsa = PKCS1_v1_5.new(receiver_pub)
        encrypted_session_key = cipher_rsa.encrypt(session_key)

        send_json(s, {
            "metadata": metadata,
            "signature": base64.b64encode(signature).decode(),
            "session_key": base64.b64encode(encrypted_session_key).decode()
        })

        parts = split_file(file_path)
        for part in parts:
            iv, cipher = encrypt_part(session_key, part)
            packet = build_part_packet(sender_priv, iv, cipher)
            send_json(s, packet)

        response = recv_response(s)
        if response.startswith("ACK"):
            log_widget.insert(tk.END, "File sent successfully!\n")
        else:
            log_widget.insert(tk.END, f"Transfer failed: {response}\n")

        s.close()

    except Exception as e:
        log_widget.insert(tk.END, f"Error: {str(e)}\n")


def launch_gui():
    root = tk.Tk()
    root.title("Sender Application")

    tk.Label(root, text="Receiver IP:").grid(row=0, column=0)
    ip_entry = tk.Entry(root)
    ip_entry.grid(row=0, column=1)
    ip_entry.insert(0, "127.0.0.1")

    tk.Label(root, text="Port:").grid(row=1, column=0)
    port_entry = tk.Entry(root)
    port_entry.grid(row=1, column=1)
    port_entry.insert(0, "12345")

    tk.Label(root, text="Select File:").grid(row=2, column=0)
    file_entry = tk.Entry(root, width=40)
    file_entry.grid(row=2, column=1)

    def browse():
        path = filedialog.askopenfilename()
        if path:
            file_entry.delete(0, tk.END)
            file_entry.insert(0, path)

    tk.Button(root, text="Browse", command=browse).grid(row=2, column=2)

    log_widget = tk.Text(root, height=10, width=60)
    log_widget.grid(row=3, column=0, columnspan=3)

    def send():
        ip = ip_entry.get()
        port = int(port_entry.get())
        path = file_entry.get()
        threading.Thread(target=send_file, args=(ip, port, path, log_widget), daemon=True).start()

    tk.Button(root, text="Send File", command=send).grid(row=4, column=1)

    root.mainloop()


if __name__ == "__main__":
    launch_gui()
