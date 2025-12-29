# secure_file_transfer/receiver_gui.py
import os
import socket
import json
import base64
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Cipher import DES3, PKCS1_v1_5

KEY_SIZE = 2048
IV_SIZE = 8
SESSION_KEY_SIZE = 24


def generate_keys(private_file, public_file):
    key = RSA.generate(KEY_SIZE)
    with open(private_file, 'wb') as f:
        f.write(key.export_key())
    with open(public_file, 'wb') as f:
        f.write(key.publickey().export_key())


def load_key(file):
    with open(file, 'rb') as f:
        return RSA.import_key(f.read())


def recv_json(sock):
    length = int.from_bytes(sock.recv(4), 'big')
    data = sock.recv(length)
    return json.loads(data.decode())


def send_response(sock, msg):
    msg_bytes = msg.encode()
    sock.sendall(len(msg_bytes).to_bytes(4, 'big') + msg_bytes)


def handle_connection(conn, out_dir, log_widget):
    try:
        if conn.recv(6) != b"Hello!":
            log_widget.insert(tk.END, "Invalid handshake\n")
            conn.close()
            return

        conn.sendall(b"Ready!")

        key_packet = recv_json(conn)
        metadata = key_packet["metadata"]
        signature = base64.b64decode(key_packet["signature"])
        encrypted_session_key = base64.b64decode(key_packet["session_key"])

        metadata_bytes = json.dumps(metadata).encode()

        sender_pub = load_key('sender_public_key.pem')
        receiver_priv = load_key('receiver_private_key.pem')

        h = SHA512.new(metadata_bytes)
        pkcs1_15.new(sender_pub).verify(h, signature)

        session_key = PKCS1_v1_5.new(receiver_priv).decrypt(encrypted_session_key, None)
        if session_key is None:
            raise ValueError("SessionKey decryption failed")

        decrypted_parts = []
        for _ in range(3):
            part = recv_json(conn)
            iv = base64.b64decode(part["iv"])
            cipher = base64.b64decode(part["cipher"])
            hash_recv = base64.b64decode(part["hash"])
            sig = base64.b64decode(part["sig"])

            h_part = SHA512.new(iv + cipher).digest()
            h_sig = SHA512.new(h_part)
            pkcs1_15.new(sender_pub).verify(h_sig, sig)

            decipher = DES3.new(session_key, DES3.MODE_CBC, iv)
            padded_plain = decipher.decrypt(cipher)
            decrypted_parts.append(padded_plain.rstrip(b' '))

        full_data = b''.join(decrypted_parts)
        output_path = os.path.join(out_dir, metadata['filename'])
        with open(output_path, 'wb') as f:
            f.write(full_data)

        send_response(conn, "ACK")
        log_widget.insert(tk.END, "File received and verified successfully!\n")

    except Exception as e:
        send_response(conn, f"NACK: {str(e)}")
        log_widget.insert(tk.END, f"Error: {str(e)}\n")
    finally:
        conn.close()


def start_server(port, out_dir, log_widget):
    if not os.path.exists('receiver_private_key.pem'):
        generate_keys('receiver_private_key.pem', 'receiver_public_key.pem')

    if not os.path.exists('sender_public_key.pem'):
        messagebox.showerror("Error", "Missing sender_public_key.pem")
        return

    s = socket.socket()
    s.bind(('0.0.0.0', port))
    s.listen(1)
    log_widget.insert(tk.END, f"Listening on port {port}...\n")

    conn, addr = s.accept()
    log_widget.insert(tk.END, f"Connection from {addr}\n")
    handle_connection(conn, out_dir, log_widget)
    s.close()


def launch_gui():
    root = tk.Tk()
    root.title("Receiver Application")

    tk.Label(root, text="Port:").grid(row=0, column=0)
    port_entry = tk.Entry(root)
    port_entry.grid(row=0, column=1)
    port_entry.insert(0, "12345")

    tk.Label(root, text="Output Directory:").grid(row=1, column=0)
    out_entry = tk.Entry(root, width=40)
    out_entry.grid(row=1, column=1)

    def browse():
        folder = filedialog.askdirectory()
        if folder:
            out_entry.delete(0, tk.END)
            out_entry.insert(0, folder)

    tk.Button(root, text="Browse", command=browse).grid(row=1, column=2)

    log_widget = tk.Text(root, height=10, width=60)
    log_widget.grid(row=2, column=0, columnspan=3)

    def start():
        port = int(port_entry.get())
        out_dir = out_entry.get()
        threading.Thread(target=start_server, args=(port, out_dir, log_widget), daemon=True).start()

    tk.Button(root, text="Start Server", command=start).grid(row=3, column=1)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
