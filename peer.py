# peer.py
import socket
import threading

from utils import send_msg, recv_msg
from config import DEFAULT_PORT, BUFFER
from ephemeral import delete_after_delay
from crypto.crypto_utils import (
    generate_key_pair,
    serialize_public_key,
    deserialize_public_key,
    encrypt_message,
    decrypt_message
)

### -----------------------------
### Global State
### -----------------------------
connections = []        # active TCP connections
peer_public_keys = {}   # {ip: public_key}
connected_ips = set()   # to avoid duplicate connections

my_private_key, my_public_key = generate_key_pair()

### -----------------------------
### Connection Handling
### -----------------------------
def handle_peer(conn, addr):
    print(f"[+] Connected to {addr}")
    connections.append(conn)
    connected_ips.add(addr[0])
    threading.Thread(target=recv_loop, args=(conn, addr), daemon=True).start()

def start_listener(listen_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', listen_port))
    s.listen()
    print(f"[*] Listening for incoming peer connections on port {listen_port}...")
    while True:
        conn, addr = s.accept()
        handle_peer(conn, addr)

def connect_to_peer(host, listen_port):
    if host in connected_ips:
        print(f"[!] Already connected to {host}, skipping.")
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, listen_port))
    print(f"[*] Connected to remote peer at {host}:{listen_port}")
    s.sendall(serialize_public_key(my_public_key))
    peer_pubkey_bytes = s.recv(BUFFER)
    peer_public_keys[host] = deserialize_public_key(peer_pubkey_bytes)
    handle_peer(s, (host, listen_port))

### -----------------------------
### Communication Loops
### -----------------------------
def recv_loop(sock, addr):
    peer_ip = addr[0]
    try:
        # exchange keys
        peer_pubkey_bytes = sock.recv(BUFFER)
        peer_public_keys[peer_ip] = deserialize_public_key(peer_pubkey_bytes)
        sock.sendall(serialize_public_key(my_public_key))

        # receive messages
        while True:
            data = sock.recv(BUFFER)
            if not data:
                print("[*] Connection closed.")
                connections.remove(sock)
                sock.close()
                break
            try:
                msg = decrypt_message(my_private_key, data)
                print(f"\n{peer_ip}: {msg}")
                delete_after_delay(peer_ip)
            except Exception as e:
                print(f"Decryption error from {peer_ip}: {e}")
    except Exception as e:
        print(f"Connection error: {e}")

def send_loop():
    while True:
        msg = input("You: ")
        for conn in connections:
            ip = conn.getpeername()[0]
            if ip in peer_public_keys:
                try:
                    encrypted = encrypt_message(peer_public_keys[ip], msg)
                    conn.sendall(encrypted)
                except Exception as e:
                    print(f"Encryption error to {ip}: {e}")
            else:
                print(f"[!] No public key for {ip}, message not sent.")

### -----------------------------
### Main Entry Point
### -----------------------------
def start_peer():
    listen_port = int(input(f"Enter your listening port (default {DEFAULT_PORT}): ") or DEFAULT_PORT)
    threading.Thread(target=start_listener, args=(listen_port,), daemon=True).start()

    choice = input("Connect to existing peer? (y/n) ").lower()
    if choice == 'y':
        ip = input("Enter peer IP to connect: ")
        peer_port = int(input("Enter peer's listening port: "))
        connect_to_peer(ip, peer_port)
    else:
        print("[*] No connection. Chat locally or wait for others...")

    send_loop()