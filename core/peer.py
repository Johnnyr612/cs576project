# core/peer.py

import socket
import threading
import time
from datetime import datetime

from core.discovery import start_discovery, get_active_peers
from core.utils import send_msg, recv_msg, get_all_local_ips
from core.config import DEFAULT_PORT, BUFFER
from core.ephemeral import delete_after_delay
from core.commands import handle_command
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

peer_names = {} # {ip: nickname}
my_name = ""    # set at startup

LOCAL_IPS = get_all_local_ips()

my_private_key, my_public_key = generate_key_pair()

### -----------------------------
### Connection Handling
### -----------------------------
def start_connection_listener(listen_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', listen_port))
    s.listen()
    print(f"[*] Listening for incoming peer connections on port {listen_port}...")

    # Run accept-loop in daemon thread for graceful shutdown
    def _accept_loop():
        while True:
            try:
                conn, addr = s.accept()
                accept_incoming_connections(conn, addr)
            except Exception as e:
                print(f"[!] Listener error: {e}")
                break

    threading.Thread(target=_accept_loop, daemon=True).start()


def accept_incoming_connections(conn, addr):
    perform_handshake(conn, addr, is_incoming=True)


def initiate_peer_connections(host, listen_port):
    if host in connected_ips:
        print(f"[!] Already connected to {host}, skipping.")
        return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, listen_port))
        perform_handshake(s, (host, listen_port), is_incoming=False)
    except Exception as e:
        print(f"[!] Connection attempt to {host}:{listen_port} failed: {e}")


def perform_handshake(sock, addr, is_incoming):
    peer_ip = addr[0]

    try:
        if is_incoming:
            # incoming: receive key, send key
            peer_pubkey_bytes = sock.recv(BUFFER)
            peer_public_keys[peer_ip] = deserialize_public_key(peer_pubkey_bytes)
            sock.sendall(serialize_public_key(my_public_key))

            # receive name, send name
            peer_name = sock.recv(BUFFER).decode().strip()
            sock.sendall(my_name.encode())
        else:
            # outgoing: send key, receive key
            sock.sendall(serialize_public_key(my_public_key))
            peer_pubkey_bytes = sock.recv(BUFFER)
            peer_public_keys[peer_ip] = deserialize_public_key(peer_pubkey_bytes)

            # send name, receive name
            sock.sendall(my_name.encode())
            peer_name = sock.recv(BUFFER).decode().strip()
        
        peer_names[peer_ip] = peer_name or peer_ip
        connections.append(sock)
        connected_ips.add(peer_ip)
        print(f"[+] Secure connection established with {peer_name} ({peer_ip})")

        # spawn a thread to listen for incoming messages on this socket
        threading.Thread(target=listen_for_messages, args=(sock, addr), daemon=True).start()

    except Exception as e:
        print(f"[!] Failed to set up connection with {peer_ip}: {e}")
        sock.close()

### -----------------------------
### Communication Loops
### -----------------------------
def listen_for_messages(sock, addr):
    peer_ip = addr[0]
    try:
        while True:
            try:
                data = sock.recv(BUFFER)
            except Exception as e:
                print(f"[!] Receive error from {peer_ip}: {e}")
                break

            if not data:
                name = peer_names.get(peer_ip, peer_ip)
                print(f"[*] Connection to {name} ({peer_ip}) closed.")

                # clean up on disconnect
                if sock in connections:
                    connections.remove(sock)
                peer_public_keys.pop(peer_ip, None)
                peer_names.pop(peer_ip, None)

                sock.close()
                break

            try:
                msg = decrypt_message(my_private_key, data)
                timestamp = datetime.now().strftime('%H:%M')
                name = peer_names.get(peer_ip, peer_ip)
                print(f"\n[{timestamp}] {name}: {msg}")
                delete_after_delay(peer_ip)
            except Exception as e:
                print(f"[!] Decryption error from {peer_ip}: {e}")
    except Exception as e:
        print(f"[!] Connection loop error: {e}")


def prompt_and_send_messages():
    while True:
        msg = input()

        # handle slash-commands
        if msg.startswith('/'):
            handle_command(
                cmd=msg.strip(),
                my_name=my_name,
                connections=connections,
                peer_names=peer_names,
                peer_public_keys=peer_public_keys
            )
            continue

        timestamp = datetime.now().strftime('%H:%M')
        print(f"[{timestamp}] You: {msg}")

        # iterate over a copy to allow removal on failure
        for conn in list(connections):
            ip = conn.getpeername()[0]
            key = peer_public_keys.get(ip)
            if not key:
                print(f"[!] No public key for {ip}, message not sent.")
                continue
            try:
                encrypted = encrypt_message(key, msg)
                conn.sendall(encrypted)
            except Exception as e:
                print(f"[!] Encryption/send error to {ip}: {e}")
                connections.remove(conn)

### -----------------------------
### Main Entry Point
### -----------------------------
def start_chat_node():
    global my_name
    my_name = input("Enter your nickname: ").strip() or "Anonymous"

    listen_port = int(input(f"Enter your listening port (default {DEFAULT_PORT}): ") or DEFAULT_PORT)
    threading.Thread(target=start_connection_listener, args=(listen_port,), daemon=True).start()

    # start peer discovery in background
    start_discovery(listen_port)

    # auto-connect to discovered peers periodically
    def connect_to_peers():
        while True:
            for ip, port in get_active_peers():
                if ip in LOCAL_IPS or ip in connected_ips:
                    continue # skip self or already connected
                print(f"[Discovery] Connecting to {ip}:{port}")
                initiate_peer_connections(ip, port)
            time.sleep(5)

    threading.Thread(target=connect_to_peers, daemon=True).start()

    print("[*] Type your message and press Enter to send.")
    print("[*] Type /help to see available commands.")

    prompt_and_send_messages()
