# core/peer.py
# Coordinates peer discovery, secure handshake, and message I/O

import socket
import threading
import time
import os
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

# -----------------------------
# Global State
# -----------------------------
connections = []        # active TCP connections
peer_public_keys = {}   # {ip: public_key}
connected_ips = set()   # to avoid duplicate connections

peer_names = {}         # {ip: nickname}
my_name = ""            # set at startup

# Discover local interfaces for manual reporting
LOCAL_IPS = get_all_local_ips()

# Ephemeral keypair (for future encryption)
my_private_key, my_public_key = generate_key_pair()

# -----------------------------
# Connection Handling
# -----------------------------
def start_connection_listener(listen_port):
    """
    Start a TCP listener to accept incoming peer connections.
    Runs accept-loop in a daemon thread.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', listen_port))
    s.listen()
    print(f"[*] Listening for incoming peer connections on port {listen_port}...")

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
    """
    Actively connect to a peer's listening port if not already connected.
    """
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
    """
    Exchange public keys and nicknames to establish a secure connection.
    """
    peer_ip = addr[0]
    try:
        if is_incoming:
            # Incoming: receive peer's public key, then send ours
            peer_pubkey_bytes = sock.recv(BUFFER)
            peer_public_keys[peer_ip] = deserialize_public_key(peer_pubkey_bytes)
            sock.sendall(serialize_public_key(my_public_key))
            # Then exchange nicknames
            peer_name = sock.recv(BUFFER).decode().strip()
            sock.sendall(my_name.encode())
        else:
            # Outgoing: send ours first, then receive peer's
            sock.sendall(serialize_public_key(my_public_key))
            peer_pubkey_bytes = sock.recv(BUFFER)
            peer_public_keys[peer_ip] = deserialize_public_key(peer_pubkey_bytes)
            sock.sendall(my_name.encode())
            peer_name = sock.recv(BUFFER).decode().strip()

        peer_names[peer_ip] = peer_name or peer_ip
        connections.append(sock)
        connected_ips.add(peer_ip)
        print(f"[+] Secure connection established with {peer_name} ({peer_ip})")

        threading.Thread(target=listen_for_messages, args=(sock, addr), daemon=True).start()

    except Exception as e:
        print(f"[!] Failed to set up connection with {peer_ip}: {e}")
        sock.close()


# -----------------------------
# Communication Loops
# -----------------------------
def listen_for_messages(sock, addr):
    """
    Thread target: receive, decrypt, and display messages from a peer.
    """
    peer_ip = addr[0]
    try:
        while True:
            data = sock.recv(BUFFER)
            if not data:
                name = peer_names.get(peer_ip, peer_ip)
                print(f"[*] Connection to {name} ({peer_ip}) closed.")
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
    """
    Main loop: read user input, handle commands, or broadcast messages.
    """
    while True:
        msg = input()
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
        for conn in list(connections):
            ip = conn.getpeername()[0]
            if ip in peer_public_keys:
                try:
                    encrypted = encrypt_message(peer_public_keys[ip], msg)
                    conn.sendall(encrypted)
                except Exception as e:
                    print(f"[!] Encryption/send error to {ip}: {e}")
                    connections.remove(conn)
            else:
                print(f"[!] No public key for {ip}, message not sent.")


# -----------------------------
# Main Entry Point
# -----------------------------
def start_chat_node():
    """
    Initialize nickname, port, discovery, and start the chat loop.
    """
    global my_name
    my_name = input("Enter your nickname: ").strip() or "Anonymous"

    listen_port = int(input(f"Enter your listening port (default {DEFAULT_PORT}): ") or DEFAULT_PORT)
    threading.Thread(target=start_connection_listener, args=(listen_port,), daemon=True).start()

    start_discovery(listen_port)

    def connect_to_peers():
        while True:
            for ip, port in get_active_peers():
                if ip in LOCAL_IPS or ip in connected_ips:
                    continue
                print(f"[Discovery] Connecting to {ip}:{port}")
                initiate_peer_connections(ip, port)
            time.sleep(5)

    threading.Thread(target=connect_to_peers, daemon=True).start()

    # Announce local IPs
    print(f"[*] Listening on port {listen_port}. You can be reached at:")
    for ip in LOCAL_IPS:
        print(f"    • {ip}:{listen_port}")

    # PUBLIC TUNNEL via ngrok (optional)
    try:
        from pyngrok import ngrok
        token = os.environ.get("NGROK_AUTH_TOKEN", "").strip()
        if not token:
            token = input("Enter your ngrok authtoken to enable public tunnel (or press Enter to skip): ").strip()
        if token:
            ngrok.set_auth_token(token)
            tunnel = ngrok.connect(listen_port, "tcp")
            public_url = tunnel.public_url
            print(f"[*] Public tunnel established at {public_url}")
            print("    • Use this address in /connect on remote peers.")
        else:
            print("[*] Skipping public ngrok tunnel (no authtoken provided).")
    except ImportError:
        print("[!] pyngrok not installed; skipping public tunnel.")
    except Exception as e:
        print(f"[!] ngrok error: {e}")

    print("[*] Type your message and press Enter to send.")
    print("[*] Type /help to see available commands.")

    prompt_and_send_messages()
