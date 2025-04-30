import socket, threading
from utils import send_msg, recv_msg
from config import DEFAULT_PORT, BUFFER
from crypto_utils import (
    generate_key_pair,
    serialize_public_key,
    deserialize_public_key,
    encrypt_message,
    decrypt_message
)

connections = []  # global list to track all peer connections
peer_public_keys = {}  # {ip: public_key}

# Generate RSA key pair
my_private_key, my_public_key = generate_key_pair()

# receive message from peer or safely disconnect
def recv_loop(sock, addr):
    peer_ip = addr[0]
    try:
        peer_pubkey_bytes = sock.recv(BUFFER)
        peer_public_keys[peer_ip] = deserialize_public_key(peer_pubkey_bytes)
        sock.sendall(serialize_public_key(my_public_key))
        while True:
            data = sock.recv(BUFFER)
            if not data:
                print("[*] Connection closed.")
                break
            try:
                msg = decrypt_message(my_private_key, data)
                print(f"\n{peer_ip}: {msg}")
                # Ephemeral message: replace after 5 seconds
                threading.Thread(target=delete_message_notice, args=(peer_ip,), daemon=True).start()
            except Exception as e:
                print(f"Decryption error from {peer_ip}: {e}")
    finally:
        if sock in connections:
            connections.remove(sock)
        sock.close()

# print [message deleted] after delay
def delete_message_notice(peer_ip):
    time.sleep(5)
    print(f"{peer_ip}: [message deleted]")
    
# send message to all peers
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

# add to connections and start receive loop
def handle_peer(conn, addr):
    print(f"[+] Connected to {addr}")
    connections.append(conn)
    threading.Thread(target=recv_loop, args=(conn, addr), daemon=True).start() # receiving message thread

# listen to possible peer connections and handle peer connection
def start_listener(listen_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', listen_port))
    s.listen()
    print(f"[*] Listening for incoming peer connections on port {listen_port}...")
    while True:
        conn, addr = s.accept()
        handle_peer(conn, addr)

# create socket and connect to another peer
def connect_to_peer(host, listen_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, listen_port))
    print(f"[*] Connected to remote peer at {host}:{listen_port}")
    s.sendall(serialize_public_key(my_public_key))
    peer_pubkey_bytes = s.recv(BUFFER)
    peer_public_keys[host] = deserialize_public_key(peer_pubkey_bytes)
    handle_peer(s, (host, listen_port))

# start method that allows user to choose to connect to other peers, choose listening port, etc.
def start_peer():
    listen_port = int(input(f"Enter your listening port (default {DEFAULT_PORT}): ") or DEFAULT_PORT)
    threading.Thread(target=start_listener, args=(listen_port, ), daemon=True).start() # listener thread

    choice = input("Connect to existing peer? (y/n) ").lower() # initiate connection
    if choice == 'y':
        # connect to existing peer
        ip = input("Enter peer IP to connect: ")
        peer_port = int(input("Enter peer's listening port: "))
        connect_to_peer(ip, peer_port)
    else:
        # dont do anything - can either
            # 1. wait for others to connect to you
            # 2. chat locally to yourself (useless)
        print("[*] No connection. Chat locally or wait for others...")

    send_loop() # create main thread for sending messages


start_peer()
