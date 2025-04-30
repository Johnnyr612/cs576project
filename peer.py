import socket, threading
from utils import send_msg, recv_msg
from config import DEFAULT_PORT, BUFFER

connections = []  # global list to track all peer connections

# receive message from peer or safely disconnect
def recv_loop(sock):
    while True:
        msg = recv_msg(sock) # receive messages
        if not msg:
            print("[*] Connection closed.")
            connections.remove(sock)
            sock.close()
            break
        print(f"\nPeer: {msg}")

# send message to all peers
def send_loop():
    while True:
        msg = input("> ")
        for conn in connections:
            send_msg(conn, msg)

# add to connections and start receive loop
def handle_peer(conn, addr):
    print(f"[+] Connected to {addr}")
    connections.append(conn)
    threading.Thread(target=recv_loop, args=(conn,), daemon=True).start() # receiving message thread

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
    print("[*] Connected to remote peer at {host}:{target_port}")
    handle_peer(s, host)

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
