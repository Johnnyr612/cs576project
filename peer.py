import socket, threading
from utils import send_msg, recv_msg
from config import PORT, BUFFER

def handle_peer(conn, addr):
    print(f"[+] Connected: {addr}")
    while True:
        msg = recv_msg(conn)
        if not msg: break
        print("f{addr}: {msg}")
    conn.close()

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # TCP socket
    s.bind(('', PORT))                                      # bind to all interfaces
    s.listen()
    print(f"[*] Listening on port {PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_peer, args=(conn,addr)).start()

def connect_to_peer(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, PORT))
    print("[*] Connected to peer")
    while True:
        msg = input("> ")
        send_msg(s, msg)

# Run one or the other. Eventually each user will be host and client
# start_server()               # host
# connect_to_peer('127.0.0.1') # client