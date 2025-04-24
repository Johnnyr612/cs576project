def send_msg(sock, msg):
    sock.sendall(msg.encode())

def recv_msg(sock):
    try: return sock.recv(1024).decode()
    except: return ""