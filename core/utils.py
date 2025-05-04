# core/utils.py

import socket
import subprocess
import re

from core.config import BUFFER

def send_msg(sock, msg):
    sock.sendall(msg.encode())

def recv_msg(sock):
    try: return sock.recv(BUFFER).decode()
    except: return ""

# prevent connecting to yourself
# TODO: scuffed fix - i kept running into issues where i would connect to my WSL IP address and didnt know how to fix it
# TODO: this is a temporary fix, if someone could look into this as well that would be great
def get_all_local_ips():
    ips = set()

    # method 1: try connect trick (should get real LAN IP)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 1))
        ips.add(s.getsockname()[0])
        s.close()
    except:
        pass

    # method 2: fallback to getaddrinfo
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            ips.add(ip)
    except:
        pass

    # method 3: WSL-safe interface scan (shell call)
    try:
        output = subprocess.check_output(["ip", "-4", "addr"], encoding="utf-8")
        matches = re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", output)
        for ip in matches:
            if not ip.startswith("127."):
                ips.add(ip)
    except:
        pass

    # always skip localhost
    ips.add("127.0.0.1")
    return ips