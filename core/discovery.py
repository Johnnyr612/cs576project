# core/discovery.py
# Peer Discovery via UDP broadcast

import socket
import threading
import time

from core.config import BUFFER
from core.utils import get_all_local_ips
LOCAL_IPS = get_all_local_ips()

DISCOVERY_PORT     = 9999   # port for UDP broadcast/listening
BROADCAST_INTERVAL = 5      # seconds between sending hello packets
PEER_TIMEOUT       = 60     # time before a peer is considered inactive

active_peers = {}           # {ip: (port, last_seen_timestamp)}
lock = threading.Lock()     # thread-safe access to active_peers


# periodically broadcasts a hello message containing this peer's listening port
def broadcast_hello(listen_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    msg = f"Hello:{listen_port}".encode()

    while True:
        s.sendto(msg, ('255.255.255.255', DISCOVERY_PORT))
        time.sleep(BROADCAST_INTERVAL)
    
# listens for hello messages from other peers and updates the active_peers dictionary with timestamps
def listen_for_peers():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # New: allow reuse so host & VM can both bind UDP port 9999
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('', DISCOVERY_PORT))  # may fail if port in use
    except OSError as e:
        print(f"[Discovery] UDP bind failed: {e}")
        return

    while True:
        try:
            data, addr = s.recvfrom(BUFFER)
            ip = addr[0]

            if ip in LOCAL_IPS:
                continue  # skip yourself

            if data.startswith(b'Hello:'):
                port = int(data.split(b':')[1])
                with lock:
                    active_peers[ip] = (port, time.time())
        except Exception as e:
            # New: log any errors in the receive loop without stopping discovery
            print(f"[Discovery] Error in listen_for_peers loop: {e}")

# returns a list of (ip, port) tuples for peers active within the timeout
def get_active_peers(timeout=PEER_TIMEOUT):
    now = time.time()
    with lock:
        return [
            (ip, port)
            for ip, (port, last_seen) in active_peers.items()
            if now - last_seen <= timeout
        ]
    
# starts broadcasting and listening in background threads
def start_discovery(listen_port):
    threading.Thread(
        target=broadcast_hello,
        args=(listen_port,),
        daemon=True
    ).start()
    threading.Thread(
        target=listen_for_peers,
        daemon=True
    ).start()
