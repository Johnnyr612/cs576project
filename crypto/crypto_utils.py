# core/utils.py
# Utility functions for socket I/O and IP discovery

import socket
import subprocess
import re
import logging

from core.config import BUFFER


def send_msg(sock: socket.socket, msg: str) -> None:
    """
    Send a UTF-8 encoded message over the given socket.

    Errors are logged rather than raised.
    """
    try:
        sock.sendall(msg.encode('utf-8'))
    except Exception as e:
        logging.error(f"[utils] send_msg failed: {e}")


def recv_msg(sock: socket.socket) -> str | None:
    """
    Receive up to BUFFER bytes from the socket and return the decoded string.

    Returns None if the connection is closed or on error.
    """
    try:
        data = sock.recv(BUFFER)
        if not data:
            # Connection closed by peer
            return None
        return data.decode('utf-8', errors='replace')
    except Exception as e:
        logging.error(f"[utils] recv_msg failed: {e}")
        return None


def get_all_local_ips() -> set[str]:
    """
    Gather all non-loopback IPv4 addresses of this machine.

    Uses three methods for resilience:
    1. Connect-trick to external address to fetch primary LAN IP.
    2. socket.getaddrinfo() for host-based IPs.
    3. Parsing `ip -4 addr` output on Linux/WSL.

    Returns a set of IP strings, excluding '127.0.0.1' and '0.0.0.0'.
    """
    ips: set[str] = set()

    # Method 1: connect-trick
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Use a public IP; no packets are actually sent
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
    except Exception as e:
        logging.debug(f"[utils] connect-trick failed: {e}")

    # Method 2: getaddrinfo
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception as e:
        logging.debug(f"[utils] getaddrinfo failed: {e}")

    # Method 3: parse `ip addr` on Linux/WSL
    try:
        output = subprocess.check_output(
            ["ip", "-4", "addr"], stderr=subprocess.DEVNULL, text=True
        )
        for match in re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", output):
            ips.add(match)
    except Exception as e:
        logging.debug(f"[utils] ip-addr scan failed: {e}")

    # Exclude loopback and unspecified addresses
    ips.discard("127.0.0.1")
    ips.discard("0.0.0.0")
    return ips
