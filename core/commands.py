# core/commands.py

import os
from datetime import datetime
from crypto.crypto_utils import encrypt_message

def handle_command(cmd, my_name, connections, peer_names, peer_public_keys):
    parts = cmd.strip().split(maxsplit=1)
    base = parts[0] # the main command

    # prints a list of supported commands with a short description
    if base == "/help":
        print("Available commands:")
        print("  /help         - Show this help message")
        print("  /peers        - List connected peers")
        print("  /quit         - Disconnect and exit")
        print("  /clear        - Clear the terminal screen")
        print("  /me <action>  - Send a third-person message (e.g., '* Alice is typing...')")

    # prints the list of currently connected peers and their nicknames
    elif base == "/peers":
        if not peer_names:
            print("[*] No peers connected.")
        else:
            print("[*] Connected peers:")
            for ip, name in peer_names.items():
                print(f"  {name} ({ip})")

    # gracefully closes all open connections and exits the program
    elif base == "/quit":
        print("[*] Disconnecting...")
        for conn in connections:
            try:
                conn.close()
            except:
                pass
        exit(0)

    # clears the terminal screen using a cross-platform call
    elif base == "/clear":
        os.system('cls' if os.name == 'nt' else 'clear')

    # sends a message in third person format
    elif base == "/me":
        if len(parts) == 2:
            action = f"* {my_name} {parts[1]}"
            timestamp = datetime.now().strftime('%H:%M')
            print(f"[{timestamp}] {action}")
            for conn in connections:
                ip = conn.getpeername()[0]
                if ip in peer_public_keys:
                    try:
                        encrypted = encrypt_message(peer_public_keys[ip], action)
                        conn.sendall(encrypted)
                    except Exception as e:
                        print(f"Encryption error to {ip}: {e}")
        else:
            print("[!] Usage: /me <action>")

    # handle unrecognized commands
    else:
        print(f"[!] Unknown command: {cmd}. Try /help.")