# ephemeral.py

import time
import threading

def delete_after_delay(peer_ip, delay=5):
    def delayed():
        time.sleep(delay)
        print(f"{peer_ip}: [message deleted]")
    threading.Thread(target=delayed, daemon=True).start()
