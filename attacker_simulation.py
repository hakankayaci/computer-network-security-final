"""Safe localhost-only suspicious behavior simulator for the demo.

This script does not attack any real system. It only connects to the local demo
server and sends metadata patterns that the AI security agent should flag.
"""

import json
import socket
import time
from typing import Dict, Optional

import config


def send_json(sock: socket.socket, payload: Dict) -> None:
    raw = json.dumps(payload, ensure_ascii=False) + "\n"
    sock.sendall(raw.encode(config.ENCODING))


def connect_attacker(name: str = "Attacker") -> Optional[socket.socket]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((config.HOST, config.PORT))
        send_json(sock, {
            "type": "register",
            "name": name,
            "mode": config.PLAIN_MODE,
        })
        return sock
    except ConnectionRefusedError:
        print("[ATTACKER SIMULATION] Server is not running. Start server.py first.")
        return None
    except OSError as exc:
        print(f"[ATTACKER SIMULATION] Could not connect: {exc}")
        return None


def repeated_reconnect_attempts() -> None:
    print("[ATTACKER SIMULATION] Simulating repeated reconnect attempts.")
    for _ in range(6):
        sock = connect_attacker()
        if sock is not None:
            time.sleep(0.12)
            sock.close()
        time.sleep(0.12)


def rapid_message_spam(sock: socket.socket) -> None:
    print("[ATTACKER SIMULATION] Simulating rapid message spam and burst traffic.")
    for index in range(35):
        send_json(sock, {
            "type": "chat",
            "mode": config.PLAIN_MODE,
            "recipient": "Hakan",
            "message": f"Local demo spam message {index}",
        })
        time.sleep(0.04)


def abnormal_message_size(sock: socket.socket) -> None:
    print("[ATTACKER SIMULATION] Simulating abnormal message size.")
    send_json(sock, {
        "type": "chat",
        "mode": config.PLAIN_MODE,
        "recipient": "Hakan",
        "message": "X" * 3500,
    })


def tamper_last_encrypted_message(sock: socket.socket) -> None:
    print("[ATTACKER SIMULATION] Requesting safe local ciphertext tamper demo.")
    send_json(sock, {"type": "tamper_last"})


def main() -> None:
    print("[ATTACKER SIMULATION] Localhost-only safe suspicious behavior demo.")

    # 1) Run the safe integrity (tamper) demo FIRST, while we still look like a
    #    normal client. This guarantees the request is handled before the AI
    #    agent has any reason to block us, so the receiver reliably shows the
    #    integrity warning instead of racing against the temporary block.
    sock = connect_attacker()
    if sock is None:
        return
    try:
        time.sleep(0.3)
        tamper_last_encrypted_message(sock)
        time.sleep(0.8)
    finally:
        sock.close()

    # 2) Now generate the suspicious behavior the AI agent should flag.
    repeated_reconnect_attempts()

    sock = connect_attacker()
    if sock is None:
        return
    try:
        time.sleep(0.3)
        rapid_message_spam(sock)
        abnormal_message_size(sock)
        print("[ATTACKER SIMULATION] Done. Watch the server terminal for AI alerts.")
        time.sleep(1.0)
    finally:
        sock.close()


if __name__ == "__main__":
    main()

