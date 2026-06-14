"""Interactive terminal client for plain and encrypted chat modes."""

import argparse
import json
import socket
import sys
import threading
import time
from typing import Dict, Optional

import config
from crypto_utils import (
    MessageIntegrityError,
    decrypt_message,
    derive_shared_key,
    encrypt_message,
    generate_private_key,
    public_key_to_base64,
)


class ChatClient:
    def __init__(self, name: str, peer: str, mode: str) -> None:
        self.name = name
        self.peer = peer
        self.mode = mode
        self.sock: Optional[socket.socket] = None
        self.send_lock = threading.Lock()
        self.stop_event = threading.Event()

        self.private_key = generate_private_key() if mode == config.ENCRYPTED_MODE else None
        self.public_key = (
            public_key_to_base64(self.private_key)
            if self.private_key is not None
            else None
        )
        self.session_key: Optional[bytes] = None
        self.last_public_key_sent_at = 0.0

    @property
    def label(self) -> str:
        return f"[CLIENT - {self.name.upper()}]"

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((config.HOST, config.PORT))

        receiver = threading.Thread(target=self._receive_loop, daemon=True)
        receiver.start()

        self._send({
            "type": "register",
            "name": self.name,
            "mode": self.mode,
        })

        if self.mode == config.ENCRYPTED_MODE:
            time.sleep(0.2)
            self.send_public_key()

    def run(self) -> None:
        print(f"{self.label} Connected to {config.HOST}:{config.PORT}")
        print(f"{self.label} Mode: {self.mode.upper()} | Peer: {self.peer}")
        self.print_help()

        try:
            while not self.stop_event.is_set():
                try:
                    user_input = input("> ").strip()
                except EOFError:
                    break

                if not user_input:
                    continue
                if user_input == "/quit":
                    break
                if user_input == "/help":
                    self.print_help()
                    continue
                if user_input == "/key":
                    self.send_public_key(force=True)
                    continue

                self.send_chat_message(user_input)
        except KeyboardInterrupt:
            print(f"\n{self.label} Exiting.")
        finally:
            self.stop_event.set()
            if self.sock is not None:
                try:
                    self.sock.close()
                except OSError:
                    pass

    def print_help(self) -> None:
        print(f"{self.label} Commands: /help, /key, /quit")
        if self.mode == config.ENCRYPTED_MODE:
            print(f"{self.label} Wait for key exchange before sending encrypted messages.")

    def send_chat_message(self, text: str) -> None:
        if self.mode == config.PLAIN_MODE:
            self._send({
                "type": "chat",
                "mode": config.PLAIN_MODE,
                "recipient": self.peer,
                "message": text,
            })
            return

        if self.session_key is None:
            print(
                f"{self.label} No shared key yet. Use /key or wait until "
                f"{self.peer} is connected in encrypted mode."
            )
            return

        encrypted_payload = encrypt_message(self.session_key, text)
        self._send({
            "type": "chat",
            "mode": config.ENCRYPTED_MODE,
            "recipient": self.peer,
            "payload": encrypted_payload,
        })
        preview = encrypted_payload["ciphertext"][:60]
        print(f"[ENCRYPTED MESSAGE] Sent ciphertext preview: {preview}...")

    def send_public_key(self, force: bool = False) -> None:
        if self.mode != config.ENCRYPTED_MODE or self.public_key is None:
            print(f"{self.label} Public key exchange is only used in encrypted mode.")
            return

        now = time.time()
        if not force and now - self.last_public_key_sent_at < 1.0:
            return

        self._send({
            "type": "public_key",
            "recipient": self.peer,
            "public_key": self.public_key,
        })
        self.last_public_key_sent_at = now
        print(f"{self.label} Sent public key to {self.peer}.")

    def _send(self, payload: Dict) -> bool:
        if self.sock is None:
            return False
        try:
            raw = json.dumps(payload, ensure_ascii=False) + "\n"
            with self.send_lock:
                self.sock.sendall(raw.encode(config.ENCODING))
            return True
        except OSError:
            print(f"{self.label} Connection to server was lost.")
            self.stop_event.set()
            return False

    def _receive_loop(self) -> None:
        if self.sock is None:
            return

        try:
            reader = self.sock.makefile("r", encoding=config.ENCODING)
            for raw_line in reader:
                if self.stop_event.is_set():
                    break
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    payload = json.loads(raw_line)
                except json.JSONDecodeError:
                    print(f"{self.label} Received malformed packet from server.")
                    continue
                self._handle_server_payload(payload)
        except OSError:
            pass
        finally:
            if not self.stop_event.is_set():
                print(f"{self.label} Server connection closed.")
            self.stop_event.set()

    def _handle_server_payload(self, payload: Dict) -> None:
        message_type = payload.get("type")
        if message_type == "system":
            self._handle_system(payload)
        elif message_type == "public_key":
            self._handle_public_key(payload)
        elif message_type == "chat":
            self._handle_chat(payload)
        else:
            print(f"{self.label} Unknown packet from server: {payload}")

    def _handle_system(self, payload: Dict) -> None:
        event = payload.get("event", "info")
        message = payload.get("message")

        if event == "peer_joined":
            peer_name = payload.get("name")
            print(f"{self.label} Peer joined: {peer_name} ({payload.get('mode')})")
            if self.mode == config.ENCRYPTED_MODE and peer_name == self.peer:
                self.send_public_key()
            return

        if event == "peer_disconnected":
            print(f"{self.label} Peer disconnected: {payload.get('name')}")
            return

        if event == "registered":
            print(f"{self.label} {message}")
            return

        if event == "blocked":
            print(f"[ALERT] {message}")
            self.stop_event.set()
            return

        if message:
            print(f"{self.label} {message}")
        else:
            print(f"{self.label} System event: {event}")

    def _handle_public_key(self, payload: Dict) -> None:
        sender = payload.get("sender")
        public_key = payload.get("public_key")

        if sender != self.peer:
            print(f"{self.label} Ignoring public key from unexpected sender: {sender}")
            return
        if self.private_key is None or not public_key:
            return

        try:
            self.session_key = derive_shared_key(self.private_key, public_key)
        except Exception as exc:
            print(f"{self.label} Key exchange failed: {exc}")
            return

        print(f"{self.label} Shared AES-GCM session key established with {self.peer}.")
        self.send_public_key()

    def _handle_chat(self, payload: Dict) -> None:
        sender = payload.get("sender", "Unknown")
        mode = payload.get("mode", config.PLAIN_MODE)

        if mode == config.PLAIN_MODE:
            print(f"[{self.name} RECEIVED]")
            print(f"{sender}: {payload.get('message', '')}")
            return

        if self.mode != config.ENCRYPTED_MODE:
            print(f"{self.label} Received encrypted message, but this client is in plain mode.")
            return

        if self.session_key is None:
            print(f"{self.label} Received encrypted message before key exchange completed.")
            return

        try:
            plaintext = decrypt_message(self.session_key, payload.get("payload", {}))
        except MessageIntegrityError:
            warning = "Warning: Message integrity check failed. Message may have been modified."
            print(f"[INTEGRITY WARNING] {warning}")
            self._send({
                "type": "integrity_failure",
                "suspected_sender": sender,
            })
            return

        print(f"[{self.name} RECEIVED]")
        print(f"[DECRYPTED MESSAGE] {sender}: {plaintext}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local encrypted chat demo client.")
    parser.add_argument("--name", required=True, help="Client name, for example Hakan.")
    parser.add_argument("--peer", required=True, help="Recipient client name, for example Melike.")
    parser.add_argument(
        "--mode",
        choices=sorted(config.VALID_MODES),
        default=config.PLAIN_MODE,
        help="Use plain or encrypted mode.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    client = ChatClient(args.name, args.peer, args.mode)
    try:
        client.connect()
    except ConnectionRefusedError:
        print("[CLIENT] Could not connect. Start server.py first.")
        sys.exit(1)
    client.run()


if __name__ == "__main__":
    main()

