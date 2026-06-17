"""Threaded localhost chat server with spy view and AI metadata monitoring."""

import copy
import functools
import json
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional, Tuple

import config
from ai_anomaly_detector import SecurityAgent
from crypto_utils import ciphertext_hex_preview, tamper_encrypted_payload

# Always flush server output immediately. In a normal terminal Python already
# line-buffers, but if the output is piped or redirected (e.g. to a log file)
# it would otherwise be block-buffered and the live [SPY SERVER VIEW] / AI
# alerts would not appear until the buffer filled. This keeps the demo readable
# everywhere.
print = functools.partial(print, flush=True)


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def json_dumps(payload: Dict) -> str:
    return json.dumps(payload, ensure_ascii=False)


@dataclass
class ClientConnection:
    name: str
    mode: str
    sock: socket.socket
    address: Tuple[str, int]
    send_lock: threading.Lock = field(default_factory=threading.Lock)

    def send(self, payload: Dict) -> bool:
        try:
            raw = json_dumps(payload) + "\n"
            with self.send_lock:
                self.sock.sendall(raw.encode(config.ENCODING))
            return True
        except OSError:
            return False

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class ChatServer:
    def __init__(self) -> None:
        self.clients: Dict[str, ClientConnection] = {}
        self.clients_lock = threading.RLock()
        self.log_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.blocked_until: Dict[str, float] = {}
        self.last_encrypted_message: Optional[Dict] = None
        self.security_agent = SecurityAgent()
        self.last_ai_alert_at: Dict[str, float] = {}

    def start(self) -> None:
        self._prepare_log_files()
        monitor_thread = threading.Thread(target=self._ai_monitor_loop, daemon=True)
        monitor_thread.start()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            # On Unix SO_REUSEADDR lets us rebind quickly after a restart. On
            # Windows it has different semantics: it would let a SECOND server
            # silently share the same port, so clients could connect to a stale
            # leftover server while this one looks frozen. So we do not set it on
            # Windows, and we let bind() fail loudly if the port is already taken.
            if os.name != "nt":
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server_socket.bind((config.HOST, config.PORT))
            except OSError:
                print(
                    f"[SERVER] Could not bind to {config.HOST}:{config.PORT}. "
                    "Another server is probably already running on this port."
                )
                print(
                    "[SERVER] Close the other server window, or stop stray python "
                    "processes (Task Manager, or: taskkill /F /IM python.exe), "
                    "then start the server again."
                )
                return
            server_socket.listen()
            print(f"[SERVER] Listening on {config.HOST}:{config.PORT}")
            print("[SERVER] Press Ctrl+C to stop the server.")

            try:
                while not self.stop_event.is_set():
                    client_socket, address = server_socket.accept()
                    thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address),
                        daemon=True,
                    )
                    thread.start()
            except KeyboardInterrupt:
                print("\n[SERVER] Shutting down.")
            finally:
                self.stop_event.set()
                self._close_all_clients()

    def _prepare_log_files(self) -> None:
        # Start every server run with empty logs. This guarantees a clean demo:
        # metadata from a previous session can never leak into the AI agent's
        # analysis and cause false alerts before any client has even connected.
        for path in (config.LOG_FILE, config.SUSPICIOUS_LOG_FILE):
            with open(path, "w", encoding=config.ENCODING):
                pass

    def _close_all_clients(self) -> None:
        with self.clients_lock:
            clients = list(self.clients.values())
            self.clients.clear()
        for client in clients:
            client.close()

    def _handle_client(self, client_socket: socket.socket, address: Tuple[str, int]) -> None:
        client_name: Optional[str] = None
        registered_client: Optional[ClientConnection] = None
        print(f"[SERVER] Connection attempt from {address[0]}:{address[1]}")

        try:
            reader = client_socket.makefile("r", encoding=config.ENCODING)
            for raw_line in reader:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue

                if len(raw_line.encode(config.ENCODING)) > config.MAX_MESSAGE_BYTES * 2:
                    self._log_event(
                        client=client_name or f"Unknown-{address[1]}",
                        event_type="oversized_packet",
                        message_size=len(raw_line),
                    )
                    self._send_raw(client_socket, {
                        "type": "system",
                        "event": "error",
                        "message": "Packet is too large for this demo server.",
                    })
                    continue

                try:
                    payload = json.loads(raw_line)
                except json.JSONDecodeError:
                    self._log_event(
                        client=client_name or f"Unknown-{address[1]}",
                        event_type="malformed_json",
                        message_size=len(raw_line),
                    )
                    self._send_raw(client_socket, {
                        "type": "system",
                        "event": "error",
                        "message": "Malformed JSON packet ignored.",
                    })
                    continue

                message_type = payload.get("type")
                if message_type == "register":
                    registered_client = self._register_client(client_socket, address, payload)
                    if registered_client is None:
                        return
                    client_name = registered_client.name
                    continue

                if registered_client is None or client_name is None:
                    self._log_event(
                        client=f"Unknown-{address[1]}",
                        event_type="unregistered_message",
                        message_size=len(raw_line),
                    )
                    self._send_raw(client_socket, {
                        "type": "system",
                        "event": "error",
                        "message": "Please register before sending messages.",
                    })
                    continue

                if message_type == "chat":
                    self._handle_chat(registered_client, payload)
                elif message_type == "public_key":
                    self._handle_public_key(registered_client, payload)
                elif message_type == "integrity_failure":
                    self._handle_integrity_failure(registered_client, payload)
                elif message_type == "tamper_last":
                    self._handle_tamper_last(registered_client)
                else:
                    self._log_event(
                        client=client_name,
                        event_type="unknown_message_type",
                        message_size=len(raw_line),
                    )
                    registered_client.send({
                        "type": "system",
                        "event": "error",
                        "message": f"Unknown message type: {message_type}",
                    })
        except OSError:
            pass
        finally:
            if client_name:
                self._disconnect_client(client_name, registered_client)
            try:
                client_socket.close()
            except OSError:
                pass

    def _send_raw(self, sock: socket.socket, payload: Dict) -> None:
        try:
            sock.sendall((json_dumps(payload) + "\n").encode(config.ENCODING))
        except OSError:
            pass

    def _register_client(
        self,
        sock: socket.socket,
        address: Tuple[str, int],
        payload: Dict,
    ) -> Optional[ClientConnection]:
        requested_name = str(payload.get("name", "")).strip()
        mode = str(payload.get("mode", config.PLAIN_MODE)).lower()

        if not requested_name:
            self._send_raw(sock, {
                "type": "system",
                "event": "error",
                "message": "Client name is required.",
            })
            return None

        name = requested_name[: config.MAX_CLIENT_NAME_LENGTH]
        if mode not in config.VALID_MODES:
            mode = config.PLAIN_MODE

        now = time.time()
        blocked_until = self.blocked_until.get(name, 0)
        if blocked_until > now:
            seconds_left = int(blocked_until - now)
            self._log_event(
                client=name,
                event_type="blocked_connection_attempt",
                mode=mode,
                connection_attempt=1,
            )
            self._send_raw(sock, {
                "type": "system",
                "event": "blocked",
                "message": f"{name} is temporarily blocked for {seconds_left} seconds in demo mode.",
            })
            print(f"[ALERT] Blocked connection attempt from {name}.")
            return None
        self.blocked_until.pop(name, None)

        client = ClientConnection(name=name, mode=mode, sock=sock, address=address)
        old_client: Optional[ClientConnection] = None

        with self.clients_lock:
            old_client = self.clients.get(name)
            self.clients[name] = client
            existing_clients = [
                {"name": other.name, "mode": other.mode}
                for other in self.clients.values()
                if other.name != name
            ]

        if old_client is not None:
            old_client.send({
                "type": "system",
                "event": "replaced",
                "message": "Another connection registered with your name.",
            })
            old_client.close()

        self._log_event(
            client=name,
            event_type="connect",
            mode=mode,
            connection_attempt=1,
        )
        print(f"[SERVER] {name} registered in {mode.upper()} mode from {address[0]}:{address[1]}")

        client.send({
            "type": "system",
            "event": "registered",
            "name": name,
            "mode": mode,
            "message": f"Registered as {name} in {mode} mode.",
        })

        for peer in existing_clients:
            client.send({
                "type": "system",
                "event": "peer_joined",
                "name": peer["name"],
                "mode": peer["mode"],
            })

        self._broadcast_system(
            exclude=name,
            event="peer_joined",
            name=name,
            mode=mode,
            message=f"{name} joined in {mode} mode.",
        )
        return client

    def _disconnect_client(
        self,
        client_name: str,
        client: Optional[ClientConnection],
    ) -> None:
        with self.clients_lock:
            current = self.clients.get(client_name)
            if current is client:
                self.clients.pop(client_name, None)
            else:
                return

        self._log_event(client=client_name, event_type="disconnect")
        print(f"[SERVER] {client_name} disconnected.")
        self._broadcast_system(
            exclude=client_name,
            event="peer_disconnected",
            name=client_name,
            message=f"{client_name} disconnected.",
        )

    def _handle_chat(self, sender: ClientConnection, payload: Dict) -> None:
        recipient_name = str(payload.get("recipient", "")).strip()
        mode = str(payload.get("mode", sender.mode)).lower()
        if mode not in config.VALID_MODES:
            mode = sender.mode

        if not recipient_name:
            sender.send({
                "type": "system",
                "event": "error",
                "message": "Recipient is required.",
            })
            return

        if mode == config.PLAIN_MODE:
            message = str(payload.get("message", ""))
            message_size = len(message.encode(config.ENCODING))
            print("[SPY SERVER VIEW - PLAIN MODE]")
            print(f"From {sender.name} to {recipient_name}: {message}")
            outbound = {
                "type": "chat",
                "mode": config.PLAIN_MODE,
                "sender": sender.name,
                "recipient": recipient_name,
                "message": message,
            }
        else:
            encrypted_payload = payload.get("payload") or {}
            message_size = len(json_dumps(encrypted_payload).encode(config.ENCODING))
            print("[SPY SERVER VIEW - ENCRYPTED MODE]")
            print(
                f"From {sender.name} to {recipient_name}: "
                f"{ciphertext_hex_preview(encrypted_payload)}"
            )
            outbound = {
                "type": "chat",
                "mode": config.ENCRYPTED_MODE,
                "sender": sender.name,
                "recipient": recipient_name,
                "payload": encrypted_payload,
            }
            self.last_encrypted_message = copy.deepcopy(outbound)

        self._log_event(
            client=sender.name,
            peer=recipient_name,
            event_type="message",
            mode=mode,
            message_size=message_size,
        )
        self._deliver_to_peer(sender, recipient_name, outbound)

    def _handle_public_key(self, sender: ClientConnection, payload: Dict) -> None:
        recipient_name = str(payload.get("recipient", "")).strip()
        public_key = payload.get("public_key")
        if not recipient_name or not public_key:
            sender.send({
                "type": "system",
                "event": "error",
                "message": "Public key message requires recipient and public_key.",
            })
            return

        print(f"[SERVER] Forwarding public key from {sender.name} to {recipient_name}.")
        self._log_event(
            client=sender.name,
            peer=recipient_name,
            event_type="key_exchange",
            mode=config.ENCRYPTED_MODE,
            message_size=len(str(public_key)),
        )
        self._deliver_to_peer(sender, recipient_name, {
            "type": "public_key",
            "sender": sender.name,
            "recipient": recipient_name,
            "public_key": public_key,
        })

    def _handle_integrity_failure(self, reporter: ClientConnection, payload: Dict) -> None:
        suspected_sender = str(payload.get("suspected_sender", "Unknown"))
        print("[INTEGRITY WARNING]")
        print(
            f"{reporter.name} reported a failed integrity check. "
            f"Suspected sender: {suspected_sender}"
        )
        self._log_event(
            client=reporter.name,
            peer=suspected_sender,
            event_type="integrity_failure",
            mode=config.ENCRYPTED_MODE,
            failed_integrity=1,
        )

    def _handle_tamper_last(self, requester: ClientConnection) -> None:
        if self.last_encrypted_message is None:
            requester.send({
                "type": "system",
                "event": "tamper_failed",
                "message": "No encrypted message is available to tamper with yet.",
            })
            return

        try:
            tampered_message = copy.deepcopy(self.last_encrypted_message)
            tampered_message["payload"] = tamper_encrypted_payload(tampered_message["payload"])
            tampered_message["tampered_for_demo"] = True
        except Exception as exc:
            requester.send({
                "type": "system",
                "event": "tamper_failed",
                "message": f"Could not tamper with the last encrypted message: {exc}",
            })
            return

        recipient_name = tampered_message.get("recipient")
        print("[ALERT] Local demo tampering attempt requested.")
        print(
            f"[ALERT] Flipping one ciphertext bit before relaying a copy to {recipient_name}."
        )
        self._log_event(
            client=requester.name,
            peer=recipient_name,
            event_type="tamper_attempt",
            mode=config.ENCRYPTED_MODE,
            message_size=len(json_dumps(tampered_message.get("payload", {}))),
        )
        self._deliver_to_peer(requester, str(recipient_name), tampered_message)

    def _deliver_to_peer(self, sender: ClientConnection, recipient_name: str, payload: Dict) -> None:
        with self.clients_lock:
            recipient = self.clients.get(recipient_name)

        if recipient is None:
            sender.send({
                "type": "system",
                "event": "delivery_failed",
                "recipient": recipient_name,
                "message": f"{recipient_name} is not connected.",
            })
            self._log_event(
                client=sender.name,
                peer=recipient_name,
                event_type="delivery_failed",
                mode=payload.get("mode", "unknown"),
            )
            return

        if not recipient.send(payload):
            sender.send({
                "type": "system",
                "event": "delivery_failed",
                "recipient": recipient_name,
                "message": f"Could not deliver message to {recipient_name}.",
            })

    def _broadcast_system(self, exclude: Optional[str], **fields) -> None:
        payload = {"type": "system", **fields}
        with self.clients_lock:
            recipients = [
                client for name, client in self.clients.items() if name != exclude
            ]
        for client in recipients:
            client.send(payload)

    def _log_event(
        self,
        client: str,
        event_type: str,
        mode: str = "unknown",
        peer: Optional[str] = None,
        message_size: int = 0,
        failed_integrity: int = 0,
        connection_attempt: int = 0,
    ) -> None:
        entry = {
            "timestamp": timestamp(),
            "epoch": time.time(),
            "client": client,
            "peer": peer,
            "event_type": event_type,
            "mode": mode,
            "message_size": int(message_size or 0),
            "failed_integrity": int(failed_integrity or 0),
            "connection_attempt": int(connection_attempt or 0),
        }
        with self.log_lock:
            with open(config.LOG_FILE, "a", encoding=config.ENCODING) as handle:
                handle.write(json_dumps(entry) + "\n")

    def _ai_monitor_loop(self) -> None:
        while not self.stop_event.is_set():
            time.sleep(config.AI_MONITOR_INTERVAL_SECONDS)
            try:
                assessments = self.security_agent.analyze_log_file()
            except Exception as exc:
                print(f"[AI SECURITY AGENT] Analysis error: {exc}")
                continue

            now = time.time()
            for assessment in assessments:
                if assessment.status != "SUSPICIOUS":
                    continue
                last_alert = self.last_ai_alert_at.get(assessment.client, 0)
                if now - last_alert < config.AI_ALERT_COOLDOWN_SECONDS:
                    continue

                self.last_ai_alert_at[assessment.client] = now
                print(assessment.format_for_terminal())
                self.security_agent.log_suspicious_event(assessment)

                if config.AI_DEMO_BLOCKING_ENABLED:
                    self._block_client_temporarily(assessment.client)

    def _block_client_temporarily(self, client_name: str) -> None:
        self.blocked_until[client_name] = time.time() + config.AI_BLOCK_DURATION_SECONDS
        with self.clients_lock:
            client = self.clients.get(client_name)

        if client is not None:
            client.send({
                "type": "system",
                "event": "blocked",
                "message": (
                    "AI security agent marked this client as suspicious. "
                    "This demo connection will close temporarily."
                ),
            })
            client.close()
        print(
            f"[ALERT] {client_name} is temporarily blocked for "
            f"{config.AI_BLOCK_DURATION_SECONDS} seconds."
        )


if __name__ == "__main__":
    ChatServer().start()

