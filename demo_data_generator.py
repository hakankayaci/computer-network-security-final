"""Generate sample metadata logs for the AI anomaly detector."""

import json
import random
import time
from datetime import datetime
from typing import Dict, List

import config
from ai_anomaly_detector import SecurityAgent


def make_event(
    client: str,
    event_type: str,
    epoch: float,
    mode: str = config.ENCRYPTED_MODE,
    peer: str = None,
    message_size: int = 0,
    failed_integrity: int = 0,
    connection_attempt: int = 0,
) -> Dict:
    return {
        "timestamp": datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S"),
        "epoch": epoch,
        "client": client,
        "peer": peer,
        "event_type": event_type,
        "mode": mode,
        "message_size": message_size,
        "failed_integrity": failed_integrity,
        "connection_attempt": connection_attempt,
    }


def generate_events() -> List[Dict]:
    random.seed(42)
    now = time.time()
    events: List[Dict] = []

    for client, peer in (("Hakan", "Melike"), ("Melike", "Hakan")):
        events.append(make_event(client, "connect", now - 55, peer=peer, connection_attempt=1))
        for index in range(5):
            events.append(
                make_event(
                    client,
                    "message",
                    now - 50 + index * 9,
                    peer=peer,
                    message_size=random.randint(50, 180),
                )
            )

    for index in range(8):
        events.append(
            make_event(
                "Attacker",
                "connect",
                now - 58 + index * 0.8,
                mode=config.PLAIN_MODE,
                peer="Hakan",
                connection_attempt=1,
            )
        )

    for index in range(36):
        events.append(
            make_event(
                "Attacker",
                "message",
                now - 40 + index * 0.06,
                mode=config.PLAIN_MODE,
                peer="Hakan",
                message_size=80 if index < 35 else 3500,
            )
        )

    events.append(
        make_event(
            "Attacker",
            "tamper_attempt",
            now - 20,
            mode=config.ENCRYPTED_MODE,
            peer="Melike",
            message_size=120,
        )
    )
    events.append(
        make_event(
            "Melike",
            "integrity_failure",
            now - 19,
            mode=config.ENCRYPTED_MODE,
            peer="Hakan",
            failed_integrity=1,
        )
    )
    return events


def main() -> None:
    events = generate_events()
    with open(config.DEMO_DATA_FILE, "w", encoding=config.ENCODING) as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(f"[DEMO DATA] Wrote {len(events)} metadata events to {config.DEMO_DATA_FILE}")
    print("[DEMO DATA] Features: messages_per_minute, average_message_size, reconnect_count,")
    print("[DEMO DATA] tamper_attempt_count, time_between_messages, burst count, attempts.")

    agent = SecurityAgent(log_file=config.DEMO_DATA_FILE)
    for assessment in agent.analyze_log_file():
        print(assessment.format_for_terminal())
        print("-" * 60)


if __name__ == "__main__":
    main()

