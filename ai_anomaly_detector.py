"""Local AI-style anomaly detector for server metadata logs.

The detector never reads plaintext message contents. It uses only metadata such
as event type, message size, timing, reconnect count, and integrity failures.
If scikit-learn is installed, an Isolation Forest is used as an additional
signal. A deterministic rule-based scorer is always available as a fallback.
"""

import json
import math
import os
import statistics
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import config

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest

    SKLEARN_AVAILABLE = True
except Exception:
    np = None
    IsolationForest = None
    SKLEARN_AVAILABLE = False


FEATURE_NAMES = (
    "messages_per_minute",
    "average_message_size",
    "reconnect_count",
    "tamper_attempt_count",
    "average_time_between_messages",
    "abnormal_burst_count",
    "connection_attempt_count",
)


@dataclass
class SecurityAssessment:
    client: str
    risk_score: float
    status: str
    reason: str
    recommended_action: str
    model_used: str

    def format_for_terminal(self) -> str:
        return (
            "[AI SECURITY AGENT]\n"
            f"Client: {self.client}\n"
            f"Risk Score: {self.risk_score:.2f}\n"
            f"Status: {self.status}\n"
            f"Reason: {self.reason}\n"
            f"Recommended Action: {self.recommended_action}\n"
            f"Model: {self.model_used}"
        )


class SecurityAgent:
    """Analyze JSONL metadata logs and classify clients as normal or suspicious."""

    def __init__(
        self,
        log_file: str = config.LOG_FILE,
        suspicious_log_file: str = config.SUSPICIOUS_LOG_FILE,
        threshold: float = config.AI_RISK_THRESHOLD,
    ) -> None:
        self.log_file = log_file
        self.suspicious_log_file = suspicious_log_file
        self.threshold = threshold
        self.model = self._build_isolation_forest() if SKLEARN_AVAILABLE else None

    def _build_isolation_forest(self):
        """Train a small normal-behavior baseline for demo use."""
        if not SKLEARN_AVAILABLE:
            return None

        baseline = []
        for i in range(120):
            baseline.append(
                [
                    1 + (i % 8),          # messages_per_minute: quiet to lively chat
                    45 + (i % 170),       # average_message_size: incl. encrypted payloads
                    0 if i % 7 else 1,    # reconnect_count: usually none
                    0,                    # tamper_attempt_count
                    3 + (i % 22),         # average_time_between_messages: 3-24s, plus idle
                    0,                    # abnormal_burst_count: normal users do not burst
                    1 if i % 5 else 2,    # connection_attempt_count
                ]
            )
        # A quiet client may have no messages yet, so the interval defaults to the
        # full window. Include that case so an idle user is not seen as anomalous.
        for gap in (45.0, 60.0):
            baseline.append([0, 0, 0, 0, gap, 0, 1])

        model = IsolationForest(
            n_estimators=100,
            contamination=0.02,
            random_state=42,
        )
        model.fit(np.array(baseline, dtype=float))
        return model

    def load_events(self) -> List[Dict]:
        if not os.path.exists(self.log_file):
            return []

        events = []
        with open(self.log_file, "r", encoding=config.ENCODING) as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return events

    def extract_features(self, events: Iterable[Dict]) -> Dict[str, Dict[str, float]]:
        grouped: Dict[str, List[Dict]] = {}
        for event in events:
            client = event.get("client") or "Unknown"
            grouped.setdefault(client, []).append(event)

        features_by_client = {}
        now = time.time()

        for client, client_events in grouped.items():
            recent_events = [
                event
                for event in client_events
                if now - float(event.get("epoch", now)) <= 60
            ]
            # Only assess clients with activity in the recent window. Without
            # this, stale metadata from a previous session (e.g. an attacker
            # that left long ago) would be re-analyzed and trigger phantom
            # alerts every time the server reads the log.
            if not recent_events:
                continue

            message_events = [
                event for event in recent_events if event.get("event_type") == "message"
            ]
            message_times = sorted(float(event.get("epoch", now)) for event in message_events)
            intervals = [
                message_times[index] - message_times[index - 1]
                for index in range(1, len(message_times))
            ]

            average_interval = statistics.mean(intervals) if intervals else 60.0
            abnormal_burst_count = sum(
                1 for interval in intervals if interval <= config.BURST_INTERVAL_SECONDS
            )

            message_sizes = [
                float(event.get("message_size", 0) or 0) for event in message_events
            ]
            average_size = statistics.mean(message_sizes) if message_sizes else 0.0

            connection_attempts = sum(
                1
                for event in recent_events
                if event.get("event_type") in {"connect", "blocked_connection_attempt"}
            )
            reconnect_count = max(0, connection_attempts - 1)
            # Count tampering ATTEMPTS, which the server logs against the client
            # that made them. We deliberately do NOT count integrity-failure
            # reports here: the receiver of a tampered message is a victim and
            # must never be penalised (and possibly blocked) for reporting it.
            tamper_attempt_count = sum(
                1
                for event in recent_events
                if event.get("event_type") == "tamper_attempt"
            )

            # Count the messages seen in the recent (<=60s) window directly.
            # Extrapolating from a tiny time span used to inflate the rate for a
            # few normal messages and caused false anomaly alerts.
            messages_per_minute = float(len(message_events))

            features_by_client[client] = {
                "messages_per_minute": messages_per_minute,
                "average_message_size": average_size,
                "reconnect_count": float(reconnect_count),
                "tamper_attempt_count": float(tamper_attempt_count),
                "average_time_between_messages": average_interval,
                "abnormal_burst_count": float(abnormal_burst_count),
                "connection_attempt_count": float(connection_attempts),
            }

        return features_by_client

    def _rule_score(self, features: Dict[str, float]) -> Tuple[float, List[str]]:
        score = 0.0
        reasons = []

        if features["messages_per_minute"] >= 25:
            score += 0.35
            reasons.append("very high message frequency")
        elif features["messages_per_minute"] >= 12:
            score += 0.18
            reasons.append("higher than usual message frequency")

        if features["average_message_size"] >= config.LARGE_MESSAGE_SIZE_BYTES:
            score += 0.22
            reasons.append("abnormally large messages")

        if features["reconnect_count"] >= 4:
            score += 0.22
            reasons.append("repeated reconnect attempts")
        elif features["reconnect_count"] >= 2:
            score += 0.12
            reasons.append("multiple reconnect attempts")

        if features["tamper_attempt_count"] >= 1:
            score += 0.28
            reasons.append("message tampering attempt")

        if features["abnormal_burst_count"] >= 3:
            score += 0.18
            reasons.append("burst traffic pattern")

        if features["connection_attempt_count"] >= 6:
            score += 0.15
            reasons.append("many connection attempts")

        return min(1.0, score), reasons

    def _model_risk(self, features: Dict[str, float]) -> float:
        if self.model is None:
            return 0.0

        vector = np.array([[features[name] for name in FEATURE_NAMES]], dtype=float)
        prediction = self.model.predict(vector)[0]
        if prediction == -1:
            return 0.80

        raw_score = float(self.model.decision_function(vector)[0])
        return max(0.0, min(0.55, 0.45 - raw_score))

    def _has_enough_activity(self, features: Dict[str, float]) -> bool:
        """Whether a client produced enough metadata to trust the ML verdict.

        The Isolation Forest is only a secondary signal. On a quiet, well behaved
        client (a few normal messages, no reconnects, no integrity failures) it
        can produce false positives, so it is not allowed to raise an alert on
        its own until one of these clearly-abnormal signals is present.
        """
        return (
            features["messages_per_minute"] >= 15
            or features["reconnect_count"] >= 2
            or features["tamper_attempt_count"] >= 1
            or features["abnormal_burst_count"] >= 3
            or features["connection_attempt_count"] >= 4
        )

    def assess_features(self, client: str, features: Dict[str, float]) -> SecurityAssessment:
        rule_score, reasons = self._rule_score(features)
        model_score = self._model_risk(features)

        # Do not let the Isolation Forest alone block a normal, low-volume client.
        if not self._has_enough_activity(features):
            model_score = min(model_score, 0.30)

        risk_score = max(rule_score, model_score)

        if model_score >= 0.80 and "Isolation Forest detected anomalous metadata" not in reasons:
            reasons.append("Isolation Forest detected anomalous metadata")

        if risk_score >= self.threshold:
            status = "SUSPICIOUS"
            recommended_action = "Temporarily block client in demo mode."
            reason = ", ".join(reasons) if reasons else "metadata pattern is unusual"
        else:
            status = "NORMAL"
            recommended_action = "Continue monitoring normal behavior."
            reason = "Behavior is within expected demo limits."

        model_used = "IsolationForest + rules" if self.model is not None else "rule-based fallback"
        return SecurityAssessment(
            client=client,
            risk_score=risk_score,
            status=status,
            reason=reason,
            recommended_action=recommended_action,
            model_used=model_used,
        )

    def analyze_log_file(self, client_name: Optional[str] = None) -> List[SecurityAssessment]:
        events = self.load_events()
        features_by_client = self.extract_features(events)

        assessments = []
        for client, features in features_by_client.items():
            if client_name and client != client_name:
                continue
            assessments.append(self.assess_features(client, features))

        assessments.sort(key=lambda item: item.risk_score, reverse=True)
        return assessments

    def log_suspicious_event(self, assessment: SecurityAssessment) -> None:
        line = (
            f"{time.strftime('%Y-%m-%d %H:%M:%S')} | "
            f"{assessment.client} | risk={assessment.risk_score:.2f} | "
            f"{assessment.reason} | {assessment.recommended_action}\n"
        )
        with open(self.suspicious_log_file, "a", encoding=config.ENCODING) as handle:
            handle.write(line)


def print_report(log_file: str = config.LOG_FILE) -> None:
    agent = SecurityAgent(log_file=log_file)
    assessments = agent.analyze_log_file()
    if not assessments:
        print("[AI SECURITY AGENT] No metadata logs were found.")
        return

    for assessment in assessments:
        print(assessment.format_for_terminal())
        print("-" * 60)


if __name__ == "__main__":
    print_report()

