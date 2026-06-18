# Advanced End-to-End Encrypted Chat Application with AI-Based Anomaly Detection

(YouTube Demo: https://youtu.be/we56pO28Ffw)
This is a Computer and Network Security course project. It is a local, terminal-based chat system where two demo clients, Hakan and Melike, communicate through a central server. The server can relay messages, show a spy-server view, and run a local AI-style security agent over metadata logs.

The project is educational and safe. It runs on `localhost` only and does not perform real attacks.

## Architecture Overview

- `server.py` accepts TCP socket clients, relays JSON messages, prints the spy server view, logs metadata, and runs the AI security agent.
- `client.py` runs an interactive chat client in plain or encrypted mode.
- `crypto_utils.py` handles X25519 key exchange and AES-GCM authenticated encryption.
- `ai_anomaly_detector.py` analyzes metadata logs using Isolation Forest when available, with a rule-based fallback.
- `attacker_simulation.py` creates safe local suspicious behavior for the demo.
- `demo_data_generator.py` creates sample metadata logs and runs the detector.

## File Structure

```text
project/
|-- server.py
|-- client.py
|-- crypto_utils.py
|-- ai_anomaly_detector.py
|-- attacker_simulation.py
|-- demo_data_generator.py
|-- config.py
|-- requirements.txt
|-- README.md
`-- demo_script.md
```

## Requirements

- Python 3.8 or newer
- Windows, macOS, or Linux
- Localhost networking enabled

Install dependencies:

```powershell
cd C:\Users\Hakan\Desktop\ComputerNetworkAndSecurity\project
python -m pip install -r requirements.txt
```

`cryptography` is used for X25519 and AES-GCM. `scikit-learn` is used for Isolation Forest. If `scikit-learn` is unavailable, the anomaly detector still works with the rule-based fallback.

## How to Run

Open three terminals in the `project` folder.

Terminal 1, start the server:

```powershell
python server.py
```

Terminal 2, start Hakan:

```powershell
python client.py --name Hakan --peer Melike --mode plain
```

Terminal 3, start Melike:

```powershell
python client.py --name Melike --peer Hakan --mode plain
```

Type a message in Hakan's terminal. In plain mode, the server prints:

```text
[SPY SERVER VIEW - PLAIN MODE]
From Hakan to Melike: Merhaba Melike, this server can read the message.
```

## Encrypted Mode

Stop the plain clients with `/quit`, then start encrypted clients:

```powershell
python client.py --name Hakan --peer Melike --mode encrypted
python client.py --name Melike --peer Hakan --mode encrypted
```

The clients exchange public keys through the server and derive the same AES session key locally. Send a message after both clients show:

```text
Shared AES-GCM session key established
```

The server sees only ciphertext:

```text
[SPY SERVER VIEW - ENCRYPTED MODE]
From Hakan to Melike: 8f3a9c2b7e01aa91...
```

Melike sees the decrypted message locally:

```text
[Melike RECEIVED]
[DECRYPTED MESSAGE] Hakan: Merhaba Melike, this server cannot read the message.
```

## Attacker Simulation

With the server running, use another terminal:

```powershell
python attacker_simulation.py
```

The simulator performs only safe localhost actions, in this order:

1. a safe tamper request that flips one bit in the last encrypted ciphertext (integrity demo),
2. repeated reconnect attempts,
3. rapid message spam and burst traffic,
4. an abnormal message size.

The tamper request runs first so the receiver reliably shows the integrity warning before the AI agent temporarily blocks the attacker.

If Hakan and Melike are connected in encrypted mode and Hakan sent an encrypted message before the tamper demo, Melike prints almost immediately:

```text
[INTEGRITY WARNING] Warning: Message integrity check failed. Message may have been modified.
```

Then, a few seconds later, watch the server terminal for:

```text
[AI SECURITY AGENT]
Client: Attacker
Risk Score: 0.80
Status: SUSPICIOUS
Reason: message tampering attempt, repeated reconnect attempts, many connection attempts, Isolation Forest detected anomalous metadata
Recommended Action: Temporarily block client in demo mode.
```

The integrity failure is attributed to the attacker that tampered the message, never to Melike, who only reports it. Hakan and Melike are never flagged for normal chatting.

## Diffie-Hellman / X25519 Key Exchange

The project uses X25519, a modern elliptic-curve Diffie-Hellman key exchange. Each client creates a private key and a public key. Public keys are sent through the server. The shared secret is calculated locally by each client and is never sent over the network.

The server can relay public keys, but it does not receive the final AES session key.

## AES-GCM Encryption and Integrity

AES-GCM encrypts messages and also creates an authentication tag. If any ciphertext byte is modified, decryption fails. This is how the project demonstrates message integrity.

In encrypted mode:

- the sender encrypts locally,
- the server relays only ciphertext,
- the receiver decrypts locally,
- tampered ciphertext causes an integrity warning.

## Spy Server Simulation

The server prints a clear spy view:

- plain mode: readable message text is visible,
- encrypted mode: only ciphertext is visible.

This demonstrates why end-to-end encryption protects message confidentiality even when a central server relays traffic.

## AI-Based Anomaly Detection

The AI security agent reads `server_logs.jsonl`. It does not read plaintext message contents. It extracts metadata features:

- messages per minute
- average message size
- reconnect count
- tampering attempt count (attributed to the client that tampered, never to the victim that reports it)
- average time between messages
- abnormal burst count
- connection attempt count

The deterministic rules are the primary detector because they give clear, explainable reasons (for example "very high message frequency"). When `scikit-learn` is installed, an Isolation Forest acts as an additional signal. To avoid false positives, the model is treated as a secondary signal: it does not raise an alert on its own for a low-activity, well-behaved client, so normal users such as Hakan and Melike are not flagged during ordinary chatting. If `scikit-learn` is unavailable, the rule-based fallback is used alone.

Run the detector manually:

```powershell
python ai_anomaly_detector.py
```

Generate sample demo logs:

```powershell
python demo_data_generator.py
```

## Troubleshooting

**The server prints `[SERVER] Listening` but shows nothing else (no spy view), yet messages still arrive.**
A previous server is most likely still running in the background and is handling the
connections instead of the one you can see. The server now refuses to start a second
time and prints `Could not bind to 127.0.0.1:5050`. To fix it, close the old server
window, or stop stray Python processes:

```powershell
taskkill /F /IM python.exe
```

Then start the server again. Start only one server at a time.

**`Could not bind to 127.0.0.1:5050`.**
Another program (usually an old server) is using the port. Stop it as above, or change
`PORT` in `config.py`.

## Limitations

This is an educational demo, not production security software. The design makes
several deliberate trade-offs, and understanding them is part of the project. The
most important limitations, grouped by security property, are:

**Authentication and key exchange**
- Public keys are relayed through the server **without certificates or identity
  verification**. A malicious or compromised server could swap the keys and mount
  a **man-in-the-middle (MITM)** attack. A real system would need authenticated
  key exchange (a PKI/certificates, or trust-on-first-use key fingerprints).
- There is **no user authentication**: a client can register under any name, so
  **impersonation** is possible. There are no accounts, passwords, or login.

**Confidentiality and transport**
- Only the message body is end-to-end encrypted. The transport is plain TCP, so
  **metadata** (who talks to whom, timing, message sizes) is visible, and plain
  mode sends everything in clear text by design (to demonstrate the problem).
- Session keys are ephemeral and per-session. This gives forward secrecy, but it
  also means there is no long-term identity to recognise a peer across sessions.

**Integrity and replay**
- AES-GCM detects tampering of a single message, but the demo does **not protect
  against replay attacks**: a captured ciphertext could be re-sent and would
  decrypt again, because there are no message counters, sequence numbers, or
  timestamps.
- Message ordering and delivery are trusted to the server. A malicious server
  could still **drop, delay, or reorder** messages (it just cannot read them).

**AI anomaly detection**
- The Isolation Forest is trained on a **small synthetic baseline**, not on real
  traffic, and the thresholds are tuned for the demo. On real traffic it could
  produce **false positives** or miss novel attacks.
- The agent analyses the server's own metadata logs, so it **trusts the server**.
- The temporary block is **demo-only and name-based**, so it is easily bypassed
  (an attacker can change names or source addresses).

**Availability**
- There is **no real denial-of-service protection**. The block is cosmetic for
  the demo, and a determined flood could still overwhelm the server.

**General**
- The code has **not been security-audited** and uses fixed demo parameters. It
  is intended only for local, safe, educational use.

## Future Improvements

- Add authenticated user accounts.
- Add a GUI or web dashboard.
- Store public-key fingerprints for trust-on-first-use.
- Add more network metadata features.
- Add unit tests and integration tests.

## Educational Security Disclaimer

This project is for a Computer and Network Security course. All simulations are local and safe. Do not use this code to attack, scan, or disrupt any real system.

## Short Turkish Presentation Explanation

Bu projede Hakan ve Melike isimli iki istemci, merkezi bir sunucu uzerinden mesajlasir. Duz metin modunda sunucu mesaji okuyabilir. Sifreli modda ise istemciler X25519 ile ortak anahtar uretir ve mesajlar AES-GCM ile uctan uca sifrelenir. Sunucu sadece sifreli veriyi gorur. AES-GCM sayesinde mesaj degistirilirse alici tarafinda butunluk uyarisi olusur. Ayrica AI guvenlik ajani mesaj icerigini okumadan, sadece davranissal metadatalari analiz ederek supheli istemcileri tespit eder.

