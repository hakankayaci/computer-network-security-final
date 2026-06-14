# Advanced End-to-End Encrypted Chat Application with AI-Based Anomaly Detection

This is a third-year Computer and Network Security course project. It is a local, terminal-based chat system where two demo clients, Hakan and Melike, communicate through a central server. The server can relay messages, show a spy-server view, and run a local AI-style security agent over metadata logs.

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

The simulator performs only safe localhost actions:

- rapid message spam
- repeated reconnect attempts
- abnormal message size
- burst traffic
- a safe tamper request that flips one bit in the last encrypted ciphertext

Watch the server terminal for:

```text
[AI SECURITY AGENT]
Client: Attacker
Risk Score: 0.87
Status: SUSPICIOUS
Reason: very high message frequency, repeated reconnect attempts
Recommended Action: Temporarily block client in demo mode.
```

If Hakan and Melike are connected in encrypted mode and an encrypted message was sent before the tamper demo, Melike should print:

```text
[INTEGRITY WARNING] Warning: Message integrity check failed. Message may have been modified.
```

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
- failed integrity count
- average time between messages
- abnormal burst count
- connection attempt count

If `scikit-learn` is installed, it uses Isolation Forest plus rules. Otherwise, it uses the rule-based fallback.

Run the detector manually:

```powershell
python ai_anomaly_detector.py
```

Generate sample demo logs:

```powershell
python demo_data_generator.py
```

## Limitations

- This is an educational local demo, not production security software.
- Public keys are relayed without certificates or identity verification, so a real production system would need authentication.
- The AI model uses synthetic baseline behavior for demonstration.
- The temporary blocking feature is only for local demo mode.

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

