# Demo Script

Use this script for the live presentation or YouTube demo video.

## Step 1: Start the Server

Open a terminal:

```powershell
cd C:\Users\Hakan\Desktop\ComputerNetworkAndSecurity\project
python server.py
```

Say:

> This is the central relay server. It forwards messages and shows what a server can see.

Expected output:

```text
[SERVER] Listening on 127.0.0.1:5050
```

## Step 2: Run Plain Mode Clients

Open two more terminals.

Hakan:

```powershell
python client.py --name Hakan --peer Melike --mode plain
```

Melike:

```powershell
python client.py --name Melike --peer Hakan --mode plain
```

## Step 3: Show Plaintext Visibility

In Hakan's terminal, type:

```text
Merhaba Melike, this server can read the message.
```

Point to the server terminal:

```text
[SPY SERVER VIEW - PLAIN MODE]
From Hakan to Melike: Merhaba Melike, this server can read the message.
```

Say:

> In normal client-server communication, the relay server can read the plaintext.

## Step 4: Switch to Encrypted Mode

In both clients, type:

```text
/quit
```

Restart them:

```powershell
python client.py --name Hakan --peer Melike --mode encrypted
python client.py --name Melike --peer Hakan --mode encrypted
```

Wait for:

```text
Shared AES-GCM session key established
```

Say:

> Now the clients exchange public keys and derive the session key locally.

## Step 5: Show Ciphertext on the Server

In Hakan's terminal, type:

```text
Merhaba Melike, this server cannot read the message.
```

Server output should show:

```text
[SPY SERVER VIEW - ENCRYPTED MODE]
From Hakan to Melike: 8f3a9c2b7e01aa91...
```

Say:

> The server still forwards the message, but it sees ciphertext instead of readable text.

## Step 6: Show Local Decryption

Melike's terminal should show:

```text
[Melike RECEIVED]
[DECRYPTED MESSAGE] Hakan: Merhaba Melike, this server cannot read the message.
```

Say:

> Only Melike can decrypt the message because the shared key exists on the clients, not on the server.

## Step 7: Run the Attacker Simulation

Open another terminal:

```powershell
python attacker_simulation.py
```

Say:

> This is not a real attack. It only creates suspicious local behavior for the demo.

## Step 8: Show AI-Based Detection

Watch the server terminal:

```text
[AI SECURITY AGENT]
Client: Attacker
Risk Score: 0.87
Status: SUSPICIOUS
Reason: very high message frequency and repeated reconnect attempts
Recommended Action: Temporarily block client in demo mode.
```

Say:

> The AI security agent does not read message contents. It only analyzes metadata such as message frequency, reconnect count, size, and integrity failures.

## Step 9: Show Integrity Warning

Before running the tamper demo, make sure Hakan has sent at least one encrypted message to Melike.

The attacker simulation sends a `tamper_last` request. The server flips one ciphertext bit in a copy of the last encrypted message.

Melike should see:

```text
[INTEGRITY WARNING] Warning: Message integrity check failed. Message may have been modified.
```

Say:

> AES-GCM detects that the ciphertext was changed, so the receiver refuses to decrypt it.

## Turkish Explanation for Presentation

Bu projede iki istemci, Hakan ve Melike, merkezi bir sunucu uzerinden haberlesiyor. Duz metin modunda sunucu mesaji okuyabiliyor. Sifreli modda istemciler X25519 anahtar degisimi ile ortak bir oturum anahtari olusturuyor ve mesajlari AES-GCM ile sifreliyor. Bu nedenle sunucu sadece anlamsiz sifreli veri goruyor. Mesaj uzerinde degisiklik yapilirsa AES-GCM butunluk kontrolu bunu yakaliyor. Ayrica AI guvenlik ajani mesaj icerigini okumadan sadece metadatalara bakarak supheli davranislari tespit ediyor.

