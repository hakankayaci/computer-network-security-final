# 🔐 End-to-End Encrypted Chat with AI Anomaly Detection

> A small chat app that lets you *see* why end-to-end encryption matters — and that catches an attacker from metadata alone, without ever reading a single message.

**🎥 Demo video:** https://youtu.be/we56pO28Ffw

| | |
|---|---|
| **Course** | CENG3544 — Computer Network and Security |
| **Instructor** | Doç. Dr. Enis Karaarslan |
| **Student** | Hakan Kayacı |

---

## The idea

Two friends, **Hakan** and **Melike**, chat through a central server. The whole project answers one question on screen: *what can the server in the middle actually read?*

![System architecture](Report/images/1.png)

- 🟢 **Plain mode** — the server reads every message. This is the problem.
- 🔒 **Encrypted mode** — the clients share a key with **X25519** and encrypt with **AES-256-GCM**, so the server sees only ciphertext. This is the fix.
- 🧪 **Integrity** — flip one bit of the ciphertext and the receiver rejects it. AES-GCM proves the message was not touched.
- 🛡️ **AI security agent** — watches **metadata only** (message rate, size, reconnects) and flags an attacker *without reading any message*.

![Five-stage security flow](Report/images/2.png)

## Try it (4 terminals)

```powershell
pip install -r requirements.txt

# 1) the server
python server.py
# 2) Hakan          # 3) Melike
python client.py --name Hakan  --peer Melike --mode plain
python client.py --name Melike --peer Hakan  --mode plain
```

Send a message → the server prints it in clear text. Now type `/quit` in both clients, restart them with `--mode encrypted`, and send again: the server shows only ciphertext, while Melike still reads the message.

Finally, run the safe attacker in a 4th terminal:

```powershell
python attacker_simulation.py
```

You will see `[INTEGRITY WARNING]` on the receiver and `[AI SECURITY AGENT] … SUSPICIOUS` on the server, which then blocks the attacker — while Hakan and Melike are never flagged.

## Good to know

- 🧱 Runs only on `localhost` (`127.0.0.1`) and performs **no real attacks**.
- 🔍 The AI never reads message content — metadata only.
- ⚠️ Educational prototype. Main limits: public keys are relayed without authentication (so a man-in-the-middle is possible), there is no replay protection, and the AI uses a demo baseline.

---

# 🇹🇷 Türkçe

> Uçtan uca şifrelemenin neden önemli olduğunu **gözünle gösteren**, ve saldırganı mesaj içeriğini hiç okumadan, sadece metadatadan yakalayan küçük bir sohbet uygulaması.

**🎥 Demo videosu:** https://youtu.be/we56pO28Ffw

| | |
|---|---|
| **Ders** | CENG3544 — Computer Network and Security |
| **Danışman** | Doç. Dr. Enis Karaarslan |
| **Öğrenci** | Hakan Kayacı |

---

## Fikir

İki arkadaş, **Hakan** ve **Melike**, merkezi bir sunucu üzerinden mesajlaşıyor. Proje ekranda tek bir soruyu yanıtlıyor: *aradaki sunucu gerçekte neyi okuyabiliyor?*

- 🟢 **Düz mod** — sunucu her mesajı okur. Problem bu.
- 🔒 **Şifreli mod** — istemciler **X25519** ile anahtar paylaşır, **AES-256-GCM** ile şifreler; sunucu artık sadece şifreli veri görür. Çözüm bu.
- 🧪 **Bütünlük** — şifreli metnin tek bir bitini değiştir, alıcı reddeder. AES-GCM mesajın değişmediğini kanıtlar.
- 🛡️ **AI güvenlik ajanı** — **sadece metadatayı** (mesaj hızı, boyut, yeniden bağlanma) izler ve saldırganı *hiçbir mesajı okumadan* işaretler.

## Çalıştır (4 terminal)

```powershell
pip install -r requirements.txt

python server.py
python client.py --name Hakan  --peer Melike --mode plain
python client.py --name Melike --peer Hakan  --mode plain
```

Mesaj gönder → sunucu açık metni yazar. Sonra iki istemcide de `/quit` yaz, `--mode encrypted` ile yeniden başlat ve tekrar gönder: sunucu sadece şifreli veri gösterir, Melike mesajı yine de okur.

Son olarak 4. terminalde güvenli saldırganı çalıştır:

```powershell
python attacker_simulation.py
```

Alıcıda `[INTEGRITY WARNING]`, sunucuda `[AI SECURITY AGENT] … SUSPICIOUS` görürsün; saldırgan engellenir, Hakan ve Melike asla işaretlenmez.

## Bilmekte fayda var

- 🧱 Sadece yerelde (`127.0.0.1`) çalışır ve **gerçek bir saldırı yapmaz**.
- 🔍 AI mesaj içeriğini hiç okumaz — sadece metadata.
- ⚠️ Eğitim amaçlı prototip. Başlıca sınırlar: açık anahtarlar kimlik doğrulamasız iletilir (MITM mümkün), replay koruması yok, AI demo verisiyle çalışır.
