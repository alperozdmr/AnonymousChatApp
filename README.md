# 🔗 Secure Peer-to-Peer Chat over Subnets with Gateway Peers

Bu proje, **aynı veya farklı subnetler içinde bulunan peer’ların** birbirleriyle güvenli bir şekilde haberleşmesini sağlar.  
Java tabanlı GUI istemciler ve Python ile yazılmış UDP/TCP gateway sunucuları birlikte çalışır.  

## 📦 Proje Bileşenleri

### 🖥️ Java Tarafı (`/java`)
- `ChatClientGUI.java` – Swing arayüzü
- `ControlClient.java` – Gateway’e TCP üzerinden TLV mesajı yollar
- `KeyManager.java` – RSA anahtar yönetimi, Base64 destekli

### 🐍 Python Tarafı (`/python`)
- `control_server.py` – Normal peer’lar için TCP/9000 listener ve UDP broadcast yayını
- `gateway_server.py` – Subnet’ler arasında köprü kuran peer (eth0 & eth1 üzerinden çift yönlü forwarding)

---

## 🌐 Ağ Mimarisi

- **Aynı subnet içindeki** peer'lar UDP broadcast ile haberleşir.
- **Farklı subnetlerdeki** peer'lar, kendi gateway'lerine mesaj gönderir.
- Gateway'ler UDP unicast (ya da TCP) ile birbirine mesajı iletir, sonra bulunduğu subnet'te tekrar broadcast eder.

---

## 🧠 Özellikler

✅ RSA ile şifreli mesajlaşma  
✅ Peer'lar birbirini tanımadığında KEY_REQUEST/RESPONSE ile anahtar alışverişi  
✅ Döngü engelleme için gateway üzerinde `seen_cache` kontrolü  
✅ Subnet'ler arası dinamik yönlendirme  
✅ Docker ağı ile container izolasyonu ve ağ simülasyonu

---

## 🛠️ Kurulum

### 1. Python Tarafı

```bash
docker build -t gateway1  Dockerfile .
docker build -t gateway2  Dockerfile .
docker build -t server1  Dockerfile .
docker build -t server1  Dockerfile .

docker-compose up -d

as you need


