
"""
control_server.py
─────────────────
• Java ControlClient’ten TCP/9000 ile komut alır
• TLV yükünü LAN’a UDP broadcast (sport=4000, dport=9001) olarak yollar
• UDP/9001’de gelen tüm broadcast-leri yakalar ve kendi bağlı Java
  istemcilerine 'RECV <base64>' satırı olarak iletir
NOT: Scapy ham Ethernet kullanır → root yetkisi gerekir.
"""

import socket, struct, base64, threading, time
from scapy.all import Ether, IP, UDP, sendp, sniff, conf

#CONTROL_HOST = "127.0.0.1"
CONTROL_HOST = "0.0.0.0"
CONTROL_PORT = 9004
UDP_PORT     = 9100          # broadcast hedefi / dinleyici
UDP_SPORT    = 4000          # kaynak port
IFACE        = conf.iface    # ör. "eth0"  →  sudo python control_server.py eth0

# --- TCP sunucu: Java istemcilerinden komut al ---
clients = set()              # akt-if PrintWriter’lar

def tcp_worker(conn, addr):
    print(f"[TCP] Connected: {addr}")
    writer = conn.makefile("w")
    clients.add(writer)
    with conn, conn.makefile("r") as reader:
        for line in reader:
            line = line.strip()
            if not line: continue
            try:
                cmd, b64 = line.split(" ", 1)
                payload = base64.b64decode(b64)
                print(f"[TCP] {cmd} len={len(payload)} → broadcast UDP")

                pkt = (
                    Ether(dst="ff:ff:ff:ff:ff:ff") /
                    IP(src="10.0.0.1", dst="255.255.255.255") /
                    UDP(sport=UDP_SPORT, dport=UDP_PORT) /
                    payload
                )
                sendp(pkt, iface=IFACE, verbose=False)

            except Exception as e:
                print(f"[ERR] TCP parse error: {e}")
    print(f"[TCP] Disconnected: {addr}")
    clients.discard(writer)

def tcp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((CONTROL_HOST, CONTROL_PORT))
    srv.listen()
    print(f"[TCP] Listening on {CONTROL_HOST}:{CONTROL_PORT}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=tcp_worker, args=(conn, addr), daemon=True).start()

# ─── UDP Yayın Dinleyici ───────────────────────────────────────────────
def udp_receiver():
    def on_pkt(pkt):
        if UDP in pkt and pkt[UDP].dport == UDP_PORT:
            payload = bytes(pkt[UDP].payload)
            line = "RECV " + base64.b64encode(payload).decode()
            # Tüm bağlı Java istemcilere gönder
            for w in list(clients):
                try:
                    w.write(line + "\n"); w.flush()
                except:
                    clients.discard(w)
            print(f"[UDP] ▼ payload len={len(payload)} → forwarded to {len(clients)} client(s)")

    print(f"[UDP] Sniffing udp port {UDP_PORT} on iface {IFACE}")
    sniff(filter=f"udp and port {UDP_PORT}", prn=on_pkt, store=False, iface=IFACE)

# ─── Başlat ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2:
        IFACE = sys.argv[1]
    threading.Thread(target=tcp_server, daemon=True).start()
    udp_receiver()