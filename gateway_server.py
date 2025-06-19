#!/usr/bin/env python3
"""
gateway_server.py

Bu kod, bir gateway peer olarak tek bir subnet’e (IFACE) bağlı çalışır:
1. Java client’lardan TCP/9005 üzerinden TLV mesajları alır.
2. Alınan TLV’i yerel subnet’te UDP/9100 ile broadcast eder (IFACE üzerinden).
3. Aynı TLV’i diğer gateway’e UDP/9200 ile unicast olarak yollar.
4. UDP receiver:
   - Eğer UDP/9100’dan (yerel subnet) geliyorsa, Java client’a “RECV <base64(TLV)>” iletir.
   - Eğer UDP/9200’dan (diğer gateway’den) geliyorsa, 
     a) Java client’a “RECV <base64(TLV)>” iletir,
     b) IFACE üzerindeki subnet’te yeniden UDP/9100 ile broadcast eder.
   - seen_set ile kopya işlemleri engeller.
"""

import sys
import socket
import base64
import threading
from scapy.all import Ether, IP, UDP, sendp, sniff, conf

# ─── CONFIGURATION ───────────────────────────────────────────────────────
CONTROL_HOST = "0.0.0.0"
CONTROL_PORT = 9005

UDP_LOCAL_PORT = 9100   # Yerel subnet broadcast için port
UDP_GW_PORT    = 9200   # Diğer gateway’e unicast için port
UDP_SPORT      = 4000   # UDP kaynak portu (aynı kalabilir)

# Tek bir interface al (örneğin: "eth0"). Parametre verilmezse Scapy'nin default iface’i kullanılır.
IFACE = sys.argv[2] #if len(sys.argv) > 1 else conf.iface
print(f"[INIT] Using interface: {IFACE}")

# Diğer subnet’teki gateway’in IP’si (unicast forwarding için tek eleman)
GATEWAY_OTHER_SUBNET = "172.25.0.10"
GATEWAYS = [GATEWAY_OTHER_SUBNET]
print(f"[INIT] Other-subnet gateway target: {GATEWAYS}")

# Seen‐Cache yapısı (aynı TLV’i ikinci kez işleme)
seen_set = set()  # TLV’in base64 string’lerini saklar

clients = set()   # Java client’ların PrintWriter’ları

# ─── TCP SERVER: Java client’lardan TLV’i al, UDP/9100 broadcast + UDP/9200 unicast yap ───
def tcp_worker(conn, addr):
    print(f"[TCP] New connection from {addr}")
    writer = conn.makefile("w")
    clients.add(writer)

    with conn, conn.makefile("r") as reader:
        for line in reader:
            line = line.strip()
            if not line:
                continue

            print(f"[TCP] Received line: {line}")
            try:
                cmd, b64 = line.split(" ", 1)
                tlv = base64.b64decode(b64)
                print(f"[TCP] Decoded TLV len={len(tlv)} for command={cmd}")

                # 1) Yerel broadcast: IFACE üzerinden UDP/9100
                print(f"[BCAST] iface={IFACE} → UDP {UDP_LOCAL_PORT}, tlv_len={len(tlv)}")
                sendp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") /
                    IP(dst="255.255.255.255") /
                    UDP(sport=UDP_SPORT, dport=UDP_LOCAL_PORT) /
                    tlv,
                    iface=IFACE,
                    verbose=False
                )

                # 2) Diğer gateway’e unicast: UDP/9200
                for gw in GATEWAYS:
                    own_ip = conf.route.route("0.0.0.0")[2]
                    if gw == own_ip:
                        print(f"[UNICAST] Skipping self gateway {gw}")
                        continue
                    print(f"[UNICAST] Sending to other-gateway {gw}:{UDP_GW_PORT}, tlv_len={len(tlv)}")
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.sendto(tlv, (gw, UDP_GW_PORT))

            except Exception as e:
                print(f"[TCP ERR] {e}")

    print(f"[TCP] Connection closed: {addr}")
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

# ─── UDP RECEIVER: Gelen TLV’leri işleme ───────────────────────────────────
def udp_receiver():
    print(f"[UDP] Sniffing UDP on interface {IFACE} (ports {UDP_LOCAL_PORT} & {UDP_GW_PORT})")

    def on_pkt(pkt):
        if UDP not in pkt:
            return

        dport = pkt[UDP].dport
        tlv = bytes(pkt[UDP].payload)
        src_ip = pkt[IP].src
        sniffed_if = pkt.sniffed_on

        # seen_set kontrolü: her TLV’i base64 string olarak sakla
        key = base64.b64encode(tlv).decode()
        # if key in seen_set:
        #     return
        seen_set.add(key)

        # 1) Eğer yerel subnet’ten geldi (port 9100):
        if dport == UDP_LOCAL_PORT:
            print(f"[UDP] From LOCAL subnet: tlv_len={len(tlv)} src={src_ip}")
            # a) Java client’a ilet
            for w in list(clients):
                try:
                    w.write("RECV " + key + "\n")
                    w.flush()
                    print(f"[UDP→TCP] Forwarded LOCAL to Java: tlv_len={len(tlv)}")
                except:
                    clients.discard(w)
            # b) Diğer gateway’e unicast (9200)
            for gw in GATEWAYS:
                print(f"[UDP→UDP] LOCAL→Unicast to {gw}:{UDP_GW_PORT}, tlv_len={len(tlv)}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(tlv, (gw, UDP_GW_PORT))
            return

        # 2) Eğer diğer gateway’den geldi (port 9200):
        if dport == UDP_GW_PORT:
            print(f"[UDP] From OTHER gateway: tlv_len={len(tlv)} src={src_ip}")
            # a) Java client’a ilet
            for w in list(clients):
                try:
                    w.write("RECV " + key + "\n")
                    w.flush()
                    print(f"[UDP→TCP] Forwarded OTHER to Java: tlv_len={len(tlv)}")
                except:
                    clients.discard(w)
            # b) Yerel subnet’te yeniden broadcast (UDP/9100)
            print(f"[REBCAST] OTHER→LOCAL broadcast on {IFACE}, tlv_len={len(tlv)}")
            sendp(
                Ether(dst="ff:ff:ff:ff:ff:ff") /
                IP(dst="255.255.255.255") /
                UDP(sport=UDP_SPORT, dport=UDP_LOCAL_PORT) /
                tlv,
                iface=IFACE,
                verbose=False
            )
            return

        # Diğer portlardansa atla
        return

    sniff(prn=on_pkt, store=False, iface=IFACE)

# ─── MAIN ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # 1) TCP server thread’ini başlat
    threading.Thread(target=tcp_server, daemon=True).start()
    # 2) UDP receiver’ı başlat (bloklayıcı)
    udp_receiver()
