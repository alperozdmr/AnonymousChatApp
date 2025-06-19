#FOR CONTROL SERVER
# FROM python:3.10-slim

# # libpcap ve derleyici araçlarını ekleyelim
# RUN apt-get update && apt-get install -y --no-install-recommends \
#         libpcap-dev gcc \
#     && rm -rf /var/lib/apt/lists/*

# RUN pip install --no-cache-dir scapy

# WORKDIR /app
# COPY gateway_server.py /app/

# EXPOSE 9000/tcp 9100/udp

# CMD ["python3", "control_server.py", "eth0"]

#FOR GATEWAY SERVER
FROM python:3.10-slim

# libpcap ve derleyici araçlarını ekleyelim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev gcc \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy

WORKDIR /app
COPY gateway_server.py /app/

EXPOSE 9005/tcp 9100/udp

CMD ["python3", "gateway_server.py", "eth0","eth1"]
