import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 24)
sock.bind(("127.0.0.1", 53))
sock.settimeout(3)
counts = {}
total = 0
print("listening", flush=True)
try:
    while True:
        data = sock.recv(512)
        name = data[13:17].decode(errors="replace")
        counts[name] = counts.get(name, 0) + 1
        total += 1
except socket.timeout:
    pass
print(f"wire total={total} {counts}", flush=True)
