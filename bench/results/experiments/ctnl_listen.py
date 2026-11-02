import resource
import socket
import sys
import time

NETLINK_NETFILTER = 12
SO_RCVBUFFORCE = 33
GROUPS = 1 | 4
sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, 256 << 20)
sock.bind((0, GROUPS))
sock.settimeout(0.05)
print("ready", flush=True)
buf = bytearray(1 << 16)
messages = overflows = 0
deadline = time.time() + float(sys.argv[1])
while time.time() < deadline:
    try:
        if sock.recv_into(buf):
            messages += 1
    except TimeoutError:
        pass
    except OSError:
        overflows += 1
usage = resource.getrusage(resource.RUSAGE_SELF)
print("messages", messages, "overflows", overflows, "cpu_s", round(usage.ru_utime + usage.ru_stime, 2), flush=True)
