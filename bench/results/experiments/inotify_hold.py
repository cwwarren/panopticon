import ctypes
import os
import sys
import time

libc = ctypes.CDLL(None, use_errno=True)
MASK = 0x1 | 0x2 | 0x4 | 0x8 | 0x20 | 0x400 | 0x800
fd = libc.inotify_init1(os.O_NONBLOCK)
for path in sys.argv[2:]:
    assert libc.inotify_add_watch(fd, path.encode(), MASK) >= 0, path
print("ready", flush=True)
deadline = time.time() + float(sys.argv[1])
events = 0
while time.time() < deadline:
    try:
        events += len(os.read(fd, 1 << 16))
    except BlockingIOError:
        time.sleep(0.01)
print("bytes", events, flush=True)
