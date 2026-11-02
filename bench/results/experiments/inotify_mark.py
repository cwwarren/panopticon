import ctypes
import os
import sys
import time

libc = ctypes.CDLL(None, use_errno=True)
MASK = 0x20 | 0x8 | 0x4 | 0x800 | 0x400
drain, secs, paths = sys.argv[1] == "1", float(sys.argv[2]), sys.argv[3:]
fd = libc.inotify_init1(os.O_NONBLOCK)
for path in paths:
    assert libc.inotify_add_watch(fd, path.encode(), MASK) >= 0, path
print("ready", flush=True)
deadline = time.time() + secs
while time.time() < deadline:
    if drain:
        try:
            while os.read(fd, 1 << 16):
                pass
        except BlockingIOError:
            pass
    time.sleep(0.01)
