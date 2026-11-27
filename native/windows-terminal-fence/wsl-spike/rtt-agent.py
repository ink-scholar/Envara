"""Echo every byte from wsl.exe stdin straight back to stdout (raw fds, no asyncio)."""
import os
while (b := os.read(0, 1 << 20)):
    view = memoryview(b)
    while view:
        view = view[os.write(1, view):]
