"""Distro-side end of the Envara <-> WSL channel: wsl.exe's own stdin/stdout.

Frames: type(1) stream(4) length(4) payload. OPEN carries the socket name the
connection arrived on; the Windows host decides what that name may reach.
No TCP port is opened between Windows and the distro. Spike only: no
per-stream flow control (one slow stream stalls the rest).
"""
import asyncio, os, struct, subprocess, sys, time
DEBUG = os.environ.get('CH_DEBUG') == '1'
def log(*a):
    if DEBUG: os.write(2, (f'[agent {time.monotonic():.2f}] ' + ' '.join(map(str, a)) + '\n').encode())

OPEN, DATA, CLOSE = 1, 2, 3
RUN = '/run/envara'
streams, out, next_id = {}, None, 1

def send(kind, sid, payload=b''):
    out.write(struct.pack('>BII', kind, sid, len(payload)) + payload)

async def accept(name, reader, writer):
    global next_id
    sid, next_id = next_id, next_id + 1
    streams[sid] = writer
    send(OPEN, sid, name.encode()); log('open', sid, name)
    try:
        while data := await reader.read(65536):
            send(DATA, sid, data)
            await out.drain()
    except ConnectionError:
        pass
    finally:
        log('local-eof', sid)
        if streams.pop(sid, None) is not None:
            send(CLOSE, sid)
        writer.close()

async def pump(reader):
    while True:
        try:
            kind, sid, n = struct.unpack('>BII', await reader.readexactly(9))
            payload = await reader.readexactly(n) if n else b''
        except asyncio.IncompleteReadError:
            os._exit(0)  # the host went away: the environment loses its route
        w = streams.get(sid)
        if kind == DATA and w:
            w.write(payload)
            log('drain?', sid, len(payload))
            try: await w.drain()
            except ConnectionError: pass
            log('drained', sid)
        elif kind == CLOSE and w:
            streams.pop(sid, None); log('host-close', sid)
            w.close()

async def main():
    global out
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=1 << 22)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), os.fdopen(0, 'rb', 0))
    tr, pr = await loop.connect_write_pipe(asyncio.streams.FlowControlMixin, os.fdopen(1, 'wb', 0))
    out = asyncio.StreamWriter(tr, pr, None, loop)
    os.makedirs(RUN, exist_ok=True)
    for name in ('route', 'bench'):
        path = f'{RUN}/{name}.sock'
        if os.path.exists(path): os.unlink(path)
        await asyncio.start_unix_server(lambda r, w, n=name: accept(n, r, w), path=path)
        os.chmod(path, 0o600)
    asyncio.ensure_future(pump(reader))
    # The test script reports on stderr, which wsl.exe carries separately.
    proc = await asyncio.create_subprocess_exec('sh', sys.argv[1], stdin=subprocess.DEVNULL, stdout=2, stderr=2)
    code = await proc.wait()
    await out.drain()
    os._exit(code)

asyncio.run(main())
