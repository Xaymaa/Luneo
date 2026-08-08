import json
import struct

MAX_PLAINTEXT = 100 * 1024 * 1024
MAX_FRAME = (MAX_PLAINTEXT + 2) // 3 * 4 

def send_framed(conn, obj):
    payload = json.dumps(obj).encode("utf-8")
    conn.sendall(struct.pack(">I", len(payload)) + payload)

def _recv_exactly(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def recv_framed(conn):
    header = _recv_exactly(conn, 4)
    if header is None:
        return None
    length = struct.unpack(">I", header)[0]
    if length > MAX_FRAME:
        raise ValueError(f"frame too large: {length}")
    payload = _recv_exactly(conn, length)
    if payload is None:
        return None
    return json.loads(payload.decode("utf-8"))