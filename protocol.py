import json
import struct

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
    payload = _recv_exactly(conn, length)
    if payload is None:
        return None
    return json.loads(payload.decode("utf-8"))