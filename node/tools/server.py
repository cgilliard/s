#!/usr/bin/env python3
"""server.py -- serves node images to tabernacle the way a node will
(docs/TABERNACLE.md), for running on a seed until the fam node does.

Usage: server.py PORT VERSION=FILE [VERSION=FILE ...]

Each FILE is served as its VERSION on UDP PORT.  A file is re-read when its
mtime changes, so a build can be replaced without a restart; its Gimli-Hash
(as gen_hash and tabernacle compute it) is printed when it is loaded, to
compare with what was patched into a tabernacle.  Nothing is checked here:
tabernacle checks what it gets.

The protocol is tabminer's (miner/src/net.rs): magic "TAB1", a type byte, the
payload; integers little-endian.  Requests carry the token our Pong gave the
asker's address (an HMAC of it under a key made at start), so nothing is sent
to a forged address.
  Ping (1)        status (140 bytes; the nonce first)   -> Pong
  Pong (2)        status: the nonce echoed, the token, all else zero (so a
                  tabminer node takes us for another chain, not a peer)
  GetPeers (3)    token                                 -> Peers, empty
  GetImages (64)  token                                 -> Images
  Images (65)     count u8, then version u32, size u32 each
  GetImage (66)   token, version u32, count u8, then start u16, len u16 each
                                                        -> ImageChunk each
  ImageChunk (67) version u32, size u32, index u16, len u16, bytes
Chunks are 1,024 bytes (the last the rest), at most MAX_ASK an ask.
"""
import hashlib
import hmac
import os
import socket
import struct
import sys

MAGIC = b'TAB1'
T_PING, T_PONG, T_GET_PEERS, T_PEERS = 1, 2, 3, 4
T_GET_IMAGES, T_IMAGES, T_GET_IMAGE, T_IMAGE_CHUNK = 64, 65, 66, 67
STATUS = 140
CHUNK = 1024
MAX_ASK = 64
MAX_INDEX = 1 << 16  # chunk indexes are u16: images up to 64 MiB
VERBOSE = os.environ.get('VERBOSE', '') != ''


def usage():
    sys.exit("usage: server.py PORT VERSION=FILE [VERSION=FILE ...]")


args = sys.argv[1:]
if len(args) < 2:
    usage()
try:
    PORT = int(args[0])
    IMAGES = {}
    for a in args[1:]:
        v, f = a.split('=', 1)
        IMAGES[int(v)] = {'path': f, 'mtime': None, 'data': b''}
except ValueError:
    usage()
KEY = os.urandom(32)


def gimli(s):
    """The Gimli permutation on 12 little-endian u32 words, in place."""
    M = 0xFFFFFFFF
    for r in range(24, 0, -1):
        for c in range(4):
            x = ((s[c] << 24) | (s[c] >> 8)) & M
            y = ((s[c + 4] << 9) | (s[c + 4] >> 23)) & M
            z = s[c + 8]
            s[c + 8] = (x ^ (z << 1) ^ ((y & z) << 2)) & M
            s[c + 4] = (y ^ x ^ ((x | z) << 1)) & M
            s[c] = (z ^ y ^ ((x & y) << 3)) & M
        if r % 4 == 0:
            s[0], s[1], s[2], s[3] = s[1], s[0], s[3], s[2]
            s[0] ^= 0x9E377900 | r
        elif r % 4 == 2:
            s[0], s[1], s[2], s[3] = s[2], s[3], s[0], s[1]


def gimli_hash(data):
    """src/gen_hash.fam's hash (and tabernacle's)."""
    s = [0] * 12
    n = len(data) // 16 * 16
    for i in range(0, n, 16):
        for j, w in enumerate(struct.unpack('<4I', data[i:i + 16])):
            s[j] ^= w
        gimli(s)
    b = bytearray(struct.pack('<12I', *s))
    for j, x in enumerate(data[n:]):
        b[j] ^= x
    b[len(data) - n] ^= 0x01
    b[15] ^= 0x80
    b[47] ^= 0x01
    s = list(struct.unpack('<12I', b))
    gimli(s)
    out = struct.pack('<4I', *s[:4])
    gimli(s)
    return out + struct.pack('<4I', *s[:4])


def image(version):
    """The image served as `version`, re-read if its file changed."""
    im = IMAGES.get(version)
    if im is None:
        return None
    try:
        mtime = os.path.getmtime(im['path'])
        if mtime != im['mtime']:
            with open(im['path'], 'rb') as f:
                data = f.read()
            if len(data) > MAX_INDEX * CHUNK:
                print(f"{im['path']}: {len(data)} bytes, over the 64 MiB a version can be")
                return None
            im.update(mtime=mtime, data=data)
            print(f"version {version}: {im['path']}, {len(data)} bytes, hash {gimli_hash(data).hex()}")
    except OSError as e:
        print(f"version {version}: {e}")
        return None
    return im['data']


def token(addr):
    msg = socket.inet_aton(addr[0]) + struct.pack('<H', addr[1])
    return hmac.new(KEY, msg, hashlib.sha256).digest()[:8]


def send(sock, addr, kind, payload):
    sock.sendto(MAGIC + bytes([kind]) + payload, addr)


for v in sorted(IMAGES):
    image(v)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', PORT))
print(f"listening on UDP :{PORT}", flush=True)

while True:
    pkt, addr = sock.recvfrom(2048)
    if len(pkt) < 5 or pkt[:4] != MAGIC:
        continue
    kind, body = pkt[4], pkt[5:]
    if kind == T_PING and len(body) == STATUS:
        status = body[:8] + bytes(4) + token(addr) + bytes(STATUS - 20)
        send(sock, addr, T_PONG, status)
        if VERBOSE:
            print(f"ping from {addr}", flush=True)
        continue
    if len(body) < 8 or not hmac.compare_digest(body[:8], token(addr)):
        continue
    if kind == T_GET_PEERS and len(body) == 8:
        send(sock, addr, T_PEERS, b'\0')
    elif kind == T_GET_IMAGES and len(body) == 8:
        have = [(v, image(v)) for v in sorted(IMAGES)]
        have = [(v, d) for v, d in have if d is not None][:255]
        send(sock, addr, T_IMAGES, bytes([len(have)])
             + b''.join(struct.pack('<II', v, len(d)) for v, d in have))
        print(f"images asked by {addr}", flush=True)
    elif kind == T_GET_IMAGE and len(body) >= 13:
        version, n = struct.unpack('<IB', body[8:13])
        if len(body) != 13 + 4 * n:
            continue
        data = image(version)
        if data is None:
            continue
        chunks = (len(data) + CHUNK - 1) // CHUNK
        sent = 0
        for k in range(n):
            start, count = struct.unpack('<HH', body[13 + 4 * k:17 + 4 * k])
            for i in range(start, min(start + count, chunks)):
                if sent == MAX_ASK:
                    break
                piece = data[i * CHUNK:(i + 1) * CHUNK]
                send(sock, addr, T_IMAGE_CHUNK,
                     struct.pack('<IIHH', version, len(data), i, len(piece)) + piece)
                sent += 1
        if VERBOSE:
            print(f"version {version}: {sent} chunks to {addr}", flush=True)
