"""
ip.py — Parse an IPv4 header (minimum 20 bytes, may be longer with options).

IPv4 header layout (RFC 791):
  Byte  0      Version (4 bits) + IHL (4 bits)
  Byte  1      DSCP/ECN
  Bytes 2–3    Total length
  Bytes 4–5    Identification
  Bytes 6–7    Flags + Fragment offset
  Byte  8      TTL
  Byte  9      Protocol
  Bytes 10–11  Header checksum
  Bytes 12–15  Source IP
  Bytes 16–19  Destination IP
  Bytes 20+    Options (if IHL > 5) then payload

Protocol numbers we care about:
  1   ICMP
  6   TCP
  17  UDP
"""

import struct
from typing import Optional

PROTO_ICMP = 1
PROTO_TCP  = 6
PROTO_UDP  = 17

_MIN_HEADER = 20
_FMT        = '!BBHHHBBH4s4s'


def ip_to_str(ip_bytes: bytes) -> str:
    """Convert 4 raw bytes to dotted-decimal notation."""
    return '.'.join(str(b) for b in ip_bytes)


def parse(raw: bytes) -> Optional[dict]:
    """
    Parse an IPv4 header.

    Parameters
    ----------
    raw : bytes
        Bytes starting at the first byte of the IP header (i.e. after the
        Ethernet header has been stripped).

    Returns
    -------
    dict with keys:
        version    : int  (should always be 4)
        ihl        : int  header length in bytes (IHL field × 4)
        ttl        : int
        protocol   : int  transport-layer protocol number
        src_ip     : str  dotted-decimal
        dst_ip     : str
        payload    : bytes  everything after the IP header (including options)

    Returns None if the packet is malformed / too short.
    """
    if len(raw) < _MIN_HEADER:
        return None

    (ver_ihl, _, total_len, _ident, _frag,
     ttl, protocol, _cksum, src_raw, dst_raw) = struct.unpack_from(_FMT, raw)

    version = ver_ihl >> 4          # upper nibble
    ihl     = (ver_ihl & 0x0F) * 4  # lower nibble × 4 = bytes

    if version != 4 or ihl < _MIN_HEADER or len(raw) < ihl:
        return None

    return {
        'version' : version,
        'ihl'     : ihl,
        'ttl'     : ttl,
        'protocol': protocol,
        'src_ip'  : ip_to_str(src_raw),
        'dst_ip'  : ip_to_str(dst_raw),
        'payload' : raw[ihl:],
    }
