"""
ethernet.py — Parse a raw Ethernet II frame header (14 bytes).

Frame layout:
  Bytes  0–5   Destination MAC (6 bytes)
  Bytes  6–11  Source MAC      (6 bytes)
  Bytes 12–13  EtherType       (2 bytes, big-endian)
  Bytes 14+    Payload

EtherType values we care about:
  0x0800  IPv4
  0x0806  ARP
  0x86DD  IPv6 (parsed as 'other' — no IPv6 support in this project)
"""

import struct
from typing import Optional


ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP  = 0x0806
ETHERTYPE_IPV6 = 0x86DD

_HEADER_LEN = 14
_FMT        = '!6s6sH'   # network byte-order: 6-byte, 6-byte, unsigned short


def mac_to_str(mac_bytes: bytes) -> str:
    """Convert 6 raw bytes to a human-readable MAC string (aa:bb:cc:dd:ee:ff)."""
    return ':'.join(f'{b:02x}' for b in mac_bytes)


def parse(raw: bytes) -> Optional[dict]:
    """
    Parse an Ethernet II frame.

    Parameters
    ----------
    raw : bytes
        Full raw frame starting at byte 0.

    Returns
    -------
    dict with keys:
        dst_mac   : str   e.g. 'ff:ff:ff:ff:ff:ff'
        src_mac   : str
        ethertype : int   e.g. 0x0800
        payload   : bytes remaining bytes after the 14-byte header

    Returns None if the frame is too short to be valid.
    """
    if len(raw) < _HEADER_LEN:
        return None

    dst_raw, src_raw, ethertype = struct.unpack_from(_FMT, raw)

    return {
        'dst_mac'  : mac_to_str(dst_raw),
        'src_mac'  : mac_to_str(src_raw),
        'ethertype': ethertype,
        'payload'  : raw[_HEADER_LEN:],
    }
