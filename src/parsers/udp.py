"""
udp.py — Parse a UDP datagram header (always exactly 8 bytes).

UDP header layout (RFC 768):
  Bytes 0–1  Source port
  Bytes 2–3  Destination port
  Bytes 4–5  Length  (header + data, in bytes)
  Bytes 6–7  Checksum
  Bytes 8+   Payload
"""

import struct
from typing import Optional

_HEADER_LEN = 8
_FMT        = '!HHHH'


def parse(raw: bytes) -> Optional[dict]:
    """
    Parse a UDP datagram header.

    Parameters
    ----------
    raw : bytes
        Bytes starting at the first byte of the UDP header.

    Returns
    -------
    dict with keys:
        src_port : int
        dst_port : int
        length   : int  (header + payload in bytes)
        checksum : int
        payload  : bytes

    Returns None if the datagram is too short.
    """
    if len(raw) < _HEADER_LEN:
        return None

    src_port, dst_port, length, checksum = struct.unpack_from(_FMT, raw)

    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'length'  : length,
        'checksum': checksum,
        'payload' : raw[_HEADER_LEN:],
    }
