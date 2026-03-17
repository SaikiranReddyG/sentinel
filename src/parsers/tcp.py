"""
tcp.py — Parse a TCP segment header (minimum 20 bytes).

TCP header layout (RFC 793):
  Bytes  0–1   Source port
  Bytes  2–3   Destination port
  Bytes  4–7   Sequence number
  Bytes  8–11  Acknowledgement number
  Byte  12     Data offset (4 bits, upper) + reserved (3 bits) + NS flag (1 bit)
  Byte  13     Control flags: CWR ECE URG ACK PSH RST SYN FIN
  Bytes 14–15  Window size
  Bytes 16–17  Checksum
  Bytes 18–19  Urgent pointer
  Bytes 20+    Options (if data offset > 5) then payload

Flag bitmasks (applied to the flags byte, byte 13):
  FIN = 0x01
  SYN = 0x02
  RST = 0x04
  PSH = 0x08
  ACK = 0x10
  URG = 0x20

Scan type identification:
  SYN scan  : flags == SYN        (0x02)
  FIN scan  : flags == FIN        (0x01)
  NULL scan : flags == 0x00
  XMAS scan : flags == FIN|PSH|URG (0x29)
"""

import struct
from typing import Optional

# Flag constants
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

# Scan type names (keyed by flags byte value)
SCAN_TYPES = {
    SYN          : 'SYN',
    FIN          : 'FIN',
    0x00         : 'NULL',
    FIN | PSH | URG : 'XMAS',
}

_MIN_HEADER = 20
_FMT        = '!HHIIBBHHH'


def flags_to_str(flags: int) -> str:
    """Return a human-readable flags string, e.g. 'SYN ACK'."""
    names = []
    for bit, name in [(CWR,'CWR'),(ECE,'ECE'),(URG,'URG'),(ACK,'ACK'),
                      (PSH,'PSH'),(RST,'RST'),(SYN,'SYN'),(FIN,'FIN')]:
        if flags & bit:
            names.append(name)
    return ' '.join(names) if names else 'NONE'


def scan_type(flags: int) -> Optional[str]:
    """Return the scan type name if *flags* matches a known scan pattern."""
    return SCAN_TYPES.get(flags)


def parse(raw: bytes) -> Optional[dict]:
    """
    Parse a TCP segment header.

    Parameters
    ----------
    raw : bytes
        Bytes starting at the first byte of the TCP header.

    Returns
    -------
    dict with keys:
        src_port    : int
        dst_port    : int
        seq         : int
        ack         : int
        data_offset : int  header length in bytes (data offset field × 4)
        flags       : int  raw flags byte
        flags_str   : str  human-readable flag names
        window      : int
        payload     : bytes  TCP payload (after header + options)

    Returns None if the segment is malformed / too short.
    """
    if len(raw) < _MIN_HEADER:
        return None

    (src_port, dst_port, seq, ack_num,
     data_off_byte, flags_byte,
     window, _cksum, _urg) = struct.unpack_from(_FMT, raw)

    # upper nibble of byte 12 = data offset (in 32-bit words)
    data_offset = (data_off_byte >> 4) * 4

    if data_offset < _MIN_HEADER or len(raw) < data_offset:
        return None

    return {
        'src_port'   : src_port,
        'dst_port'   : dst_port,
        'seq'        : seq,
        'ack'        : ack_num,
        'data_offset': data_offset,
        'flags'      : flags_byte,
        'flags_str'  : flags_to_str(flags_byte),
        'window'     : window,
        'payload'    : raw[data_offset:],
    }
