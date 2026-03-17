"""
arp.py — Parse an ARP packet for IPv4 over Ethernet (always 28 bytes).

ARP packet layout (RFC 826) for htype=Ethernet, ptype=IPv4:
  Bytes  0–1   Hardware type  (1 = Ethernet)
  Bytes  2–3   Protocol type  (0x0800 = IPv4)
  Byte   4     Hardware address length (6 for Ethernet)
  Byte   5     Protocol address length (4 for IPv4)
  Bytes  6–7   Operation  (1 = request, 2 = reply)
  Bytes  8–13  Sender hardware address (MAC)
  Bytes 14–17  Sender protocol address (IP)
  Bytes 18–23  Target hardware address (MAC)
  Bytes 24–27  Target protocol address (IP)

ARP spoofing indicators:
  - An ARP reply (op==2) that changes the MAC for a known IP.
  - A gratuitous ARP: sender_ip == target_ip (used legitimately for cache
    refresh but also the standard MITM setup tool).
"""

import struct
from typing import Optional

OP_REQUEST = 1
OP_REPLY   = 2

_ARP_LEN = 28
_FMT     = '!HHBBH6s4s6s4s'


def _mac(b: bytes) -> str:
    return ':'.join(f'{x:02x}' for x in b)


def _ip(b: bytes) -> str:
    return '.'.join(str(x) for x in b)


def parse(raw: bytes) -> Optional[dict]:
    """
    Parse an ARP packet.

    Parameters
    ----------
    raw : bytes
        Bytes starting at the first byte of the ARP header (after Ethernet
        header has been stripped).

    Returns
    -------
    dict with keys:
        htype       : int   hardware type  (1 = Ethernet)
        ptype       : int   protocol type  (0x0800 = IPv4)
        operation   : int   1=request, 2=reply
        sender_mac  : str
        sender_ip   : str
        target_mac  : str
        target_ip   : str
        is_gratuitous : bool  True when sender_ip == target_ip

    Returns None if the packet is too short or not IPv4/Ethernet.
    """
    if len(raw) < _ARP_LEN:
        return None

    (htype, ptype, hlen, plen, operation,
     sender_mac_raw, sender_ip_raw,
     target_mac_raw, target_ip_raw) = struct.unpack_from(_FMT, raw)

    # Only handle Ethernet/IPv4 ARP — skip others silently
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        return None

    sender_ip = _ip(sender_ip_raw)
    target_ip = _ip(target_ip_raw)

    return {
        'htype'        : htype,
        'ptype'        : ptype,
        'operation'    : operation,
        'sender_mac'   : _mac(sender_mac_raw),
        'sender_ip'    : sender_ip,
        'target_mac'   : _mac(target_mac_raw),
        'target_ip'    : target_ip,
        'is_gratuitous': sender_ip == target_ip,
    }
