"""
capture.py — Raw AF_PACKET socket setup and promiscuous mode management.

Requires root / CAP_NET_RAW.  Linux only (AF_PACKET is not available on macOS
or Windows — that is intentional; this project is a learning exercise in how
the Linux kernel exposes the wire to userspace).
"""

import socket
import struct
import fcntl

# Linux ioctl constants for network interface flags
SIOCGIFFLAGS = 0x8913   # get interface flags
SIOCSIFFLAGS = 0x8914   # set interface flags
IFF_PROMISC  = 0x100    # promiscuous mode bit

# ifreq struct: 16-byte interface name + 24 bytes of union data = 40 bytes
_IFREQ_SIZE = 40


def _ifreq(ifname: str) -> bytes:
    """Build a packed ifreq struct with the interface name in the first 16 bytes."""
    return struct.pack('16sH22x', ifname.encode()[:15], 0)


def set_promiscuous(sock: socket.socket, ifname: str, enable: bool = True) -> None:
    """Toggle promiscuous mode on *ifname* via ioctl."""
    ifreq = _ifreq(ifname)
    # fetch current flags
    result = fcntl.ioctl(sock.fileno(), SIOCGIFFLAGS, ifreq)
    flags = struct.unpack_from('16xH', result)[0]

    if enable:
        flags |= IFF_PROMISC
    else:
        flags &= ~IFF_PROMISC

    # write updated flags back
    ifreq_new = struct.pack('16sH22x', ifname.encode()[:15], flags)
    fcntl.ioctl(sock.fileno(), SIOCSIFFLAGS, ifreq_new)


def create_socket(ifname: str) -> socket.socket:
    """
    Open an AF_PACKET/SOCK_RAW socket bound to *ifname*.

    Captures every Ethernet frame arriving on the interface regardless of
    destination MAC (promiscuous mode is enabled automatically).

    Returns the open socket — caller is responsible for closing it.
    Raises PermissionError if not running as root / without CAP_NET_RAW.
    """
    # ETH_P_ALL = 0x0003 — capture every protocol
    ETH_P_ALL = 0x0003
    try:
        sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(ETH_P_ALL),
        )
    except PermissionError:
        raise PermissionError(
            "Raw socket requires root or CAP_NET_RAW. "
            "Re-run with: sudo python3 src/main.py"
        )

    sock.bind((ifname, 0))
    set_promiscuous(sock, ifname, enable=True)
    return sock


def close_socket(sock: socket.socket, ifname: str) -> None:
    """Disable promiscuous mode and close *sock* cleanly."""
    try:
        set_promiscuous(sock, ifname, enable=False)
    except OSError:
        pass  # interface may have gone away
    sock.close()
