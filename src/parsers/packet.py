"""
parse_packet — Dispatcher that chains Ethernet → IP → TCP/UDP/ARP parsers.

Returns a single unified packet dict with all parsed layers merged, or None
if the frame is malformed / an unsupported protocol at any layer.

Packet dict keys (present only when the corresponding layer was parsed):

  # Ethernet layer (always present on success)
  eth_src_mac, eth_dst_mac, ethertype

  # IP layer (present when ethertype == 0x0800)
  ip_src, ip_dst, ip_ttl, ip_protocol, ip_version, ip_ihl

  # TCP layer (present when ip_protocol == 6)
  tcp_src_port, tcp_dst_port, tcp_seq, tcp_ack,
  tcp_flags, tcp_flags_str, tcp_window, tcp_data_offset

  # UDP layer (present when ip_protocol == 17)
  udp_src_port, udp_dst_port, udp_length, udp_checksum

  # ARP layer (present when ethertype == 0x0806)
  arp_operation, arp_sender_mac, arp_sender_ip,
  arp_target_mac, arp_target_ip, arp_is_gratuitous

  # Meta
  proto : str  one of 'TCP', 'UDP', 'ARP', 'ICMP', 'OTHER'
  raw   : bytes  the original raw frame bytes
"""

from typing import Optional

from src.parsers import ethernet, ip, tcp, udp, arp
from src.parsers.ethernet import ETHERTYPE_IPV4, ETHERTYPE_ARP
from src.parsers.ip import PROTO_TCP, PROTO_UDP, PROTO_ICMP


def parse_packet(raw: bytes) -> Optional[dict]:
    """
    Parse a raw Ethernet frame all the way through to the transport layer.

    Parameters
    ----------
    raw : bytes
        Complete raw frame as returned by sock.recvfrom().

    Returns
    -------
    Unified packet dict, or None on a parsing failure.
    """
    # --- Ethernet layer ---
    eth = ethernet.parse(raw)
    if eth is None:
        return None

    packet: dict = {
        'proto'      : 'OTHER',
        'raw'        : raw,
        'eth_src_mac': eth['src_mac'],
        'eth_dst_mac': eth['dst_mac'],
        'ethertype'  : eth['ethertype'],
    }

    # --- IPv4 layer ---
    if eth['ethertype'] == ETHERTYPE_IPV4:
        ip_hdr = ip.parse(eth['payload'])
        if ip_hdr is None:
            return packet  # return what we have so far

        packet.update({
            'ip_src'     : ip_hdr['src_ip'],
            'ip_dst'     : ip_hdr['dst_ip'],
            'ip_ttl'     : ip_hdr['ttl'],
            'ip_protocol': ip_hdr['protocol'],
            'ip_version' : ip_hdr['version'],
            'ip_ihl'     : ip_hdr['ihl'],
        })

        # --- TCP ---
        if ip_hdr['protocol'] == PROTO_TCP:
            tcp_hdr = tcp.parse(ip_hdr['payload'])
            if tcp_hdr is None:
                return packet
            packet.update({
                'proto'          : 'TCP',
                'tcp_src_port'   : tcp_hdr['src_port'],
                'tcp_dst_port'   : tcp_hdr['dst_port'],
                'tcp_seq'        : tcp_hdr['seq'],
                'tcp_ack'        : tcp_hdr['ack'],
                'tcp_flags'      : tcp_hdr['flags'],
                'tcp_flags_str'  : tcp_hdr['flags_str'],
                'tcp_window'     : tcp_hdr['window'],
                'tcp_data_offset': tcp_hdr['data_offset'],
            })

        # --- UDP ---
        elif ip_hdr['protocol'] == PROTO_UDP:
            udp_hdr = udp.parse(ip_hdr['payload'])
            if udp_hdr is None:
                return packet
            packet.update({
                'proto'        : 'UDP',
                'udp_src_port' : udp_hdr['src_port'],
                'udp_dst_port' : udp_hdr['dst_port'],
                'udp_length'   : udp_hdr['length'],
                'udp_checksum' : udp_hdr['checksum'],
            })

        elif ip_hdr['protocol'] == PROTO_ICMP:
            packet['proto'] = 'ICMP'

    # --- ARP layer ---
    elif eth['ethertype'] == ETHERTYPE_ARP:
        arp_pkt = arp.parse(eth['payload'])
        if arp_pkt is None:
            return packet
        packet.update({
            'proto'             : 'ARP',
            'arp_operation'     : arp_pkt['operation'],
            'arp_sender_mac'    : arp_pkt['sender_mac'],
            'arp_sender_ip'     : arp_pkt['sender_ip'],
            'arp_target_mac'    : arp_pkt['target_mac'],
            'arp_target_ip'     : arp_pkt['target_ip'],
            'arp_is_gratuitous' : arp_pkt['is_gratuitous'],
        })

    return packet
