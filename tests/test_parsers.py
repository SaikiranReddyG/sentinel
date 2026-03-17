"""
test_parsers.py — Unit tests for all protocol parsers and detection engines.

All tests use hand-crafted byte sequences — no live network, no root required.
Run with:
    python3 -m pytest tests/ -v
"""

import struct
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from src.parsers import ethernet, ip, tcp, udp, arp
from src.parsers.packet import parse_packet
from src.parsers.tcp import SYN, FIN, PSH, ACK, URG
from src.detection.port_scan import PortScanDetector
from src.detection.syn_flood import SynFloodDetector
from src.detection.arp_spoof import ArpSpoofDetector
from src.alerts import Alert, AlertLogger, dict_to_alert
from src.rules import load_rules, RulesMatcher


# ===========================================================================
# Helpers — byte-level frame builders
# ===========================================================================

def _mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(':'))


def _ip4(s: str) -> bytes:
    return bytes(int(x) for x in s.split('.'))


def build_ethernet(dst='ff:ff:ff:ff:ff:ff', src='aa:bb:cc:dd:ee:ff', ethertype=0x0800, payload=b'') -> bytes:
    return struct.pack('!6s6sH', _mac(dst), _mac(src), ethertype) + payload


def build_ipv4(src='10.0.0.1', dst='10.0.0.2', protocol=6, payload=b'') -> bytes:
    ihl     = 5              # no options — 20 bytes
    version = 4
    ver_ihl = (version << 4) | ihl
    total   = 20 + len(payload)
    ttl     = 64
    return (
        struct.pack('!BB', ver_ihl, 0)       # ver_ihl, DSCP
        + struct.pack('!H', total)            # total length
        + struct.pack('!HH', 0, 0)            # ident, flags+frag
        + struct.pack('!BB', ttl, protocol)   # ttl, protocol
        + struct.pack('!H', 0)                # checksum (0 = skip)
        + _ip4(src) + _ip4(dst)
        + payload
    )


def build_tcp(src_port=12345, dst_port=80, seq=0, ack=0, flags=SYN, window=65535, payload=b'') -> bytes:
    data_offset = 5    # 20 bytes, no options
    data_off_byte = (data_offset << 4)
    return (
        struct.pack('!HH', src_port, dst_port)
        + struct.pack('!II', seq, ack)
        + struct.pack('!BB', data_off_byte, flags)
        + struct.pack('!HHH', window, 0, 0)  # window, checksum, urgent
        + payload
    )


def build_udp(src_port=12345, dst_port=53, payload=b'') -> bytes:
    length = 8 + len(payload)
    return struct.pack('!HHHH', src_port, dst_port, length, 0) + payload


def build_arp(op=2,
              sender_mac='aa:bb:cc:dd:ee:ff', sender_ip='192.168.1.1',
              target_mac='00:00:00:00:00:00', target_ip='192.168.1.2') -> bytes:
    return struct.pack(
        '!HHBBH6s4s6s4s',
        1,          # htype  = Ethernet
        0x0800,     # ptype  = IPv4
        6,          # hlen
        4,          # plen
        op,
        _mac(sender_mac), _ip4(sender_ip),
        _mac(target_mac), _ip4(target_ip),
    )


# ===========================================================================
# Ethernet parser
# ===========================================================================

class TestEthernet:
    def test_basic_parse(self):
        raw = build_ethernet(dst='ff:ff:ff:ff:ff:ff', src='aa:bb:cc:dd:ee:ff',
                              ethertype=0x0800, payload=b'\x01\x02')
        result = ethernet.parse(raw)
        assert result is not None
        assert result['dst_mac']    == 'ff:ff:ff:ff:ff:ff'
        assert result['src_mac']    == 'aa:bb:cc:dd:ee:ff'
        assert result['ethertype']  == 0x0800
        assert result['payload']    == b'\x01\x02'

    def test_arp_ethertype(self):
        raw = build_ethernet(ethertype=0x0806, payload=b'x' * 28)
        result = ethernet.parse(raw)
        assert result['ethertype'] == 0x0806

    def test_too_short_returns_none(self):
        assert ethernet.parse(b'\x00' * 13) is None

    def test_empty_returns_none(self):
        assert ethernet.parse(b'') is None


# ===========================================================================
# IPv4 parser
# ===========================================================================

class TestIPv4:
    def test_basic_parse(self):
        raw = build_ipv4(src='10.0.0.1', dst='192.168.1.10', protocol=6,
                         payload=b'\xde\xad')
        result = ip.parse(raw)
        assert result is not None
        assert result['src_ip']    == '10.0.0.1'
        assert result['dst_ip']    == '192.168.1.10'
        assert result['protocol']  == 6
        assert result['version']   == 4
        assert result['ihl']       == 20
        assert result['payload']   == b'\xde\xad'

    def test_ttl_extracted(self):
        raw = build_ipv4(protocol=17)
        result = ip.parse(raw)
        assert result['ttl'] == 64

    def test_too_short_returns_none(self):
        assert ip.parse(b'\x00' * 19) is None

    def test_bad_version_returns_none(self):
        raw = bytearray(build_ipv4())
        raw[0] = 0x60  # set version to 6 (IPv6)
        assert ip.parse(bytes(raw)) is None


# ===========================================================================
# TCP parser
# ===========================================================================

class TestTCP:
    def test_syn_only(self):
        raw = build_tcp(src_port=54321, dst_port=22, flags=SYN)
        result = tcp.parse(raw)
        assert result is not None
        assert result['src_port']  == 54321
        assert result['dst_port']  == 22
        assert result['flags']     == SYN
        assert 'SYN' in result['flags_str']
        assert 'ACK' not in result['flags_str']

    def test_syn_ack(self):
        raw = build_tcp(flags=SYN | ACK)
        result = tcp.parse(raw)
        assert result['flags'] == SYN | ACK
        assert 'SYN' in result['flags_str']
        assert 'ACK' in result['flags_str']

    def test_fin_scan(self):
        raw = build_tcp(flags=FIN)
        result = tcp.parse(raw)
        assert result['flags'] == FIN

    def test_null_scan(self):
        raw = build_tcp(flags=0x00)
        result = tcp.parse(raw)
        assert result['flags'] == 0x00
        assert result['flags_str'] == 'NONE'

    def test_xmas_scan(self):
        raw = build_tcp(flags=FIN | PSH | URG)
        result = tcp.parse(raw)
        assert result['flags'] == FIN | PSH | URG

    def test_scan_type_classification(self):
        from src.parsers.tcp import scan_type
        assert scan_type(SYN)            == 'SYN'
        assert scan_type(FIN)            == 'FIN'
        assert scan_type(0x00)           == 'NULL'
        assert scan_type(FIN | PSH | URG) == 'XMAS'
        assert scan_type(SYN | ACK)      is None

    def test_too_short_returns_none(self):
        assert tcp.parse(b'\x00' * 19) is None


# ===========================================================================
# UDP parser
# ===========================================================================

class TestUDP:
    def test_basic_parse(self):
        raw = build_udp(src_port=1025, dst_port=53, payload=b'dns_query')
        result = udp.parse(raw)
        assert result is not None
        assert result['src_port'] == 1025
        assert result['dst_port'] == 53
        assert result['length']   == 8 + len(b'dns_query')
        assert result['payload']  == b'dns_query'

    def test_too_short_returns_none(self):
        assert udp.parse(b'\x00' * 7) is None

    def test_empty_payload(self):
        raw = build_udp(src_port=0, dst_port=0)
        result = udp.parse(raw)
        assert result['payload'] == b''


# ===========================================================================
# ARP parser
# ===========================================================================

class TestARP:
    def test_arp_reply(self):
        raw = build_arp(op=2, sender_mac='aa:bb:cc:dd:ee:ff',
                        sender_ip='192.168.1.1',
                        target_ip='192.168.1.2')
        result = arp.parse(raw)
        assert result is not None
        assert result['operation']   == 2
        assert result['sender_mac']  == 'aa:bb:cc:dd:ee:ff'
        assert result['sender_ip']   == '192.168.1.1'
        assert result['target_ip']   == '192.168.1.2'

    def test_arp_request(self):
        raw = build_arp(op=1)
        result = arp.parse(raw)
        assert result['operation'] == 1

    def test_gratuitous_arp(self):
        raw = build_arp(op=2, sender_ip='192.168.1.1', target_ip='192.168.1.1')
        result = arp.parse(raw)
        assert result['is_gratuitous'] is True

    def test_non_gratuitous(self):
        raw = build_arp(op=2, sender_ip='192.168.1.1', target_ip='192.168.1.2')
        result = arp.parse(raw)
        assert result['is_gratuitous'] is False

    def test_too_short_returns_none(self):
        assert arp.parse(b'\x00' * 27) is None


# ===========================================================================
# Packet dispatcher (parse_packet)
# ===========================================================================

class TestParsePacket:
    def _tcp_frame(self, src_ip='10.0.0.1', dst_ip='10.0.0.2',
                   src_port=1234, dst_port=80, flags=SYN) -> bytes:
        tcp_seg = build_tcp(src_port=src_port, dst_port=dst_port, flags=flags)
        ip_pkt  = build_ipv4(src=src_ip, dst=dst_ip, protocol=6, payload=tcp_seg)
        return build_ethernet(ethertype=0x0800, payload=ip_pkt)

    def _udp_frame(self, src_port=1025, dst_port=53) -> bytes:
        udp_dg = build_udp(src_port=src_port, dst_port=dst_port)
        ip_pkt = build_ipv4(protocol=17, payload=udp_dg)
        return build_ethernet(ethertype=0x0800, payload=ip_pkt)

    def _arp_frame(self, op=2, sender_ip='10.0.0.1', target_ip='10.0.0.2') -> bytes:
        arp_pkt = build_arp(op=op, sender_ip=sender_ip, target_ip=target_ip)
        return build_ethernet(ethertype=0x0806, payload=arp_pkt)

    def test_tcp_packet(self):
        frame  = self._tcp_frame(src_ip='10.0.0.5', dst_ip='10.0.0.6',
                                  dst_port=22, flags=SYN)
        packet = parse_packet(frame)
        assert packet is not None
        assert packet['proto']         == 'TCP'
        assert packet['ip_src']        == '10.0.0.5'
        assert packet['ip_dst']        == '10.0.0.6'
        assert packet['tcp_dst_port']  == 22
        assert packet['tcp_flags']     == SYN

    def test_udp_packet(self):
        frame  = self._udp_frame(dst_port=53)
        packet = parse_packet(frame)
        assert packet['proto']         == 'UDP'
        assert packet['udp_dst_port']  == 53

    def test_arp_packet(self):
        frame  = self._arp_frame(op=2, sender_ip='192.168.1.1')
        packet = parse_packet(frame)
        assert packet['proto']          == 'ARP'
        assert packet['arp_operation']  == 2
        assert packet['arp_sender_ip']  == '192.168.1.1'

    def test_malformed_returns_none(self):
        assert parse_packet(b'\x00' * 5) is None


# ===========================================================================
# PortScanDetector
# ===========================================================================

class TestPortScanDetector:
    _config = {'thresholds': {'port_scan': {'ports': 5, 'window': 60}}}

    def _syn_packet(self, src_ip='10.0.0.1', dst_port=80) -> dict:
        return {
            'proto'       : 'TCP',
            'ip_src'      : src_ip,
            'ip_dst'      : '10.0.0.2',
            'tcp_dst_port': dst_port,
            'tcp_flags'   : SYN,
        }

    def test_no_alert_below_threshold(self):
        d = PortScanDetector(self._config)
        alerts = []
        for port in range(1, 5):   # 4 ports < threshold of 5
            alerts.extend(d.check(self._syn_packet(dst_port=port)))
        assert alerts == []

    def test_alert_at_threshold(self):
        d = PortScanDetector(self._config)
        alerts = []
        for port in range(1, 7):   # 6 unique ports >= threshold of 5
            alerts.extend(d.check(self._syn_packet(dst_port=port)))
        assert len(alerts) == 1
        assert alerts[0]['detection_type'] == 'PORT_SCAN'
        assert alerts[0]['severity']       == 'high'

    def test_no_double_alert_same_window(self):
        d = PortScanDetector(self._config)
        alerts = []
        for port in range(1, 20):  # well over threshold
            alerts.extend(d.check(self._syn_packet(dst_port=port)))
        # Should alert exactly once per window
        assert len(alerts) == 1

    def test_syn_scan_type(self):
        d = PortScanDetector(self._config)
        alerts = []
        for port in range(1, 7):
            alerts.extend(d.check(self._syn_packet(dst_port=port)))
        assert 'SYN' in alerts[0]['message']

    def test_xmas_scan_detected(self):
        d = PortScanDetector(self._config)
        alerts = []
        for port in range(1, 7):
            pkt = self._syn_packet(dst_port=port)
            pkt['tcp_flags'] = FIN | PSH | URG
            alerts.extend(d.check(pkt))
        assert len(alerts) == 1
        assert 'XMAS' in alerts[0]['message']

    def test_non_tcp_ignored(self):
        d = PortScanDetector(self._config)
        alerts = d.check({'proto': 'UDP', 'ip_src': '10.0.0.1'})
        assert alerts == []

    def test_ack_only_not_classified_as_scan(self):
        d = PortScanDetector(self._config)
        alerts = []
        for port in range(1, 7):
            pkt = {'proto': 'TCP', 'ip_src': '10.0.0.1', 'ip_dst': '10.0.0.2',
                   'tcp_dst_port': port, 'tcp_flags': ACK}
            alerts.extend(d.check(pkt))
        assert alerts == []


# ===========================================================================
# SynFloodDetector
# ===========================================================================

class TestSynFloodDetector:
    _config = {'thresholds': {'syn_flood': {'rate': 10, 'window': 5}}}

    def _syn_packet(self, src_ip='10.0.0.5', dst_ip='10.0.0.2') -> dict:
        return {
            'proto'      : 'TCP',
            'ip_src'     : src_ip,
            'ip_dst'     : dst_ip,
            'tcp_flags'  : SYN,
        }

    def test_no_alert_below_rate(self):
        d = SynFloodDetector(self._config)
        # Only 3 SYNs — well below rate threshold of 10/s
        alerts = []
        for _ in range(3):
            alerts.extend(d.check(self._syn_packet()))
        assert alerts == []

    def test_syn_ack_ignored(self):
        d = SynFloodDetector(self._config)
        alerts = []
        for _ in range(100):
            pkt = self._syn_packet()
            pkt['tcp_flags'] = SYN | ACK
            alerts.extend(d.check(pkt))
        assert alerts == []

    def test_non_tcp_ignored(self):
        d = SynFloodDetector(self._config)
        alerts = d.check({'proto': 'UDP', 'ip_src': '1.2.3.4'})
        assert alerts == []


# ===========================================================================
# ArpSpoofDetector
# ===========================================================================

class TestArpSpoofDetector:
    _config = {'thresholds': {'arp_spoof': {'enabled': True, 'cooldown': 0}}}

    def _arp_pkt(self, sender_ip, sender_mac, op=2,
                 target_ip='192.168.1.2', is_gratuitous=False) -> dict:
        return {
            'proto'            : 'ARP',
            'arp_operation'    : op,
            'arp_sender_ip'    : sender_ip,
            'arp_sender_mac'   : sender_mac,
            'arp_target_ip'    : target_ip,
            'arp_is_gratuitous': is_gratuitous,
        }

    def test_no_alert_first_seen(self):
        d = ArpSpoofDetector(self._config)
        alerts = d.check(self._arp_pkt('192.168.1.1', 'aa:bb:cc:dd:ee:ff'))
        assert alerts == []

    def test_alert_on_mac_change(self):
        d = ArpSpoofDetector(self._config)
        d.check(self._arp_pkt('192.168.1.1', 'aa:bb:cc:dd:ee:ff'))
        alerts = d.check(self._arp_pkt('192.168.1.1', '11:22:33:44:55:66'))
        assert len(alerts) == 1
        assert alerts[0]['detection_type'] == 'ARP_SPOOF'
        assert '192.168.1.1' in alerts[0]['message']

    def test_no_alert_same_mac(self):
        d = ArpSpoofDetector(self._config)
        d.check(self._arp_pkt('192.168.1.1', 'aa:bb:cc:dd:ee:ff'))
        alerts = d.check(self._arp_pkt('192.168.1.1', 'aa:bb:cc:dd:ee:ff'))
        assert alerts == []

    def test_disabled_produces_no_alerts(self):
        cfg = {'thresholds': {'arp_spoof': {'enabled': False}}}
        d = ArpSpoofDetector(cfg)
        d.check(self._arp_pkt('10.0.0.1', 'aa:aa:aa:aa:aa:aa'))
        alerts = d.check(self._arp_pkt('10.0.0.1', 'bb:bb:bb:bb:bb:bb'))
        assert alerts == []

    def test_arp_table_populated(self):
        d = ArpSpoofDetector(self._config)
        d.check(self._arp_pkt('10.0.0.1', 'de:ad:be:ef:00:01'))
        tbl = d.get_arp_table()
        assert '10.0.0.1' in tbl
        assert tbl['10.0.0.1']['mac'] == 'de:ad:be:ef:00:01'


# ===========================================================================
# AlertLogger
# ===========================================================================

class TestAlertLogger:
    def test_write_and_deduplicate(self, tmp_path):
        log_file = str(tmp_path / 'test_alerts.log')
        logger   = AlertLogger(log_file, cooldown=60.0)

        alert = Alert(
            detection_type='PORT_SCAN',
            severity='high',
            src_ip='1.2.3.4',
            dst_ip='5.6.7.8',
            message='test alert',
        )

        written1 = logger.log(alert)
        written2 = logger.log(alert)  # same key, within cooldown

        assert written1 is True
        assert written2 is False

        with open(log_file) as fh:
            lines = fh.readlines()
        assert len(lines) == 1
        assert 'PORT_SCAN' in lines[0]
        assert '1.2.3.4' in lines[0]

    def test_different_types_both_logged(self, tmp_path):
        log_file = str(tmp_path / 'alerts2.log')
        logger   = AlertLogger(log_file, cooldown=60.0)

        a1 = dict_to_alert({'detection_type': 'PORT_SCAN', 'severity': 'high',
                             'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'message': 'scan'})
        a2 = dict_to_alert({'detection_type': 'SYN_FLOOD', 'severity': 'critical',
                             'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'message': 'flood'})

        logger.log(a1)
        logger.log(a2)

        with open(log_file) as fh:
            lines = fh.readlines()
        assert len(lines) == 2


# ===========================================================================
# RulesMatcher
# ===========================================================================

class TestRulesMatcher:
    _rules_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rules', 'default.yaml')

    def test_rules_load(self):
        rules = load_rules(self._rules_file)
        assert len(rules) > 0

    def test_ssh_rule_fires_at_threshold(self):
        rules   = load_rules(self._rules_file)
        matcher = RulesMatcher(rules)

        # Find the SSH rule
        ssh_rule = next(r for r in rules if r.dst_port == 22 and r.protocol == 'tcp')
        threshold = ssh_rule.threshold_count

        packets_sent = 0
        alerts       = []
        for _ in range(threshold + 1):
            pkt = {
                'proto'       : 'TCP',
                'ip_src'      : '10.0.0.99',
                'ip_dst'      : '10.0.0.1',
                'tcp_src_port': 54321,
                'tcp_dst_port': 22,
                'tcp_flags'   : SYN,
            }
            alerts.extend(matcher.match(pkt))
            packets_sent += 1

        assert len(alerts) >= 1
        assert any('ssh' in a['detection_type'].lower() or 'SSH' in a['message'] for a in alerts)

    def test_wrong_protocol_no_match(self):
        rules   = load_rules(self._rules_file)
        matcher = RulesMatcher(rules)
        # Send UDP packet to port 22 — should not match the TCP SSH rule
        for _ in range(20):
            pkt = {
                'proto'       : 'UDP',
                'ip_src'      : '10.0.0.1',
                'ip_dst'      : '10.0.0.2',
                'udp_src_port': 54321,
                'udp_dst_port': 22,
            }
            alerts = matcher.match(pkt)
            # No TCP rule should fire on UDP traffic
            tcp_alerts = [a for a in alerts if 'SSH' in a.get('message', '')]
            assert tcp_alerts == []
