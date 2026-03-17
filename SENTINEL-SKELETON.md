# SENTINEL — Network Intrusion Detection System

> A packet-level IDS built from raw sockets in Python. No libraries for capture or parsing — just the kernel, struct.unpack(), and your own logic.

---

## Repo Structure

```
sentinel/
├── README.md
├── NOTES.md                    ← your learning notes as you build
├── config.yaml                 ← runtime configuration
├── requirements.txt            ← pyyaml (only external dependency)
│
├── src/
│   ├── main.py                 ← entry point — CLI, wires everything together
│   ├── capture.py              ← raw socket setup and packet capture loop
│   │
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── ethernet.py         ← Ethernet frame parser (14 bytes)
│   │   ├── ip.py               ← IPv4 header parser (20+ bytes)
│   │   ├── tcp.py              ← TCP segment parser (20+ bytes)
│   │   ├── udp.py              ← UDP datagram parser (8 bytes)
│   │   └── arp.py              ← ARP packet parser (28 bytes)
│   │
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── port_scan.py        ← detects SYN/FIN/NULL/XMAS scans
│   │   ├── syn_flood.py        ← detects SYN flood by rate per source IP
│   │   └── arp_spoof.py        ← detects ARP cache poisoning attempts
│   │
│   ├── rules.py                ← YAML rules engine — load, parse, match
│   ├── alerts.py               ← alert generation, severity, logging
│   └── dashboard.py            ← terminal UI — live stats and alert feed
│
├── rules/
│   └── default.yaml            ← built-in detection rules
│
├── logs/
│   └── .gitkeep                ← alert logs go here at runtime
│
└── tests/
    ├── test_parsers.py         ← unit tests with hand-crafted byte sequences
    └── samples/
        └── sample.pcap         ← captured packets for offline testing
```

---

## File-by-File Breakdown

### src/main.py — Entry Point

What it does:
- Parses CLI arguments (interface name, config file path, verbosity)
- Loads config.yaml
- Loads detection rules from rules/default.yaml
- Creates the raw socket via capture.py
- Runs the main loop: capture → parse → detect → alert → display
- Handles Ctrl+C gracefully (print summary, close socket)

Key function:
```
main():
    args = parse_args()
    config = load_config(args.config)
    rules = load_rules(config['rules_file'])
    sock = create_socket(config['interface'])
    detectors = [PortScanDetector(), SynFloodDetector(), ArpSpoofDetector()]
    dashboard = Dashboard()

    while True:
        raw_bytes = sock.recvfrom(65535)
        packet = parse_packet(raw_bytes)
        for detector in detectors:
            alerts = detector.check(packet)
            for alert in alerts:
                log_alert(alert)
                dashboard.add_alert(alert)
        dashboard.update(packet)
```

### src/capture.py — Raw Socket Setup

What it does:
- Opens an AF_PACKET raw socket (Linux-specific, needs root/CAP_NET_RAW)
- Binds to a specific network interface
- Sets promiscuous mode so it sees ALL traffic, not just traffic for this host
- Returns raw bytes for each packet

Key concepts:
- socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) — captures everything
- Promiscuous mode via ioctl() call with IFF_PROMISC flag
- This is what Wireshark does under the hood

Why no scapy: You're building this to learn. Scapy hides the byte-level work.

### src/parsers/ethernet.py — Ethernet Frame Parser

What it does:
- Takes raw bytes, unpacks the first 14 bytes
- Extracts: destination MAC (6 bytes), source MAC (6 bytes), EtherType (2 bytes)
- EtherType tells you what's inside: 0x0800 = IPv4, 0x0806 = ARP
- Returns remaining bytes (the payload) for the next parser

Key code pattern:
```
struct.unpack('!6s6sH', raw[:14])
# ! = network byte order (big-endian)
# 6s = 6 bytes as bytes object (MAC address)
# H = unsigned short (2 bytes, EtherType)
```

### src/parsers/ip.py — IPv4 Header Parser

What it does:
- Parses the IPv4 header (minimum 20 bytes, can be longer with options)
- Extracts: version, header length (IHL), TTL, protocol number, source IP, dest IP
- Protocol number tells you what's next: 6 = TCP, 17 = UDP
- IHL field tells you actual header length (IHL × 4 bytes)

Key detail:
- First byte contains BOTH version (4 bits) and IHL (4 bits)
- You need bitwise operations: version = byte >> 4, ihl = byte & 0x0F

### src/parsers/tcp.py — TCP Segment Parser

What it does:
- Parses TCP header (minimum 20 bytes)
- Extracts: source port, dest port, sequence number, ack number, flags
- Flags are critical for detection: SYN, ACK, FIN, RST, PSH, URG
- Data offset field tells you where the payload starts

Key detail:
- Flags live in a single byte, each flag is one bit
- SYN = 0x02, ACK = 0x10, FIN = 0x01, RST = 0x04
- A SYN-only packet (no ACK) = connection initiation = what port scanners send

### src/parsers/udp.py — UDP Datagram Parser

What it does:
- Simplest parser — UDP header is always exactly 8 bytes
- Extracts: source port, dest port, length, checksum
- No flags, no state — UDP is stateless

### src/parsers/arp.py — ARP Packet Parser

What it does:
- Parses ARP packets (28 bytes for IPv4 over Ethernet)
- Extracts: operation (request=1, reply=2), sender MAC, sender IP, target MAC, target IP
- ARP spoofing detection compares these against a known-good ARP cache

### src/detection/port_scan.py — Port Scan Detector

What it does:
- Maintains a dictionary: source_ip → set of destination ports seen
- If one IP touches more than N unique ports within T seconds → alert
- Also detects scan types by TCP flags:
  - SYN scan: SYN flag only, no ACK
  - FIN scan: FIN flag only
  - NULL scan: no flags set
  - XMAS scan: FIN + PSH + URG flags set

State it keeps:
```
connections = {
    '192.168.1.50': {
        'ports': {22, 80, 443, 8080, 3306},
        'first_seen': 1710500000.0,
        'scan_type': 'SYN'
    }
}
```

### src/detection/syn_flood.py — SYN Flood Detector

What it does:
- Counts SYN packets per source IP per time window
- If rate exceeds threshold (e.g., 100 SYNs/second from one IP) → alert
- Uses a sliding window or token bucket approach
- Distinguishes legitimate bursts from sustained floods

State it keeps:
```
syn_counts = {
    '10.0.0.5': {
        'count': 347,
        'window_start': 1710500000.0
    }
}
```

### src/detection/arp_spoof.py — ARP Spoof Detector

What it does:
- Maintains an ARP cache: IP → MAC mapping
- When an ARP reply changes the MAC for a known IP → alert
- Also detects gratuitous ARP (unsolicited replies)
- The gateway IP changing MAC is the classic MITM indicator

State it keeps:
```
arp_table = {
    '192.168.1.1': {
        'mac': 'aa:bb:cc:dd:ee:ff',
        'first_seen': 1710500000.0,
        'reply_count': 3
    }
}
```

### src/rules.py — Rules Engine

What it does:
- Loads YAML rules from rules/default.yaml
- Each rule defines: name, condition (protocol, port, flag pattern, threshold), severity
- Matches incoming parsed packets against rule conditions
- Returns matching rule + alert details

Example rule in YAML:
```yaml
rules:
  - name: "SSH brute force"
    protocol: tcp
    dst_port: 22
    threshold:
      count: 10
      window: 60  # seconds
      group_by: src_ip
    severity: high
    message: "Possible SSH brute force from {src_ip}"

  - name: "DNS amplification"
    protocol: udp
    src_port: 53
    threshold:
      count: 50
      window: 10
      group_by: src_ip
    severity: critical
    message: "DNS amplification attack from {src_ip}"
```

### src/alerts.py — Alert System

What it does:
- Takes detection events and formats them as structured alerts
- Each alert has: timestamp, severity (low/medium/high/critical), source IP, dest IP,
  detection type, human-readable message
- Writes to logs/alerts.log (append mode)
- Also passes alerts to the dashboard for live display

Alert format:
```
[2026-03-15 14:32:07] CRITICAL | SYN_FLOOD | 10.0.0.5 → 192.168.1.10 | 
  347 SYN packets in 2.1s (threshold: 100/s)
```

### src/dashboard.py — Terminal Dashboard

What it does:
- Live-updating terminal UI (using curses or simple ANSI escape codes)
- Shows: packets/second, protocol breakdown (TCP/UDP/ARP/other),
  active alerts, top talkers (IPs by packet count)
- Refreshes every second
- Scrolling alert feed at the bottom

### config.yaml — Runtime Config

```yaml
interface: enp0s3       # network interface to capture on
rules_file: rules/default.yaml
log_file: logs/alerts.log
thresholds:
  port_scan:
    ports: 15           # unique ports before alerting
    window: 60          # seconds
  syn_flood:
    rate: 100           # SYNs per second per source
  arp_spoof:
    enabled: true
dashboard:
  refresh_rate: 1       # seconds
  show_top_talkers: 5
```

---

## Build Order (milestones)

1. **capture.py + main.py** — open socket, print raw hex bytes. Run with sudo, verify you see traffic.
2. **ethernet.py** — parse frames, print src/dst MAC and EtherType for every packet.
3. **ip.py** — parse IP headers, print src/dst IP addresses.
4. **tcp.py + udp.py** — parse transport headers, print ports and flags.
5. **arp.py** — parse ARP packets, print sender/target.
6. At this point you have a working packet sniffer. Test with: `sudo nmap -sS <target>` from another terminal.
7. **port_scan.py** — implement scan detection, test with nmap.
8. **syn_flood.py** — implement flood detection, test with `hping3 -S --flood`.
9. **arp_spoof.py** — implement spoof detection (needs netlab later for proper testing).
10. **rules.py** — add YAML rule loading and matching.
11. **alerts.py** — structured logging to file.
12. **dashboard.py** — terminal UI last, once everything else works.

---

## How to Run

```bash
# basic capture (prints parsed packets)
sudo python3 src/main.py -i enp0s3

# with config
sudo python3 src/main.py -c config.yaml

# verbose mode (shows raw hex + parsed)
sudo python3 src/main.py -i enp0s3 -v
```

## Testing Your Detectors

From a second terminal on the same network:

```bash
# trigger port scan detection
nmap -sS 192.168.1.95

# trigger SYN flood detection
sudo hping3 -S --flood -p 80 192.168.1.95

# generate ARP traffic
arping 192.168.1.95
```

---

## Key Concepts You'll Learn

- **AF_PACKET sockets** — Linux kernel interface for raw packet access
- **struct.unpack()** — converting raw bytes to Python values using format strings
- **Network byte order** — why `!` matters in struct format (big-endian)
- **Protocol layering** — Ethernet wraps IP wraps TCP, each with its own header
- **Stateful detection** — tracking connections over time, not just single packets
- **Sliding windows** — rate-based detection without storing every packet
- **YAML-driven config** — separating detection logic from detection policy

## Connection to Other Projects

- **syswatch** → same /proc reading skills, same ncurses dashboard approach
- **mysh** → you understand process signals (Ctrl+C handling) from building the shell
- **netlab** (next) → netlab generates the attack traffic that sentinel detects
