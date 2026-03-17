"""
dashboard.py — Live terminal dashboard using curses.

Layout (terminal rows top-to-bottom):
  ┌─────────────────────────────────────────────────────────────────┐
  │ SENTINEL IDS  │  Interface: eth0  │  Uptime: 00:01:23          │  row 0
  ├─────────────────────────────────────────────────────────────────┤
  │ Packets: 12345  │  Rate: 47/s  │  TCP: 8012  UDP: 3211  ARP: 22 │  row 2
  ├──────────────────┬──────────────────────────────────────────────┤
  │ TOP TALKERS      │  ALERTS (newest first)                       │  row 4
  │ 10.0.0.5  4321   │  14:32:07  CRITICAL  SYN_FLOOD  ...          │  rows 5+
  │ 192.168.1.2 201  │  ...                                         │
  │ ...              │                                              │
  └──────────────────┴──────────────────────────────────────────────┘

The dashboard updates at config.dashboard.refresh_rate seconds.

Curses color pair assignments:
  1  White on black   — normal text
  2  Cyan on black    — header / labels
  3  Green on black   — low-severity alerts and counters
  4  Yellow on black  — medium / high alerts
  5  Red on black     — critical alerts
  6  Black on cyan    — header bar background

Falls back gracefully to no-color output if the terminal does not support
colors (e.g. piped output).
"""

import curses
import time
import threading
from collections import defaultdict, deque


_MAX_ALERTS     = 50   # max entries kept in the alert ring buffer
_PROTO_COLUMNS  = ['TCP', 'UDP', 'ARP', 'ICMP', 'OTHER']

# Severity → curses color pair index
_SEV_COLOR = {
    'low'     : 3,
    'medium'  : 4,
    'high'    : 4,
    'critical': 5,
}


class Dashboard:
    """
    Thread-safe live terminal dashboard.

    Usage:
        dash = Dashboard(config)
        dash.start()          # launches the curses render thread
        ...
        dash.update(packet)   # call from main packet loop
        dash.add_alert(alert) # call from main packet loop
        ...
        dash.stop()           # clean shutdown
    """

    def __init__(self, config: dict, ifname: str = 'unknown') -> None:
        cfg = config.get('dashboard', {})
        self._refresh_rate  = float(cfg.get('refresh_rate',     1.0))
        self._top_n         = int(cfg.get('show_top_talkers',   5))
        self._ifname        = ifname

        self._lock          = threading.Lock()
        self._start_time    = time.time()
        self._running       = False
        self._thread        = None

        # Counters (protected by _lock)
        self._total         = 0
        self._proto_counts  = defaultdict(int)
        self._talkers       = defaultdict(int)   # ip → packet count
        self._alerts        = deque(maxlen=_MAX_ALERTS)

        # Rate tracking
        self._last_total    = 0
        self._last_tick     = time.time()
        self._current_rate  = 0.0

    # ------------------------------------------------------------------
    # Public API (called from main packet loop — thread-safe)
    # ------------------------------------------------------------------

    def update(self, packet: dict) -> None:
        """Record a parsed packet in the counters."""
        with self._lock:
            self._total += 1
            proto = packet.get('proto', 'OTHER')
            self._proto_counts[proto] += 1
            ip = packet.get('ip_src') or packet.get('arp_sender_ip')
            if ip:
                self._talkers[ip] += 1

    def add_alert(self, alert) -> None:
        """Prepend an Alert to the alert feed (newest first)."""
        with self._lock:
            self._alerts.appendleft(alert)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the curses render loop in a background thread."""
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the render thread to stop and wait for it."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    # ------------------------------------------------------------------
    # Curses render loop (runs in background thread)
    # ------------------------------------------------------------------

    def _run(self) -> None:
        try:
            curses.wrapper(self._curses_main)
        except Exception:
            # If curses fails (non-interactive terminal, CI, etc.) fall back
            # to silent mode — main loop still runs, alerts still logged to file
            pass

    def _curses_main(self, stdscr) -> None:
        curses.curs_set(0)      # hide cursor
        stdscr.nodelay(True)    # non-blocking getch
        self._init_colors()

        while self._running:
            try:
                self._render(stdscr)
            except curses.error:
                pass            # terminal resized mid-draw — just retry next tick

            # Sleep in small increments so we exit quickly on stop()
            deadline = time.time() + self._refresh_rate
            while self._running and time.time() < deadline:
                time.sleep(0.05)
                # Allow 'q' to quit
                ch = stdscr.getch()
                if ch in (ord('q'), ord('Q')):
                    self._running = False
                    return

    @staticmethod
    def _init_colors() -> None:
        if not curses.has_colors():
            return
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_WHITE,   -1)   # normal
        curses.init_pair(2, curses.COLOR_CYAN,    -1)   # labels
        curses.init_pair(3, curses.COLOR_GREEN,   -1)   # low
        curses.init_pair(4, curses.COLOR_YELLOW,  -1)   # medium/high
        curses.init_pair(5, curses.COLOR_RED,     -1)   # critical

    def _render(self, stdscr) -> None:
        stdscr.erase()
        max_rows, max_cols = stdscr.getmaxyx()

        with self._lock:
            total         = self._total
            proto_counts  = dict(self._proto_counts)
            talkers       = dict(self._talkers)
            alerts        = list(self._alerts)
            now           = time.time()

        # Compute rate
        elapsed_tick = now - self._last_tick
        if elapsed_tick >= 1.0:
            self._current_rate = (total - self._last_total) / elapsed_tick
            self._last_total   = total
            self._last_tick    = now

        uptime = int(now - self._start_time)
        h, m, s = uptime // 3600, (uptime % 3600) // 60, uptime % 60

        C = lambda n: curses.color_pair(n) if curses.has_colors() else 0

        # Row 0 — header bar
        header = (
            f' SENTINEL IDS  |  Interface: {self._ifname}'
            f'  |  Uptime: {h:02d}:{m:02d}:{s:02d} '
        ).ljust(max_cols - 1)
        self._addstr(stdscr, 0, 0, header, C(2) | curses.A_BOLD, max_cols)

        # Row 1 — separator
        self._addstr(stdscr, 1, 0, '─' * (max_cols - 1), C(2), max_cols)

        # Row 2 — stats
        tcp = proto_counts.get('TCP', 0)
        udp = proto_counts.get('UDP', 0)
        arp = proto_counts.get('ARP', 0)
        icmp= proto_counts.get('ICMP',0)
        stats_line = (
            f' Packets: {total:,}  |  Rate: {self._current_rate:.0f}/s  |'
            f'  TCP: {tcp:,}  UDP: {udp:,}  ARP: {arp:,}  ICMP: {icmp:,}'
        )
        self._addstr(stdscr, 2, 0, stats_line[:max_cols - 1], C(1), max_cols)

        # Row 3 — separator
        self._addstr(stdscr, 3, 0, '─' * (max_cols - 1), C(2), max_cols)

        # Split remaining area: left 28 cols for talkers, rest for alerts
        left_width  = min(30, max_cols // 3)
        right_start = left_width + 1
        right_width = max_cols - right_start - 1
        content_rows = max_rows - 6   # rows available below header (row 4+)

        # Row 4 — section labels
        self._addstr(stdscr, 4, 0,            f' TOP TALKERS',       C(2) | curses.A_BOLD, left_width)
        if right_start < max_cols - 1:
            self._addstr(stdscr, 4, right_start, ' ALERTS (newest first)', C(2) | curses.A_BOLD, right_width)

        # Row 5 — sub-separator
        self._addstr(stdscr, 5, 0, '─' * (max_cols - 1), C(2), max_cols)

        # Top talkers
        sorted_talkers = sorted(talkers.items(), key=lambda x: x[1], reverse=True)
        for i, (ip, count) in enumerate(sorted_talkers[:self._top_n]):
            row = 6 + i
            if row >= max_rows - 1:
                break
            line = f' {ip:<18} {count:>7,}'
            self._addstr(stdscr, row, 0, line[:left_width], C(1), left_width)

        # Vertical divider
        for row in range(4, max_rows - 1):
            if left_width < max_cols - 1:
                try:
                    stdscr.addch(row, left_width, curses.ACS_VLINE)
                except curses.error:
                    pass

        # Alert feed
        for i, alert in enumerate(alerts):
            row = 6 + i
            if row >= max_rows - 1 or right_start >= max_cols - 1:
                break
            sev     = getattr(alert, 'severity', 'low').lower()
            color   = C(_SEV_COLOR.get(sev, 1))
            display = getattr(alert, 'format_display', lambda: str(alert))()
            self._addstr(stdscr, row, right_start, display[:right_width], color, right_width)

        # Bottom status bar
        bottom_row = max_rows - 1
        bottom = f' [q] quit  |  {len(alerts)} alert(s) '.ljust(max_cols - 1)
        self._addstr(stdscr, bottom_row, 0, bottom, C(2), max_cols)

        stdscr.refresh()

    @staticmethod
    def _addstr(stdscr, row: int, col: int, text: str,
                attr: int, max_width: int) -> None:
        """Safe addstr that won't raise on out-of-bounds writes."""
        try:
            stdscr.addstr(row, col, text[:max_width], attr)
        except curses.error:
            pass
