"""Renders the README screenshots from made-up networks, in light and dark mode.

    python scripts/screenshot.py

Real scans name the networks around you, which shows where you are, so the screenshots never
come from one. The window is drawn offscreen at twice its size, for high-density displays.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ["QT_SCALE_FACTOR"] = "2"

from PySide6.QtCore import QSettings, QTemporaryDir
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

from wifianalyzer.gui import theme
from wifianalyzer.gui.icon import app_icon
from wifianalyzer.gui.window import MainWindow
from wifianalyzer.models import Band, Connection, Network, ScanResult
from wifianalyzer.scanner import Scanner

DOCS = Path(__file__).resolve().parent.parent / "docs"
G24, G5, G6 = Band.GHZ_2_4, Band.GHZ_5, Band.GHZ_6

# Name, band, channel, width, signal, security and standard. BSSIDs are locally administered
# addresses, which no manufacturer assigns.
NETWORKS = [
    ("Hearth", G5, 36, 80, -47, "WPA2/WPA3", "802.11ax"),
    ("Hearth Guest", G5, 36, 80, -48, "WPA2", "802.11ax"),
    ("Willow", G5, 44, 80, -66, "WPA2", "802.11ac"),
    ("Orchard", G5, 60, 20, -81, "WPA2", "802.11ac"),
    ("Juniper", G5, 100, 160, -77, "WPA3", "802.11ax"),
    ("Atlas", G5, 149, 80, -70, "WPA2/WPA3", "802.11ax"),
    ("Lighthouse", G5, 157, 80, -83, "WPA3", "802.11be"),
    ("Hearth", G24, 6, 20, -52, "WPA2/WPA3", "802.11ax"),
    ("Willow", G24, 1, 20, -63, "WPA2", "802.11n"),
    ("Bramble", G24, 1, 20, -74, "WPA2", "802.11n"),
    ("Atlas", G24, 6, 40, -69, "WPA2/WPA3", "802.11ax"),
    ("Juniper", G24, 11, 20, -71, "WPA3", "802.11ax"),
    ("Kettle", G24, 11, 20, -86, "WPA/WPA2", "802.11g"),
    ("Printer Setup", G24, 6, 20, -80, "Open", "802.11n"),
    ("Hearth", G6, 37, 160, -61, "WPA3", "802.11ax"),
    ("Lighthouse", G6, 5, 320, -79, "WPA3", "802.11be"),
]


def scan_result() -> ScanResult:
    networks = [
        Network(
            ssid=ssid,
            bssid=f"02:00:00:00:00:{i:02x}",
            rssi=rssi,
            noise=-92 if i == 1 else None,
            band=band,
            channel=channel,
            width=width,
            security=security,
            phy=phy,
            is_current=i == 1,
        )
        for i, (ssid, band, channel, width, rssi, security, phy) in enumerate(NETWORKS, start=1)
    ]
    connection = Connection(
        ssid="Hearth",
        bssid="02:00:00:00:00:01",
        rssi=-47,
        noise=-92,
        tx_rate=1201.0,
        band=G5,
        channel=36,
        width=80,
        security="WPA3",
        phy="802.11ax",
    )
    return ScanResult("en0", networks, connection, country="NL")


class DemoScanner(Scanner):
    name = "en0"

    def __init__(self) -> None:
        self.result = scan_result()

    def scan(self) -> ScanResult:
        return self.result

    def connection(self) -> Connection | None:
        return self.result.connection


def dark_palette() -> QPalette:
    """The colors the system gives Qt's own widgets in dark mode, which the offscreen platform doesn't."""
    t, role = theme.DARK, QPalette.ColorRole
    palette = QPalette()
    for color, roles in (
        (t.page, [role.Window]),
        (t.surface, [role.Base, role.AlternateBase, role.Button, role.ToolTipBase]),
        (t.text, [role.WindowText, role.Text, role.ButtonText, role.ToolTipText, role.BrightText]),
        (t.muted, [role.PlaceholderText]),
        (t.accent, [role.Highlight]),
        ("#ffffff", [role.HighlightedText]),
        (t.border, [role.Mid, role.Dark, role.Shadow]),
        (t.axis, [role.Light, role.Midlight]),
    ):
        for r in roles:
            palette.setColor(r, QColor(color))
    return palette


def capture(app: QApplication, dark: bool, folder: str) -> None:
    theme.current = lambda: theme.DARK if dark else theme.LIGHT
    app.setPalette(dark_palette() if dark else app.style().standardPalette())
    settings = QSettings(f"{folder}/{dark}.ini", QSettings.Format.IniFormat)
    window = MainWindow(DemoScanner(), autostart=False, settings=settings)
    window.resize(1280, 940)
    window.show()
    window.apply_result(window._scanner.scan())
    # Five minutes of a steady link with a short dip, as the history card shows it.
    now = time.time()
    window._history.clear()
    for age in range(300, -1, -2):
        dip = 9 if 150 < age < 170 else 0
        window._history.append((now - age, -47 - (age * 7 % 5) // 2 - dip))
    window.history_chart.set_samples(window._history)
    app.processEvents()
    path = DOCS / f"screenshot-{'dark' if dark else 'light'}.png"
    window.grab().save(str(path))
    window.close()
    sys.stdout.write(f"{path}\n")


def main() -> None:
    app = QApplication([])
    QApplication.setWindowIcon(app_icon())
    DOCS.mkdir(exist_ok=True)
    folder = QTemporaryDir()  # keeps the window's settings away from the real ones
    for dark in (False, True):
        capture(app, dark, folder.path())


if __name__ == "__main__":
    main()
