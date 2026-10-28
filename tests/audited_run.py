"""Runs the desktop app on a fake scan and reports every attempt it makes to reach the network.

test_offline.py runs this as a script in a process of its own, because an audit hook can't be
removed once it's added. The hook goes in before anything is imported, so it sees import-time
activity too, and it watches every thread, including the scan worker.
"""

import json
import socket
import sys
import time
from pathlib import Path

# Netlink and Unix sockets never leave the computer.
LOCAL_FAMILIES = {getattr(socket, name) for name in ("AF_UNIX", "AF_NETLINK") if hasattr(socket, name)}
NAME_LOOKUPS = {"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo"}
OPENERS = {
    "webbrowser.open", "os.startfile", "urllib.Request", "http.client.connect",
    "ftplib.connect", "smtplib.connect", "imaplib.open", "poplib.connect",
}  # fmt: skip
attempts: list[str] = []


def watch(event: str, args: tuple[object, ...]) -> None:
    if event == "socket.__new__" and args[1] not in LOCAL_FAMILIES:
        attempts.append(f"{event}: address family {args[1]}")
    elif event in ("socket.connect", "socket.sendto") and getattr(args[0], "family", None) not in LOCAL_FAMILIES:
        attempts.append(f"{event}: {args[1]!r}")
    elif event in NAME_LOOKUPS or event in OPENERS:
        attempts.append(f"{event}: {args!r}")


sys.addaudithook(watch)


def main(folder: Path) -> dict[str, object]:
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication, QFileDialog

    from factories import make_connection, make_network
    from wifianalyzer.gui.window import MainWindow
    from wifianalyzer.models import Band, ScanResult
    from wifianalyzer.scanner import Scanner

    networks = [
        make_network(36, -52, Band.GHZ_5, 80, ssid="Home", bssid="02:00:00:00:00:01", is_current=True),
        make_network(1, -60, ssid="<b>Neighbour</b>", bssid="02:00:00:00:00:02"),
        make_network(52, -70, Band.GHZ_5, 40, ssid="Cafe", bssid="02:00:00:00:00:03"),
        make_network(37, -75, Band.GHZ_6, 160, ssid="Office", bssid="02:00:00:00:00:04"),
    ]
    result = ScanResult("wlan0", networks, make_connection(36, -52, ssid="Home", bssid="02:00:00:00:00:01"))

    class FakeScanner(Scanner):
        name = "wlan0"

        def scan(self):
            return result

        def connection(self):
            return result.connection

    app = QApplication([])
    settings = QSettings(str(folder / "settings.ini"), QSettings.Format.IniFormat)
    window = MainWindow(FakeScanner(), settings=settings)
    window.show()
    deadline = time.monotonic() + 10
    while window._result is None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    for band in Band:
        window.select_band(band)
        window.grab()
    saved = folder / "scan.json"
    QFileDialog.getSaveFileName = lambda *_: (str(saved), "")
    window.save_action.trigger()
    window.close()
    return {"scanned": window._result is not None, "saved": saved.exists(), "attempts": attempts}


if __name__ == "__main__":
    sys.stdout.write(json.dumps(main(Path(sys.argv[1]))))
