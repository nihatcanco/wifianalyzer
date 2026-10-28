"""The desktop app, built with Qt (PySide6)."""

from __future__ import annotations

import argparse
import logging
import sys
import traceback
from collections.abc import Sequence
from types import TracebackType

from .. import APP_NAME, __version__
from ..macos import bundle

log = logging.getLogger(__name__)


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        bundle.exec_in_app("wifianalyzer.gui", sys.argv[1:])
        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(prog="wifianalyzer", description=APP_NAME)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-i", "--interface", help="Wi-Fi interface to use (default: the system's Wi-Fi interface)")
    parser.add_argument("-v", "--verbose", action="store_true", help="log what's happening to stderr")
    parser.add_argument(
        "--request-location",
        action="store_true",
        help="ask for Location access right away" if sys.platform == "darwin" else argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    return run(args.interface, request_location=args.request_location)


def run(interface: str | None = None, *, request_location: bool = False) -> int:
    from PySide6.QtWidgets import QApplication, QMessageBox

    from ..scanner import ScanError, open_scanner
    from .icon import app_icon
    from .window import MainWindow

    app = QApplication.instance() or QApplication(sys.argv[:1])
    QApplication.setApplicationName("wifianalyzer")
    QApplication.setApplicationDisplayName(APP_NAME)
    QApplication.setApplicationVersion(__version__)
    QApplication.setOrganizationName("wifianalyzer")
    QApplication.setDesktopFileName("wifianalyzer")
    QApplication.setWindowIcon(app_icon())
    _show_unexpected_errors()
    try:
        scanner = open_scanner(interface)
    except ScanError as e:
        QMessageBox.critical(None, APP_NAME, str(e))
        return 1
    try:
        window = MainWindow(scanner, request_location=request_location)
        window.show()
        return app.exec()
    finally:
        scanner.close()


def _show_unexpected_errors() -> None:
    """Report an unexpected exception in a dialog: started from an icon, the app has no terminal.

    Only the first is shown, so a bug in painting code can't open a dialog on every repaint.
    """
    shown = False

    def hook(kind: type[BaseException], value: BaseException, tb: TracebackType | None) -> None:
        nonlocal shown
        log.error("Unexpected error", exc_info=(kind, value, tb))
        if shown or issubclass(kind, KeyboardInterrupt):
            return
        shown = True
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QMessageBox

        box = QMessageBox(QMessageBox.Icon.Critical, APP_NAME, f"Something went wrong: {value}")
        box.setTextFormat(Qt.TextFormat.PlainText)  # message boxes open links in rich text
        box.setInformativeText("The app keeps running, but it may not work as expected.")
        box.setDetailedText("".join(traceback.format_exception(kind, value, tb)))
        box.exec()

    sys.excepthook = hook
