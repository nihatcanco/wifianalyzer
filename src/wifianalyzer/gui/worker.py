"""Runs scanner calls on a background thread, so a scan of several seconds never freezes the window."""

from __future__ import annotations

import logging
import sys

from PySide6.QtCore import QObject, Signal, Slot

from ..scanner import ScanError, Scanner

log = logging.getLogger(__name__)


class ScanWorker(QObject):
    """Lives on a worker thread. All scanner access goes through here, one call at a time.

    Every request ends in exactly one signal, so the window always learns that it's over.
    """

    scanned = Signal(object)  # ScanResult
    failed = Signal(object)  # ScanError
    polled = Signal(object)  # Connection | None
    poll_failed = Signal(object)  # ScanError

    def __init__(self, scanner: Scanner) -> None:
        super().__init__()
        self._scanner = scanner

    @Slot()
    def thread_started(self) -> None:
        # The VS Code debugger only follows Qt threads for PySide2/PyQt5, so breakpoints in
        # this worker never fire under PySide6 unless the thread is registered by hand.
        debugpy = sys.modules.get("debugpy")
        if debugpy is not None:
            debugpy.debug_this_thread()

    @Slot()
    def scan(self) -> None:
        try:
            result = self._scanner.scan()
        except ScanError as e:
            self.failed.emit(e)
        except Exception as e:  # a bug rather than a scan problem; the window should still recover
            log.exception("Scan failed")
            self.failed.emit(ScanError(f"Unexpected error: {e}"))
        else:
            self.scanned.emit(result)

    @Slot()
    def poll(self) -> None:
        try:
            connection = self._scanner.connection()
        except ScanError as e:
            self.poll_failed.emit(e)
        except Exception as e:
            log.exception("Reading the connection failed")
            self.poll_failed.emit(ScanError(f"Unexpected error: {e}"))
        else:
            self.polled.emit(connection)
