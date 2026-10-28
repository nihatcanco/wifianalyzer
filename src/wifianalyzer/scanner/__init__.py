"""Wi-Fi scanning, with a backend for each operating system.

- macOS: CoreWLAN (``corewlan``)
- Windows: the Native Wifi API in wlanapi.dll (``wlanapi``)
- Linux: nl80211, the kernel's Wi-Fi driver interface, over netlink (``nl80211``)
"""

from __future__ import annotations

import sys

from .base import AccessDeniedError, ScanError, Scanner, mark_current

__all__ = ["AccessDeniedError", "ScanError", "Scanner", "mark_current", "open_scanner"]


def open_scanner(interface: str | None = None) -> Scanner:
    """A scanner for ``interface``, or for the system's Wi-Fi interface when None."""
    if sys.platform == "darwin":
        from .corewlan import CoreWLANScanner

        return CoreWLANScanner(interface)
    if sys.platform == "win32":
        from .wlanapi import WlanApiScanner

        return WlanApiScanner(interface)
    if sys.platform.startswith("linux"):
        from .nl80211 import Nl80211Scanner

        return Nl80211Scanner(interface)
    raise ScanError(f"Scanning isn't supported on this operating system ({sys.platform})")
