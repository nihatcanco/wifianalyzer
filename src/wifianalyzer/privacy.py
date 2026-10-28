"""Where each operating system lets people decide what apps may learn about nearby Wi-Fi.

macOS hides network names and BSSIDs from apps without Location Services permission. Windows 11
hides nearby networks altogether unless desktop apps may use the location. Linux has no such
control.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

log = logging.getLogger(__name__)


def settings_url() -> str | None:
    """The settings page that controls access, or None where there is none."""
    if sys.platform == "darwin":
        return "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"
    if sys.platform == "win32":
        return "ms-settings:privacy-location"
    return None


def settings_path() -> str | None:
    """How to find that page, for instructions."""
    if sys.platform == "darwin":
        return "System Settings › Privacy & Security › Location Services"
    if sys.platform == "win32":
        return "Settings › Privacy & security › Location"
    return None


def open_settings() -> bool:
    """Open the settings page. False if there isn't one or it couldn't be opened."""
    url = settings_url()
    if url is None:
        return False
    try:
        if sys.platform == "win32":
            os.startfile(url)
        else:
            subprocess.run(["/usr/bin/open", url], check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as e:
        log.warning("Couldn't open %s: %s", url, e)
        return False
    return True
