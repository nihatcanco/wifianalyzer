"""Choosing the backend and the settings page for the operating system."""

import subprocess
import sys
import types

import pytest

from wifianalyzer import privacy, scanner
from wifianalyzer.scanner import ScanError


@pytest.mark.parametrize(
    ("platform", "module", "backend"),
    [
        ("darwin", "corewlan", "CoreWLANScanner"),
        ("win32", "wlanapi", "WlanApiScanner"),
        ("linux", "nl80211", "Nl80211Scanner"),
    ],
)
def test_open_scanner_picks_the_backend_for_the_platform(monkeypatch, platform, module, backend):
    opened = []
    fake = types.SimpleNamespace(**{backend: lambda interface: opened.append(interface) or backend})
    monkeypatch.setitem(sys.modules, f"wifianalyzer.scanner.{module}", fake)
    monkeypatch.setattr(scanner.sys, "platform", platform)
    found = scanner.open_scanner("wlan0")
    monkeypatch.undo()
    assert found == backend
    assert opened == ["wlan0"]


def test_open_scanner_on_an_unsupported_system(monkeypatch):
    monkeypatch.setattr(scanner.sys, "platform", "freebsd14")
    with pytest.raises(ScanError) as raised:
        scanner.open_scanner()
    monkeypatch.undo()
    assert "isn't supported on this operating system (freebsd14)" in str(raised.value)


def test_open_settings_on_macos(monkeypatch):
    ran = []
    monkeypatch.setattr(privacy.subprocess, "run", lambda command, **_: ran.append(command))
    monkeypatch.setattr(privacy.sys, "platform", "darwin")
    opened = privacy.open_settings()
    monkeypatch.undo()
    assert opened
    assert ran == [
        ["/usr/bin/open", "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"]
    ]


def test_open_settings_reports_failure(monkeypatch):
    def fail(command, **_):
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(privacy.subprocess, "run", fail)
    monkeypatch.setattr(privacy.sys, "platform", "darwin")
    opened = privacy.open_settings()
    monkeypatch.undo()
    assert not opened


def test_open_settings_on_windows(monkeypatch):
    started = []
    monkeypatch.setattr(privacy.os, "startfile", started.append, raising=False)
    monkeypatch.setattr(privacy.sys, "platform", "win32")
    opened = privacy.open_settings()
    monkeypatch.undo()
    assert opened
    assert started == ["ms-settings:privacy-location"]


def test_no_settings_on_linux(monkeypatch):
    monkeypatch.setattr(privacy.sys, "platform", "linux")
    found = (privacy.settings_path(), privacy.open_settings())
    monkeypatch.undo()
    assert found == (None, False)
