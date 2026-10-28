"""wifianalyzer runs entirely on the user's computer: nothing in it may connect to another service."""

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import wifianalyzer

PACKAGE = Path(wifianalyzer.__file__).parent
SOURCES = sorted(PACKAGE.rglob("*.py"))
NETWORK_MODULES = {
    "socket", "ssl", "http", "urllib", "ftplib", "smtplib", "imaplib", "poplib", "xmlrpc", "asyncio",
    "requests", "httpx", "aiohttp", "urllib3", "websockets", "webbrowser",
    "PySide6.QtNetwork", "PySide6.QtNetworkAuth", "PySide6.QtWebSockets", "PySide6.QtHttpServer",
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebView",
}  # fmt: skip
# Ways a Qt app opens web pages: in the browser, from links in a label or message box, or in
# Qt's own About dialog, which links to qt.io.
LINK_OPENERS = {"openUrl", "setOpenExternalLinks", "aboutQt", "AboutQtRole"}
# The Linux scanner talks to the kernel over a netlink socket, which never leaves the machine.
NETLINK_MODULE = PACKAGE / "scanner" / "netlink.py"
# CoreLocation calls that make macOS work out a position, which can query Apple's servers.
LOCATION_LOOKUPS = {
    "startUpdatingLocation", "requestLocation",
    "startMonitoringSignificantLocationChanges", "startMonitoringVisits",
}  # fmt: skip
URL = re.compile(r"\b(?:https?|ftp|wss?)://", re.IGNORECASE)


def _imports(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            yield node.module
            yield from (f"{node.module}.{alias.name}" for alias in node.names)


def _trees():
    for path in SOURCES:
        yield path, ast.parse(path.read_text(encoding="utf-8"))


def test_no_module_imports_networking():
    for path, tree in _trees():
        allowed = {"socket"} if path == NETLINK_MODULE else set()
        for name in _imports(tree):
            banned = any(name == m or name.startswith(m + ".") for m in NETWORK_MODULES - allowed)
            assert not banned, f"{path.relative_to(PACKAGE)}: {name}"


def test_the_only_sockets_are_netlink_sockets():
    for path, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ast.unparse(node.func) == "socket.socket":
                assert node.args, f"{path.name}: socket.socket() without an address family"
                assert ast.unparse(node.args[0]) == "socket.AF_NETLINK", f"{path.name}: {ast.unparse(node)}"


def test_location_is_never_looked_up():
    for path, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in LOCATION_LOOKUPS, f"{path.name}: {node.attr}"


def test_no_internet_addresses():
    for path, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert not URL.search(node.value), f"{path.name}: {node.value!r}"


def test_nothing_opens_web_links():
    for path, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in LINK_OPENERS, f"{path.name}: {node.attr}"


def test_the_running_app_never_reaches_the_network(tmp_path):
    # The tests above read the code. This one watches the app scan, draw every band and save the scan.
    run = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("audited_run.py")), str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
    )
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout) == {"scanned": True, "saved": True, "attempts": []}
