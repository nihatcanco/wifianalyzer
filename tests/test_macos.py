import plistlib
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

from wifianalyzer.macos import bundle, location

macos_only = pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
_CONFIG = Path(sysconfig.get_config_var("BINDIR") or "") / f"python{sysconfig.get_config_var('LDVERSION')}-config"
needs_compiler = pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("clang") is None or not _CONFIG.exists(),
    reason="building the bundle needs macOS, clang and Python's development files",
)


def test_info_plist_explains_location_use():
    info = bundle.info_plist()
    assert info["NSLocationUsageDescription"] == info["NSLocationWhenInUseUsageDescription"] == bundle.USAGE
    assert info["CFBundleExecutable"] == bundle.EXECUTABLE
    assert info["CFBundleIdentifier"] == bundle.BUNDLE_ID


@macos_only
def test_plain_python_cannot_request_location():
    assert not location.can_request()


@macos_only
def test_the_app_moves_into_the_bundle_once_it_exists(tmp_path, monkeypatch):
    calls = []
    app = tmp_path / "Wi-Fi Analyzer.app"
    monkeypatch.setattr(bundle, "default_path", lambda: app)
    monkeypatch.setattr(bundle.os, "execv", lambda path, args: calls.append((path, args)))

    bundle.exec_in_app("wifianalyzer.gui", [])
    assert calls == []

    exe = bundle.executable(app)
    exe.parent.mkdir(parents=True)
    exe.touch()
    bundle.exec_in_app("wifianalyzer.gui", ["-i", "en1"])
    assert calls == [(exe, [str(exe), "-m", "wifianalyzer.gui", "-i", "en1"])]

    monkeypatch.setattr(location, "can_request", lambda: True)  # already inside it
    bundle.exec_in_app("wifianalyzer.gui", [])
    assert len(calls) == 1


@needs_compiler
def test_bundle_runs_this_environment_as_the_app(tmp_path):
    app = bundle.build(tmp_path / "Wi-Fi Analyzer.app")
    subprocess.run(["codesign", "--verify", "--strict", str(app)], check=True)
    with (app / "Contents" / "Info.plist").open("rb") as f:
        assert plistlib.load(f) == bundle.info_plist()
    code = "import sys; from wifianalyzer.macos import location; print(sys.prefix); print(location.can_request())"
    run = subprocess.run([str(bundle.executable(app)), "-c", code], check=True, capture_output=True, text=True)
    assert run.stdout.splitlines() == [sys.prefix, "True"]


@needs_compiler
def test_rebuilding_keeps_the_same_signature(tmp_path):
    # Location permission is tied to the signature, so an unchanged rebuild must not alter it.
    app = tmp_path / "Wi-Fi Analyzer.app"

    def cdhash():
        info = subprocess.run(["codesign", "-dvvv", str(app)], capture_output=True, text=True, check=True).stderr
        return next(line for line in info.splitlines() if line.startswith("CDHash="))

    bundle.build(app)
    first = cdhash()
    bundle.build(app)
    assert cdhash() == first
    assert [p.name for p in tmp_path.iterdir()] == [app.name]  # no staging leftovers


def test_other_platforms_never_move_into_a_bundle(monkeypatch):
    monkeypatch.setattr(bundle.sys, "platform", "linux")
    monkeypatch.setattr(bundle.os, "execv", lambda *_: pytest.fail("execv called"))
    bundle.exec_in_app("wifianalyzer.gui", [])
