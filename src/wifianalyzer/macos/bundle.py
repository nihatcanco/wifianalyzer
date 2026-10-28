"""Builds the macOS app bundle that wifianalyzer runs in to get Location access.

macOS only asks for Location access on behalf of an app whose Info.plist says why it wants it.
A python binary has no Info.plist, so its requests are dropped without a prompt and network
names stay hidden. The bundle's executable (launcher.c) runs this environment's Python inside
its own process, so macOS sees Wi-Fi Analyzer.app as the program asking, and the permission
belongs to the bundle.

Building it only uses local tools: clang, and codesign with an ad-hoc signature and no
timestamp server.
"""

from __future__ import annotations

import json
import os
import plistlib
import shlex
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from importlib import resources
from pathlib import Path

from .. import APP_NAME, __version__
from . import location

__all__ = ["APP_NAME", "AppBuildError", "build", "exec_in_app", "open_app"]
BUNDLE_ID = "io.github.nihatcanco.wifianalyzer"
EXECUTABLE = "wifianalyzer"
USAGE = (
    "Wi-Fi Analyzer needs Location access to show the names of nearby Wi-Fi networks, which macOS "
    "treats as location data. It doesn't use your location."
)


class AppBuildError(Exception):
    """The bundle couldn't be built. The message says why."""


def default_path() -> Path:
    """Where the bundle goes: inside the environment, because its launcher only works with that one."""
    return Path(sys.prefix) / f"{APP_NAME}.app"


def executable(app: Path) -> Path:
    """The bundle's launcher, which also accepts the same arguments as the python command."""
    return app / "Contents" / "MacOS" / EXECUTABLE


def info_plist() -> dict[str, str | bool]:
    return {
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleExecutable": EXECUTABLE,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": __version__,
        "CFBundleVersion": __version__,
        "LSMinimumSystemVersion": "12.0",  # what Qt 6.8, the oldest Qt wifianalyzer supports, needs
        "NSHighResolutionCapable": True,
        "NSLocationUsageDescription": USAGE,
        "NSLocationWhenInUseUsageDescription": USAGE,
    }


def build(app: Path | None = None) -> Path:
    """Build the bundle for the running Python environment, replacing any earlier build.

    Builds are reproducible, so rebuilding an unchanged bundle keeps its Location permission.
    """
    app = app or default_path()
    flags = _compiler_flags()
    app.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=app.parent, prefix=".build-") as tmp:
        staged = Path(tmp) / app.name
        executable(staged).parent.mkdir(parents=True)
        with (staged / "Contents" / "Info.plist").open("wb") as f:
            plistlib.dump(info_plist(), f)
        python = json.dumps(sys.executable, ensure_ascii=False)  # as a C string literal
        with resources.as_file(resources.files(__package__) / "launcher.c") as source:
            _run(["clang", str(source), "-o", str(executable(staged)), f"-DWIFIANALYZER_PYTHON={python}", *flags])
        _run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(staged)])  # stays offline
        # Renaming leaves a running copy of the old bundle untouched.
        if app.exists():
            shutil.rmtree(app)
        staged.rename(app)
    return app


def open_app(app: Path, args: list[str] | None = None) -> None:
    """Start the bundle the way Finder does. If it's already running, macOS brings it forward instead."""
    _run(["/usr/bin/open", str(app), *(["--args", *args] if args else [])])


def exec_in_app(module: str, args: list[str]) -> None:
    """Rerun this command inside the bundle, if it has been built, by replacing this process.

    Location access belongs to the bundle, so a command only sees network names when it runs there.
    """
    if sys.platform != "darwin" or location.can_request():
        return
    path = executable(default_path())
    if path.exists():
        os.execv(path, [str(path), "-m", module, *args])


def _compiler_flags() -> list[str]:
    config = Path(sysconfig.get_config_var("BINDIR")) / f"python{sysconfig.get_config_var('LDVERSION')}-config"
    if not config.exists():
        raise AppBuildError(f"{config} is missing. It comes with Python's development files.")
    cflags = shlex.split(_run([str(config), "--cflags"]))
    ldflags = shlex.split(_run([str(config), "--embed", "--ldflags"]))
    # Debug info records the temporary paths of the build, which would make every build differ.
    return [flag for flag in cflags if flag != "-g"] + ldflags


def _run(command: list[str]) -> str:
    try:
        return subprocess.run(command, check=True, capture_output=True, text=True).stdout
    except FileNotFoundError:
        raise AppBuildError(
            f"{command[0]} wasn't found. Install Apple's command line tools: xcode-select --install"
        ) from None
    except subprocess.CalledProcessError as e:
        raise AppBuildError(f"{Path(command[0]).name} failed: {(e.stderr or e.stdout).strip()}") from None
