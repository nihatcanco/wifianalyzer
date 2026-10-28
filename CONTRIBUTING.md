# Contributing

Bug reports and pull requests are welcome. For anything bigger than a fix, please open an issue first to talk it
through.

## Setup

You need Python 3.11 or newer.

```sh
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e . --group dev
```

On Windows, the environment's programs are in `.venv\Scripts` instead of `.venv/bin`. Dependency groups need pip 25.1
or newer, which the second line takes care of.

## Checks

```sh
.venv/bin/python -m pytest                  # tests, with coverage: add --cov
.venv/bin/ruff check && .venv/bin/ruff format --check
.venv/bin/mypy --platform darwin            # and --platform linux, --platform win32
```

CI runs all of them on macOS, Windows and Linux with the oldest and newest supported Python, and once more on macOS
with the oldest Qt and PyObjC that `pyproject.toml` accepts. Type-check for all three platforms, since each one only
checks the code that runs there. To run the lint and format checks before every commit,
install the hooks in `.pre-commit-config.yaml` with [pre-commit](https://pre-commit.com).

The desktop app's tests use Qt's offscreen platform, so no windows open.
Every backend is tested on every platform, with data laid out as the system API and the 802.11 standard describe it.
A few tests talk to the real system API and only run on its platform.

## Layout

```text
src/wifianalyzer/
  models.py          Band, Network, Connection and ScanResult
  channels.py        channel and frequency math: bonding blocks, overlap, DFS
  analysis.py        signal quality, interference scoring and recommendations
  display.py         naming, escaping and chart-scale helpers
  export.py          scans as JSON
  privacy.py         where each system lets users allow access to nearby networks
  scanner/           one backend per operating system, behind open_scanner()
    corewlan.py      macOS
    wlanapi.py       Windows: wlanapi.dll through ctypes
    nl80211.py       Linux: the kernel's nl80211 interface
    netlink.py       the generic netlink protocol nl80211 runs over
    elements.py      802.11 information elements, which Windows and Linux report unparsed
  macos/
    location.py      the Location Services permission
    bundle.py        builds Wi-Fi Analyzer.app, which macOS can grant Location access
    launcher.c       the bundle's executable: runs this environment's Python in-process
  gui/               desktop app (PySide6)
    window.py        main window; wires everything together
    worker.py        runs scanner calls on a background thread
    charts.py        spectrum and signal-history charts
    table.py         network table model and signal meters
    panels.py        connection card, recommendations, access banner
    entries.py       per-network numbering and colors
    theme.py         light and dark colors
    icon.py          the app icon, drawn in code
tests/
scripts/
  screenshot.py      draws the README's screenshots from made-up networks
```

Only `scanner/`, `macos/` and `privacy.py` talk to the operating system.

## Ground rules

- **No network access.** The app must never connect to anything, directly or by making the system do it, such as
  asking macOS for a location or opening a web page from a link. `tests/test_offline.py` enforces what it can, both
  by reading the code and by watching the app run (`tests/audited_run.py`); extend it when a new kind of access
  appears.
- **Names come from strangers.** Anyone nearby can broadcast any network name. Show names with `display.printable`, and
  keep Qt labels that show them in plain-text format.
- **Same words everywhere.** Every backend describes security and standards with the same labels, so the app
  doesn't need to know which system it runs on.
- **Screenshots show made-up networks.** A real scan shows where it was taken. After changing the window, redraw the
  README's screenshots with `.venv/bin/python scripts/screenshot.py`.

## Releases

1. Update `__version__` in `src/wifianalyzer/__init__.py` and move the changes in `CHANGELOG.md` under the new version,
   with the date.
2. Install the tools with `.venv/bin/pip install --group release`, build with `.venv/bin/python -m build` and check
   with `.venv/bin/twine check --strict dist/*`.
