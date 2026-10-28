import json
import os
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QPointF, QSettings, Qt
from PySide6.QtGui import Qt as GuiQt
from PySide6.QtGui import QTextDocument
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox

from factories import make_connection, make_network
from wifianalyzer import gui
from wifianalyzer.channels import channel_frequency
from wifianalyzer.gui import theme
from wifianalyzer.gui.charts import SignalHistoryChart, SpectrumChart, tooltip_html
from wifianalyzer.gui.entries import CURRENT_SLOT, Entry, SlotAssigner
from wifianalyzer.gui.icon import app_icon
from wifianalyzer.gui.panels import ConnectionCard
from wifianalyzer.gui.table import NetworkTableModel
from wifianalyzer.gui.window import MainWindow
from wifianalyzer.gui.worker import ScanWorker
from wifianalyzer.macos import bundle
from wifianalyzer.models import Band
from wifianalyzer.scanner import AccessDeniedError, ScanError, Scanner

macos_only = pytest.mark.skipif(sys.platform != "darwin", reason="Location access is requested on macOS only")


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class FakeScanner(Scanner):
    name = "wlan0"

    def __init__(self, result):
        self.result = result
        self.cancelled = False

    def scan(self):
        return self.result

    def connection(self):
        return self.result.connection

    def cancel(self):
        self.cancelled = True


@pytest.fixture
def settings(tmp_path):
    return QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)


@pytest.fixture
def window(app, sample_result, settings):
    w = MainWindow(FakeScanner(sample_result), autostart=False, settings=settings)
    yield w
    w.close()


def named(network, i):
    return replace(network, ssid=f"net{i}", bssid=f"00:00:00:00:00:{i:02x}")


def wait_until(app, condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    return condition()


# --- Colors -----------------------------------------------------------------------------


def test_connected_network_gets_first_color():
    networks = [make_network(1, -40), make_network(6, -60, is_current=True)]
    assert SlotAssigner().assign(networks) == [1, CURRENT_SLOT]


def test_colors_stay_with_networks_across_scans():
    a, b, c = (named(make_network(ch, rssi), i) for i, (ch, rssi) in enumerate([(1, -50), (6, -60), (11, -70)]))
    assigner = SlotAssigner()
    first = dict(zip("abc", assigner.assign([a, b, c]), strict=True))
    # b gets stronger than a and a new network appears: nobody already colored is repainted.
    d = named(make_network(3, -40), 9)
    second = dict(zip("bad", assigner.assign([replace(b, rssi=-45), a, d]), strict=True))
    assert second["a"] == first["a"]
    assert second["b"] == first["b"]
    assert second["d"] not in (first["a"], first["b"])


def test_networks_beyond_the_palette_are_gray():
    networks = [make_network(1, -40 - i) for i in range(theme.SERIES_COUNT + 3)]
    slots = SlotAssigner().assign(networks)
    assert slots[: theme.SERIES_COUNT - 1] == list(range(1, theme.SERIES_COUNT))
    assert set(slots[theme.SERIES_COUNT - 1 :]) == {None}


def test_light_and_dark_palettes_match():
    assert len(theme.LIGHT.series) == len(theme.DARK.series) == theme.SERIES_COUNT


# --- Charts -----------------------------------------------------------------------------


def test_spectrum_hit_testing(app):
    strong, weak = make_network(1, -50), make_network(11, -80)
    chart = SpectrumChart()
    chart.resize(800, 300)
    chart.set_data(Band.GHZ_2_4, [Entry(1, strong, 1), Entry(2, weak, 2)], ceiling=-40)
    plot = chart._plot_rect()
    axis = chart._axis(plot)

    def at(channel, dbm):
        return QPointF(axis.x(channel_frequency(Band.GHZ_2_4, channel)), chart._y(dbm, plot))

    assert chart.entry_at(at(1, -50)).index == 1  # on the line
    assert chart.entry_at(at(1, -85)).index == 1  # inside the curve
    assert chart.entry_at(at(11, -78)).index == 2  # within reach of the line
    assert chart.entry_at(at(11, -50)) is None  # far above the weak network
    assert chart.entry_at(at(6, -90)) is None  # between the two
    assert not chart.grab().isNull()


def test_spectrum_describes_itself_for_screen_readers(app):
    chart = SpectrumChart()
    chart.set_data(Band.GHZ_5, [Entry(1, make_network(44, -52, Band.GHZ_5, 80, ssid="Home"), 0)], ceiling=-40)
    assert chart.accessibleDescription() == "1 networks on 5 GHz. The strongest, Home, is on channel 36–48 at -52 dBm."
    chart.set_data(Band.GHZ_6, [], ceiling=-40)
    assert chart.accessibleDescription() == "No networks found on 6 GHz."


@pytest.mark.parametrize("band", list(Band))
def test_spectrum_paints_every_band(app, sample_result, band):
    chart = SpectrumChart()
    chart.resize(700, 260)
    entries = [Entry(i, n, i % theme.SERIES_COUNT) for i, n in enumerate(sample_result.networks, 1) if n.band is band]
    chart.set_data(band, entries, ceiling=-40)
    assert not chart.grab().isNull()


def test_empty_spectrum_paints(app):
    chart = SpectrumChart()
    chart.resize(600, 250)
    chart.set_data(Band.GHZ_6, [], ceiling=-40)
    assert not chart.grab().isNull()


def test_history_chart_paints_with_gaps(app):
    chart = SignalHistoryChart()
    chart.resize(600, 180)
    now = time.time()
    chart.set_samples([(now - 30, -60), (now - 20, None), (now - 10, -58), (now, -57)])
    assert not chart.grab().isNull()
    assert "Now -57 dBm" in chart.accessibleDescription()


def test_tooltip_escapes_ssid():
    network = make_network(6, -55, ssid="<img src=x>", bssid="aa:bb:cc:dd:ee:ff")
    text = tooltip_html(Entry(1, network, 0), theme.LIGHT)
    assert "<img" not in text
    assert "&lt;img src=x&gt;" in text
    assert text.index("-55 dBm") < text.index("&lt;img")  # the reading leads


def test_labels_never_render_ssids_as_html(app):
    card = ConnectionCard()
    card.set_connection(make_connection(36, -55, ssid="<b>evil</b>"))
    assert card.name.textFormat() == Qt.TextFormat.PlainText
    assert card.name.text() == "<b>evil</b>"


@pytest.mark.parametrize("ssid", ["<b>evil</b>", "Tom & Jerry"])
def test_table_tooltips_never_render_ssids_as_html(app, ssid):
    # Qt guesses whether a tooltip is HTML, so the escaped text must also be marked up to be read as HTML.
    model = NetworkTableModel()
    model.set_entries([Entry(1, make_network(6, -55, ssid=ssid), 0)])
    tooltip = model.data(model.index(0, NetworkTableModel.NAME), Qt.ItemDataRole.ToolTipRole)
    assert GuiQt.mightBeRichText(tooltip)
    document = QTextDocument()
    document.setHtml(tooltip)
    assert document.toPlainText() == ssid


def test_control_characters_in_names_are_shown_escaped(app):
    card = ConnectionCard()
    card.set_connection(make_connection(36, -55, ssid="cafe\x1b[2J"))
    assert card.name.text() == "cafe\\x1b[2J"


def test_icon_has_every_size(app):
    sizes = {(s.width(), s.height()) for s in app_icon().availableSizes()}
    assert {(16, 16), (32, 32), (256, 256)} <= sizes


# --- Table ------------------------------------------------------------------------------


def test_table_model_values_and_sort_keys(app):
    current = make_network(52, -55, Band.GHZ_5, 80, is_current=True, noise=-90)
    model = NetworkTableModel()
    model.set_entries([Entry(1, current, 0), Entry(2, make_network(36, -70, Band.GHZ_5), None)])
    assert model.rowCount() == 2
    row = [model.data(model.index(0, c)) for c in range(model.columnCount())]
    assert row == ["1", "—", "—", "-55 dBm", "52  DFS", "80 MHz", "WPA2", "Wi-Fi 6 (ax)", "35 dB"]
    assert model.data(model.index(1, NetworkTableModel.SNR)) == "—"
    assert model.data(model.index(0, NetworkTableModel.SIGNAL), NetworkTableModel.SORT_ROLE) == -55
    assert model.data(model.index(0, 1), Qt.ItemDataRole.FontRole).bold()


def test_sorted_column_title_shows_the_direction(window):
    header = window.table.horizontalHeader()
    title = window.table_model.headerData
    assert not header.isSortIndicatorShown()
    assert title(NetworkTableModel.INDEX, Qt.Orientation.Horizontal) == "# ↑"
    window.table.sortByColumn(NetworkTableModel.SIGNAL, Qt.SortOrder.DescendingOrder)
    assert title(NetworkTableModel.SIGNAL, Qt.Orientation.Horizontal) == "Signal ↓"
    assert title(NetworkTableModel.INDEX, Qt.Orientation.Horizontal) == "#"


# --- Window -----------------------------------------------------------------------------


def test_window_shows_connected_band_first(window, sample_result):
    window.apply_result(sample_result)
    assert window.band_buttons[Band.GHZ_5].isChecked()
    assert window.band_actions[Band.GHZ_5].isChecked()
    assert window.table_model.rowCount() == sum(n.band is Band.GHZ_5 for n in sample_result.networks)
    assert window.table.isColumnHidden(NetworkTableModel.BSSID)
    assert not window.banner.isHidden()
    # You're on 36–48 with a neighbour on 44; 52–64 has nobody.
    assert window.recommendations.verdict.text() == "Switch to 52–64: no neighbours overlap it."
    assert not window.grab().isNull()


def test_switching_band_updates_everything_below(window, sample_result):
    window.apply_result(sample_result)
    window.select_band(Band.GHZ_2_4)
    assert window.table_model.rowCount() == sum(n.band is Band.GHZ_2_4 for n in sample_result.networks)
    assert window.spectrum_card.title.text() == "2.4 GHz spectrum"
    assert "not connected on 2.4 GHz" in window.recommendations.verdict.text()


def test_band_shortcuts_switch_bands(window, sample_result):
    window.apply_result(sample_result)
    window.band_actions[Band.GHZ_6].trigger()
    assert window.band_buttons[Band.GHZ_6].isChecked()
    assert window.spectrum_card.title.text() == "6 GHz spectrum"


def test_chart_and_table_selection_stay_in_sync(window, sample_result):
    window.apply_result(sample_result)
    third = window.table_model.data(window.table_model.index(2, 0), NetworkTableModel.ENTRY_ROLE)
    window._select_entry(third)
    assert window.spectrum._selected == third.index
    window._select_entry(None)
    assert window.spectrum._selected is None


def test_selection_survives_rescan_when_bssids_are_known(window, sample_result):
    result = replace(sample_result, networks=[named(n, i) for i, n in enumerate(sample_result.networks)])
    window.apply_result(result)
    assert window.banner.isHidden()
    assert not window.table.isColumnHidden(NetworkTableModel.BSSID)
    entry = window.table_model.data(window.table_model.index(1, 0), NetworkTableModel.ENTRY_ROLE)
    window._select_entry(entry)
    window.apply_result(result)
    assert window.spectrum._selected == entry.index


def test_the_page_scrolls_only_when_the_window_is_too_small_for_it(app, window, sample_result):
    window.apply_result(sample_result)
    window.show()
    scroll, page = window.centralWidget(), window.centralWidget().widget()
    window.resize(1280, 860)
    app.processEvents()
    assert page.height() == scroll.viewport().height()
    window.resize(640, 480)
    app.processEvents()
    assert page.height() > scroll.viewport().height()
    assert window.spectrum.height() >= window.spectrum.minimumHeight()


def test_failed_scan_keeps_previous_results(window, sample_result):
    window.apply_result(sample_result)
    window.scan_now()
    window._scan_failed(ScanError("Wi-Fi is turned off on wlan0."))
    assert window.status.text() == "⚠ Wi-Fi is turned off on wlan0. Showing the previous results."
    assert window.scan_action.isEnabled()
    assert window.table_model.rowCount() > 0


def test_access_denied_explains_and_clears_once_allowed(window, sample_result):
    window._scan_failed(
        AccessDeniedError("Windows only shows nearby Wi-Fi networks to apps that may use your location.")
    )
    assert not window.banner.isHidden()
    assert window.banner.message.text().startswith("Windows only shows")
    assert window.banner.allow.isHidden()
    named_result = replace(sample_result, networks=[named(n, i) for i, n in enumerate(sample_result.networks)])
    window.apply_result(named_result)
    assert window.banner.isHidden()


def test_save_scan_writes_json(window, sample_result, tmp_path, monkeypatch):
    target = tmp_path / "scan.json"
    suggested = []

    def choose(parent, caption, path, filters):
        suggested.append(Path(path))
        return str(target), ""

    monkeypatch.setattr(QFileDialog, "getSaveFileName", choose)
    assert not window.save_action.isEnabled()
    window.apply_result(sample_result)
    window.save_action.trigger()
    # Documents and Desktop are often synced to the cloud, and a scan shows where it was taken.
    assert suggested[0].parent == Path.home()
    data = json.loads(target.read_text(encoding="utf-8"))
    assert len(data["networks"]) == len(sample_result.networks)
    assert {r["band"] for r in data["recommendations"]} == {"2.4", "5", "6"}


def test_settings_are_remembered(app, sample_result, settings, monkeypatch):
    first = MainWindow(FakeScanner(sample_result), autostart=False, settings=settings)
    first.interval.setValue(42)
    first.auto_refresh.setChecked(False)
    first.close()
    # Qt reports exceptions raised in slots through sys.excepthook instead of raising them.
    errors = []
    monkeypatch.setattr(sys, "excepthook", lambda *exc_info: errors.append(exc_info))
    second = MainWindow(FakeScanner(sample_result), autostart=False, settings=settings)
    try:
        assert not errors
        assert second.interval.value() == 42
        assert second._scan_timer.interval() == 42_000
        assert not second.auto_refresh.isChecked()
        assert not second.interval.isEnabled()
    finally:
        second.close()


@macos_only
def test_allow_reopens_as_app_when_macos_cannot_ask_this_process(window, monkeypatch, tmp_path):
    opened = []
    monkeypatch.setattr(bundle, "build", lambda: tmp_path / "Wi-Fi Analyzer.app")
    monkeypatch.setattr(bundle, "open_app", lambda app, args: opened.append((app, args)))
    window.show()
    assert "reopen" in window.banner.message.text()
    window.banner.allow.click()
    args = ["-m", "wifianalyzer.gui", "-i", "wlan0", "--request-location"]
    assert opened == [(tmp_path / "Wi-Fi Analyzer.app", args)]
    assert not window.isVisible()


@macos_only
def test_app_build_failure_is_shown_in_the_banner(window, monkeypatch):
    def fail():
        raise bundle.AppBuildError("clang wasn't found.")

    monkeypatch.setattr(bundle, "build", fail)
    window.banner.allow.click()
    assert window.banner.message.text().endswith("clang wasn't found.")
    assert window.banner.allow.isEnabled()


@pytest.mark.skipif(sys.platform == "darwin", reason="macOS can ask for access from the app")
def test_banner_never_offers_to_ask_elsewhere(window, sample_result):
    window.apply_result(sample_result)  # redacted, which only macOS does, but the button must stay away
    assert window.banner.allow.isHidden()


# --- Worker -----------------------------------------------------------------------------


class BrokenScanner(FakeScanner):
    def scan(self):
        raise RuntimeError("driver exploded")

    def connection(self):
        raise RuntimeError("driver exploded")


def test_worker_reports_unexpected_errors_as_failures(app, sample_result):
    worker = ScanWorker(BrokenScanner(sample_result))
    failures, poll_failures = [], []
    worker.failed.connect(failures.append)
    worker.poll_failed.connect(poll_failures.append)
    worker.scan()
    worker.poll()
    assert [str(e) for e in failures] == ["Unexpected error: driver exploded"]
    assert [str(e) for e in poll_failures] == ["Unexpected error: driver exploded"]


def test_worker_thread_is_registered_with_the_debugger(app, sample_result, settings, monkeypatch):
    calls = []
    fake_debugpy = type(
        "FakeDebugpy", (), {"debug_this_thread": staticmethod(lambda: calls.append(threading.get_ident()))}
    )
    monkeypatch.setitem(sys.modules, "debugpy", fake_debugpy)
    w = MainWindow(FakeScanner(sample_result), autostart=True, settings=settings)
    try:
        assert wait_until(app, lambda: calls)
    finally:
        w.close()
    assert len(calls) == 1
    assert calls[0] != threading.main_thread().ident


def test_scans_run_on_the_worker_thread_and_quitting_cancels(app, sample_result, settings):
    scanner = FakeScanner(sample_result)
    w = MainWindow(scanner, autostart=True, settings=settings)
    try:
        assert wait_until(app, lambda: w._result is not None and w._history)
        assert w._result is sample_result
        assert w._history[-1][1] == sample_result.connection.rssi
        assert w.scan_action.isEnabled()
    finally:
        w.close()
    assert not w._thread.isRunning()
    assert scanner.cancelled


# --- Starting up --------------------------------------------------------------------------


@pytest.fixture
def excepthook():
    previous = sys.excepthook
    yield
    sys.excepthook = previous


def test_run_reports_a_missing_interface(app, monkeypatch, excepthook):
    def fail(interface):
        raise ScanError("No Wi-Fi interface found")

    shown = []
    monkeypatch.setattr("wifianalyzer.scanner.open_scanner", fail)
    monkeypatch.setattr(QMessageBox, "critical", lambda parent, title, text: shown.append((title, text)))
    assert gui.run() == 1
    assert shown == [("Wi-Fi Analyzer", "No Wi-Fi interface found")]


def test_unexpected_errors_are_shown_once(app, monkeypatch, excepthook):
    shown = []
    monkeypatch.setattr(QMessageBox, "exec", lambda box: shown.append((box.text(), box.textFormat())))
    gui._show_unexpected_errors()
    for _ in range(2):
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            sys.excepthook(*sys.exc_info())
    assert shown == [("Something went wrong: boom", Qt.TextFormat.PlainText)]
