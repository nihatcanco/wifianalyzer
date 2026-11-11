"""The main window: connection summary, signal history, spectrum, network table and recommendations."""

from __future__ import annotations

import sys
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path

from PySide6 import __version__ as pyside_version
from PySide6.QtCore import (
    QEvent,
    QItemSelectionModel,
    QObject,
    QSettings,
    QSize,
    QSortFilterProxyModel,
    QStandardPaths,
    Qt,
    QThread,
    QTimer,
    Signal,
    qVersion,
)
from PySide6.QtGui import QAction, QActionGroup, QCloseEvent, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QButtonGroup,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from .. import APP_NAME, __version__, privacy
from ..analysis import bands_in, recommend
from ..display import chart_ceiling, index_networks, printable
from ..export import ScanFileError, from_json, to_csv, to_json
from ..macos import bundle, location
from ..models import Band, Connection, ScanResult
from ..scanner import AccessDeniedError, ScanError, Scanner
from . import snapshot, theme
from .charts import SignalHistoryChart, SpectrumChart
from .entries import Entry, SlotAssigner
from .panels import AccessBanner, Card, ConnectionCard, RecommendationsCard, label
from .table import NetworkTableModel, SignalDelegate
from .worker import ScanWorker

POLL_INTERVAL_MS = 1000
LOCATION_TIMEOUT_S = 60
DEFAULT_SCAN_INTERVAL_S = 10


class ScrollPage(QScrollArea):
    """Fills the window with the page, and scrolls only when the window is smaller than the page can be.

    QScrollArea's own resizing follows the page's preferred height once it contains wrapping text,
    which would show a scroll bar even where everything fits. On a small screen, scrolling beats
    squeezing the charts below a readable size.
    """

    def __init__(self, page: QWidget) -> None:
        super().__init__()
        self.setObjectName("scroll")
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setWidget(page)
        self.viewport().installEventFilter(self)

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if watched is self.viewport() and event.type() == QEvent.Type.Resize:
            self.fit()
        return super().eventFilter(watched, event)

    def fit(self) -> None:
        page, viewport = self.widget(), self.viewport().size()
        if page is None:
            return
        minimum = page.minimumSizeHint()
        width = max(viewport.width(), minimum.width())
        layout = page.layout()
        needed = layout.minimumHeightForWidth(width) if layout and layout.hasHeightForWidth() else -1
        page.resize(width, max(viewport.height(), needed, minimum.height()))


def _file_name(result: ScanResult, kind: str, suffix: str) -> str:
    return f"wifi-{kind}-{result.timestamp:%Y%m%d-%H%M%S}{suffix}"


def _timer(parent: QObject, interval_ms: int, callback: Callable[[], None]) -> QTimer:
    timer = QTimer(parent)
    timer.setInterval(interval_ms)
    timer.timeout.connect(callback)
    return timer


class MainWindow(QMainWindow):
    request_scan = Signal()
    request_poll = Signal()

    def __init__(
        self,
        scanner: Scanner,
        *,
        autostart: bool = True,
        request_location: bool = False,
        settings: QSettings | None = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(640, 480)
        self._scanner = scanner
        self._settings = settings if settings is not None else QSettings()

        self._result: ScanResult | None = None
        """The scan on show: the latest live one, or a saved one while ``_viewing`` names its file."""
        self._live: ScanResult | None = None
        self._connection: Connection | None = None
        self._viewing: str | None = None
        self._band: Band | None = None
        self._assigners = {band: SlotAssigner() for band in Band}
        self._history: deque[tuple[float, int | None]] = deque(maxlen=SignalHistoryChart.WINDOW_SECONDS)
        self._scanning = False
        self._polling = False
        self._selected_bssid: str | None = None
        self._authorization: location.AuthorizationRequest | None = None
        self._authorization_deadline = 0.0

        self._build_actions()
        self._build_menus()
        self._build_toolbar()
        self._build_body()
        self._build_status_bar()
        # Restoring settings fires the toggle and interval slots, which use these timers.
        self._poll_timer = _timer(self, POLL_INTERVAL_MS, self._poll)
        self._scan_timer = _timer(self, self.interval.value() * 1000, self.scan_now)
        self._authorization_timer = _timer(self, 500, self._check_authorization)
        self._restore_settings()
        self._apply_theme()
        QGuiApplication.styleHints().colorSchemeChanged.connect(self._apply_theme)

        self._thread = QThread(self)
        self._worker = ScanWorker(scanner)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.thread_started)
        self.request_scan.connect(self._worker.scan)
        self.request_poll.connect(self._worker.poll)
        self._worker.scanned.connect(self.apply_result)
        self._worker.failed.connect(self._scan_failed)
        self._worker.polled.connect(self.apply_connection)
        self._worker.poll_failed.connect(self._poll_failed)

        if autostart:
            self._thread.start()
            self._poll_timer.start()
            if self.auto_refresh.isChecked():
                self._scan_timer.start()
            QTimer.singleShot(0, self.scan_now)
        if request_location:
            QTimer.singleShot(0, self._request_location)

    # --- Layout -----------------------------------------------------------------------

    def _build_actions(self) -> None:
        self.scan_action = QAction("Scan Now", self)
        self.scan_action.setShortcuts([QKeySequence("Ctrl+R"), QKeySequence(Qt.Key.Key_F5)])
        self.scan_action.setToolTip("Scan now (Ctrl+R)")
        self.scan_action.triggered.connect(self.scan_now)

        self.auto_refresh = QAction("Auto-refresh", self)
        self.auto_refresh.setCheckable(True)
        self.auto_refresh.setChecked(True)
        self.auto_refresh.toggled.connect(self._toggle_auto_refresh)

        self.live_action = QAction("Back to Live", self)
        self.live_action.setToolTip("Leave the saved scan and scan again")
        self.live_action.setVisible(False)
        self.live_action.triggered.connect(self.scan_now)

        self.open_action = QAction("Open Scan…", self)
        self.open_action.setShortcut(QKeySequence.StandardKey.Open)
        self.open_action.triggered.connect(self._open_scan)

        self.save_action = QAction("Save Scan…", self)
        self.save_action.setShortcut(QKeySequence.StandardKey.Save)
        self.save_action.triggered.connect(self._save_scan)
        self.csv_action = QAction("Export Networks as CSV…", self)
        self.csv_action.triggered.connect(self._export_csv)
        self.chart_action = QAction("Export Spectrum Chart…", self)
        self.chart_action.triggered.connect(self._export_chart)
        self.snapshot_action = QAction("Export Window Snapshot…", self)
        self.snapshot_action.triggered.connect(self._export_snapshot)
        # No copy to the clipboard: macOS and Windows can sync it to other devices and the cloud.
        self.export_actions = (self.save_action, self.csv_action, self.chart_action, self.snapshot_action)
        for action in self.export_actions:
            action.setEnabled(False)

        self.quit_action = QAction("Quit", self)
        self.quit_action.setShortcut(QKeySequence("Ctrl+Q"))
        self.quit_action.setMenuRole(QAction.MenuRole.QuitRole)
        self.quit_action.triggered.connect(self.close)

        self.band_actions: dict[Band, QAction] = {}
        group = QActionGroup(self)
        for number, band in enumerate(Band, start=1):
            action = QAction(band.label, group)
            action.setCheckable(True)
            action.setShortcut(QKeySequence(f"Ctrl+{number}"))
            action.triggered.connect(lambda _=False, b=band: self.select_band(b))
            self.band_actions[band] = action

        # No "About Qt": its dialog links to websites, and the app must never open one.
        self.about_action = QAction(f"About {APP_NAME}", self)
        self.about_action.setMenuRole(QAction.MenuRole.AboutRole)
        self.about_action.triggered.connect(self._show_about)

    def _build_menus(self) -> None:
        bar = self.menuBar()
        file_menu = bar.addMenu("&File")
        file_menu.addAction(self.open_action)
        file_menu.addAction(self.save_action)
        file_menu.addSeparator()
        file_menu.addActions([self.csv_action, self.chart_action, self.snapshot_action])
        file_menu.addSeparator()
        file_menu.addAction(self.quit_action)  # macOS moves it to the application menu
        view = bar.addMenu("&View")
        view.addActions(list(self.band_actions.values()))
        scan = bar.addMenu("&Scan")
        scan.addAction(self.scan_action)
        scan.addAction(self.auto_refresh)
        scan.addAction(self.live_action)
        help_menu = bar.addMenu("&Help")
        help_menu.addAction(self.about_action)

    def _build_toolbar(self) -> None:
        toolbar = self.addToolBar("Scan")
        toolbar.setObjectName("scan-toolbar")
        toolbar.setMovable(False)
        # Style sheet padding applies its largest side all round; this lines the buttons up with the cards.
        toolbar.setContentsMargins(10, 0, 10, 0)
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        toolbar.addAction(self.scan_action)
        primary = toolbar.widgetForAction(self.scan_action)
        if primary:
            primary.setObjectName("primary")
        toolbar.addAction(self.auto_refresh)
        for action in (self.scan_action, self.auto_refresh):
            button = toolbar.widgetForAction(action)
            if button:
                button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.interval = QSpinBox()
        self.interval.setRange(5, 300)
        self.interval.setValue(DEFAULT_SCAN_INTERVAL_S)
        self.interval.setSuffix(" s")
        self.interval.setToolTip("Seconds between automatic scans")
        self.interval.setAccessibleName("Scan interval")
        self.interval.valueChanged.connect(lambda seconds: self._scan_timer.setInterval(seconds * 1000))
        toolbar.addWidget(label("every", "secondary"))
        toolbar.addWidget(self.interval)
        toolbar.addAction(self.live_action)  # shown while a saved scan is open
        live = toolbar.widgetForAction(self.live_action)
        if live:
            live.setCursor(Qt.CursorShape.PointingHandCursor)

    def _build_body(self) -> None:
        page = QWidget()
        page.setObjectName("page")
        root = QVBoxLayout(page)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(12)

        can_ask = sys.platform == "darwin"
        self.banner = AccessBanner(can_ask=can_ask, reopens_as_app=can_ask and not location.can_request())
        self.banner.allow_clicked.connect(self._request_location)
        self.banner.settings_clicked.connect(privacy.open_settings)
        self.banner.hide()
        root.addWidget(self.banner)
        root.addLayout(self._build_connection_row())
        root.addLayout(self._build_band_picker())

        self.spectrum_card = Card("Spectrum")
        self.spectrum = SpectrumChart()
        self.spectrum.activated.connect(self._select_entry)
        self.spectrum_card.layout_.addWidget(self.spectrum, stretch=1)

        table_card = Card("Networks")
        table_card.layout_.addWidget(self._build_table(), stretch=1)
        table_card.setMinimumHeight(160)
        self.recommendations = RecommendationsCard()
        self.recommendations.setMinimumWidth(380)

        self.bottom_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.bottom_splitter.addWidget(table_card)
        self.bottom_splitter.addWidget(self.recommendations)
        self.bottom_splitter.setStretchFactor(0, 3)
        self.bottom_splitter.setStretchFactor(1, 1)
        self.bottom_splitter.setSizes([860, 420])
        self.bottom_splitter.setChildrenCollapsible(False)
        self.bottom_splitter.setHandleWidth(12)  # the same gap as between the other cards

        self.main_splitter = QSplitter(Qt.Orientation.Vertical)
        self.main_splitter.addWidget(self.spectrum_card)
        self.main_splitter.addWidget(self.bottom_splitter)
        self.main_splitter.setStretchFactor(0, 3)
        self.main_splitter.setStretchFactor(1, 2)
        self.main_splitter.setSizes([600, 400])
        self.main_splitter.setChildrenCollapsible(False)
        self.main_splitter.setHandleWidth(12)
        root.addWidget(self.main_splitter, stretch=1)

        self.page = page
        self.setCentralWidget(ScrollPage(page))
        self.table.setFocus()

    def _build_connection_row(self) -> QHBoxLayout:
        top = QHBoxLayout()
        top.setSpacing(12)
        self.connection_card = ConnectionCard()
        self.connection_card.setMaximumWidth(470)
        top.addWidget(self.connection_card, stretch=1)
        history_card = Card("Signal strength · last 5 minutes")
        self.history_chart = SignalHistoryChart()
        history_card.layout_.addWidget(self.history_chart, stretch=1)
        top.addWidget(history_card, stretch=2)
        return top

    def _build_band_picker(self) -> QHBoxLayout:
        """A segmented control for the band that everything below it shows: spectrum, table and recommendations."""
        bands = QHBoxLayout()
        bands.setSpacing(10)
        bands.addWidget(label("Band", "secondary"))
        segmented = QFrame()
        segmented.setObjectName("segmented")
        segments = QHBoxLayout(segmented)
        segments.setContentsMargins(2, 2, 2, 2)
        segments.setSpacing(2)
        self.band_group = QButtonGroup(self)
        self.band_group.setExclusive(True)
        self.band_buttons: dict[Band, QPushButton] = {}
        for band in Band:
            button = QPushButton(band.label)
            button.setCheckable(True)
            button.setMinimumWidth(110)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setToolTip(self.band_actions[band].shortcut().toString(QKeySequence.SequenceFormat.NativeText))
            self.band_group.addButton(button)
            self.band_buttons[band] = button
            button.clicked.connect(lambda _=False, b=band: self.select_band(b))
            segments.addWidget(button)
        bands.addWidget(segmented)
        bands.addStretch()
        return bands

    def _build_table(self) -> QTableView:
        self.table_model = NetworkTableModel(self)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.table_model)
        self.proxy.setSortRole(NetworkTableModel.SORT_ROLE)
        self.table = QTableView()
        self.table.setAccessibleName("Networks")
        self.table.setModel(self.proxy)
        header = self.table.horizontalHeader()
        header.sortIndicatorChanged.connect(self.table_model.show_sort)
        self.table.setSortingEnabled(True)
        header.setSortIndicatorShown(False)  # after enabling sorting, which shows it; the model draws its own
        self.table.sortByColumn(NetworkTableModel.INDEX, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setMouseTracking(True)  # for the row hover highlight
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(32)
        self.table.setItemDelegateForColumn(NetworkTableModel.SIGNAL, SignalDelegate(self.table))
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(NetworkTableModel.NAME, QHeaderView.ResizeMode.Stretch)
        header.setHighlightSections(False)
        # Selection, not the current index: focusing the table makes a row current without the user choosing it.
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)
        return self.table

    def _build_status_bar(self) -> None:
        self.status = label("Starting…")
        self.busy = QProgressBar()
        self.busy.setRange(0, 0)
        self.busy.setFixedWidth(90)
        self.busy.setMaximumHeight(6)
        self.busy.setTextVisible(False)
        self.busy.setAccessibleName("Scanning")
        self.busy.hide()
        self.statusBar().addWidget(self.status, 1)
        self.statusBar().addPermanentWidget(self.busy)

    def _apply_theme(self, *_: object) -> None:
        self.setStyleSheet(theme.stylesheet(theme.current()))
        self.table_model.refresh_colors()
        self.spectrum.update()
        self.history_chart.update()

    # --- Settings ---------------------------------------------------------------------

    def _restore_settings(self) -> None:
        s = self._settings
        geometry = s.value("window/geometry")
        if not (geometry and self.restoreGeometry(geometry)):
            self.resize(self._default_size())
        for key, splitter in (
            ("window/main-splitter", self.main_splitter),
            ("window/bottom-splitter", self.bottom_splitter),
        ):
            state = s.value(key)
            if state:
                splitter.restoreState(state)
        interval = s.value("scan/interval", DEFAULT_SCAN_INTERVAL_S, type=int)
        self.interval.setValue(interval if isinstance(interval, int) else DEFAULT_SCAN_INTERVAL_S)
        auto = s.value("scan/auto-refresh", True, type=bool)
        self.auto_refresh.setChecked(bool(auto))
        self.interval.setEnabled(bool(auto))

    def _save_settings(self) -> None:
        s = self._settings
        s.setValue("window/geometry", self.saveGeometry())
        s.setValue("window/main-splitter", self.main_splitter.saveState())
        s.setValue("window/bottom-splitter", self.bottom_splitter.saveState())
        s.setValue("scan/interval", self.interval.value())
        s.setValue("scan/auto-refresh", self.auto_refresh.isChecked())
        s.sync()

    def _default_size(self) -> QSize:
        """1280 × 860, or less on a small screen."""
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is None:
            return QSize(1280, 860)
        available = screen.availableGeometry()
        return QSize(min(1280, int(available.width() * 0.9)), min(860, int(available.height() * 0.9)))

    # --- Scanning ---------------------------------------------------------------------

    def scan_now(self) -> None:
        if self._viewing is not None:
            self._leave_saved_scan()
        if self._scanning:
            return
        self._scanning = True
        self.scan_action.setEnabled(False)
        self.busy.show()
        self.status.setText("Scanning…")
        self.request_scan.emit()

    def _poll(self) -> None:
        if not self._polling:
            self._polling = True
            self.request_poll.emit()

    def _toggle_auto_refresh(self, enabled: bool) -> None:
        self.interval.setEnabled(enabled)
        if enabled and self._viewing is None:
            self._scan_timer.start()
        else:
            self._scan_timer.stop()

    def _finish_scan(self) -> None:
        self._scanning = False
        self.scan_action.setEnabled(True)
        self.busy.hide()

    def _scan_failed(self, error: ScanError) -> None:
        self._finish_scan()
        if self._viewing is not None:
            return  # the saved scan stays on show, and the next live scan reports the problem again
        message = str(error).rstrip(".")
        if isinstance(error, AccessDeniedError):
            self.banner.show_access_denied(str(error))
            self.banner.show()
            message = "The system is withholding scan results"
        suffix = ". Showing the previous results." if self._live is not None else "."
        self.status.setText(f"⚠ {message}{suffix}")

    def _poll_failed(self, error: ScanError) -> None:
        self._polling = False
        if isinstance(error, AccessDeniedError) and self._viewing is None:
            self.banner.show_access_denied(str(error))
            self.banner.show()

    def apply_result(self, result: ScanResult) -> None:
        """Take in a live scan. While a saved scan is open, it waits until Back to Live."""
        self._finish_scan()
        self._live = result
        if self._viewing is None:
            self._show_live()
        if result.connection:
            self.apply_connection(result.connection, polled=False)

    def apply_connection(self, connection: Connection | None, *, polled: bool = True) -> None:
        if polled:
            self._polling = False
        # The history keeps recording while a saved scan is open, so it has no gap afterwards.
        self._connection = connection
        self._history.append((time.time(), connection.rssi if connection else None))
        if self._viewing is None:
            self.connection_card.set_connection(connection)
            self.history_chart.set_samples(self._history)

    def _show_live(self) -> None:
        result = self._live
        if result is None:
            self._clear()
            return
        self._show(result)
        self.banner.setVisible(result.redacted)
        self.status.setText(f"Last scan {result.timestamp:%H:%M:%S} · {self._summary(result)}")

    def _show(self, result: ScanResult) -> None:
        self._result = result
        for action in self.export_actions:
            action.setEnabled(True)
        if self._band is None:
            self._band = result.connection.band if result.connection else Band.GHZ_2_4
        for band, button in self.band_buttons.items():
            count = sum(n.band is band for n in result.networks)
            button.setText(f"{band.label}  ·  {count}")
        self.band_buttons[self._band].setChecked(True)
        self.band_actions[self._band].setChecked(True)
        self._refresh_band()

    def _clear(self) -> None:
        """Back to how the window starts, before its first scan."""
        self._result = None
        for action in self.export_actions:
            action.setEnabled(False)
        for band, button in self.band_buttons.items():
            button.setText(band.label)
        self.banner.hide()
        self.table_model.set_entries([])
        self.spectrum.set_data(self._band or Band.GHZ_2_4, [], chart_ceiling([]))
        self.recommendations.set_report(None)
        self.status.setText("")

    @staticmethod
    def _summary(result: ScanResult) -> str:
        parts = [f"{len(result.networks)} networks", f"interface {printable(result.interface)}"]
        if result.country:
            parts.append(f"country {printable(result.country)}")
        return " · ".join(parts)

    # --- Saved scans ------------------------------------------------------------------

    def show_saved_scan(self, result: ScanResult, name: str) -> None:
        """Show a scan from a file until Back to Live or Scan Now. Automatic scans pause meanwhile."""
        self._viewing = name
        self._scan_timer.stop()
        self.live_action.setVisible(True)
        self.setWindowTitle(f"{printable(name)} – {APP_NAME}")
        self.banner.hide()  # it's about what this computer may scan, not what's in the file
        self._show(result)
        self.connection_card.set_connection(result.connection)
        self.history_chart.show_message("Saved scans don't include the signal history")
        self.status.setText(f"Saved scan from {result.timestamp:%Y-%m-%d %H:%M:%S} · {self._summary(result)}")

    def _leave_saved_scan(self) -> None:
        self._viewing = None
        self.live_action.setVisible(False)
        self.setWindowTitle(APP_NAME)
        self.connection_card.set_connection(self._connection)
        self.history_chart.set_samples(self._history)
        self._show_live()
        if self.auto_refresh.isChecked():
            self._scan_timer.start()

    # --- Band view --------------------------------------------------------------------

    def select_band(self, band: Band) -> None:
        self._band = band
        self.band_buttons[band].setChecked(True)
        self.band_actions[band].setChecked(True)
        self._refresh_band()

    def _refresh_band(self) -> None:
        if self._result is None or self._band is None:
            return
        band = self._band
        networks = [n for n in self._result.networks if n.band is band]
        indexed = index_networks(networks)
        slots = self._assigners[band].assign([n for _, n in indexed])
        entries = [Entry(i, n, slot) for (i, n), slot in zip(indexed, slots, strict=True)]

        # Resetting the model clears the table selection, so note it first. It can only be
        # carried across rescans when the access point is identifiable by its BSSID.
        selected = self._selected_bssid
        self.spectrum_card.title.setText(f"{band.label} spectrum")
        self.spectrum.set_data(band, entries, chart_ceiling(networks))
        self.table_model.set_entries(entries)
        self.table.setColumnHidden(NetworkTableModel.BSSID, self._result.redacted)
        self.recommendations.set_report(recommend(self._result, band))

        match = next((e for e in entries if selected and e.network.bssid == selected), None)
        if match:
            self._select_entry(match)
        else:
            self._selected_bssid = None
            self.spectrum.set_selected(None)

    def _select_entry(self, entry: Entry | None) -> None:
        if entry is None:
            self.table.clearSelection()
            return
        for row in range(self.proxy.rowCount()):
            index = self.proxy.index(row, 0)
            if index.data(NetworkTableModel.ENTRY_ROLE).index == entry.index:
                self.table.selectionModel().setCurrentIndex(
                    index,
                    QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows,
                )
                self.table.scrollTo(index)
                return

    def _selection_changed(self, *_: object) -> None:
        rows = self.table.selectionModel().selectedRows()
        entry: Entry | None = rows[0].data(NetworkTableModel.ENTRY_ROLE) if rows else None
        self._selected_bssid = entry.network.bssid if entry else None
        self.spectrum.set_selected(entry.index if entry else None)

    # --- Files and About --------------------------------------------------------------

    def _folder(self) -> Path:
        """Where file dialogs start: the last folder used, or the home folder.

        Not Documents or Desktop: iCloud and OneDrive often sync those, and a scan, even a picture of
        one, shows where it was taken.
        """
        folder = self._settings.value("export/folder") or QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.HomeLocation
        )
        return Path(str(folder))

    def _choose(self, caption: str, name: str, filters: str) -> tuple[Path, str] | None:
        """Ask where to save. Returns the path and the chosen filter, or None if cancelled."""
        path, chosen = QFileDialog.getSaveFileName(self, caption, str(self._folder() / name), filters)
        return (Path(path), chosen) if path else None

    def _write(self, caption: str, path: Path, render: Callable[[], bytes]) -> None:
        try:
            path.write_bytes(render())
        except OSError as e:
            QMessageBox.warning(self, caption, f"Couldn't save {path.name}: {e.strerror or e}")
            return
        self._settings.setValue("export/folder", str(path.parent))
        self.statusBar().showMessage(f"Saved {path.name}", 5000)

    def _save_scan(self) -> None:
        result = self._result
        if result is None:
            return
        chosen = self._choose("Save Scan", _file_name(result, "scan", ".json"), "JSON (*.json)")
        if chosen:
            reports = [recommend(result, band) for band in bands_in(result)]
            self._write("Save Scan", chosen[0], (to_json(result, reports) + "\n").encode)

    def _open_scan(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open Scan", str(self._folder()), "JSON (*.json)")
        if not path:
            return
        file = Path(path)
        try:
            result = from_json(file.read_bytes())
        except OSError as e:
            QMessageBox.warning(self, "Open Scan", f"Couldn't open {file.name}: {e.strerror or e}")
            return
        except ScanFileError as e:
            QMessageBox.warning(self, "Open Scan", f"{file.name} isn't a scan saved by {APP_NAME}: {e}.")
            return
        self._settings.setValue("export/folder", str(file.parent))
        self.show_saved_scan(result, file.name)

    def _export_csv(self) -> None:
        result = self._result
        if result is None:
            return
        chosen = self._choose("Export Networks", _file_name(result, "networks", ".csv"), "CSV (*.csv)")
        if chosen:
            # With a byte order mark, Excel reads the file as UTF-8 rather than in the system's code page.
            self._write("Export Networks", chosen[0], lambda: to_csv(result).encode("utf-8-sig"))

    def _export_chart(self) -> None:
        result, band = self._result, self._band
        if result is None or band is None:
            return
        name = _file_name(result, f"spectrum-{band.value}ghz", ".png")
        chosen = self._choose("Export Spectrum Chart", name, "PNG image (*.png);;SVG drawing (*.svg)")
        if not chosen:
            return
        path, chosen_filter = chosen
        if path.suffix.lower() not in (".png", ".svg"):
            path = path.with_name(path.name + (".svg" if "svg" in chosen_filter else ".png"))
        if path.suffix.lower() == ".svg":
            title = f"{band.label} spectrum, {result.timestamp:%Y-%m-%d %H:%M:%S}"
            self._write("Export Spectrum Chart", path, lambda: snapshot.chart_svg(self.spectrum, title))
        else:
            self._write("Export Spectrum Chart", path, lambda: snapshot.chart_png(self.spectrum))

    def _export_snapshot(self) -> None:
        result = self._result
        if result is None:
            return
        chosen = self._choose("Export Window Snapshot", _file_name(result, "snapshot", ".png"), "PNG image (*.png)")
        if chosen:
            # The page, not the window: no toolbar or status bar, and all of it even when it's scrolled.
            self._write("Export Window Snapshot", chosen[0], lambda: snapshot.widget_png(self.page))

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            f"About {APP_NAME}",
            f"<h3>{APP_NAME} {__version__}</h3>"
            "<p>Nearby networks, their spectrum and the quietest channels on 2.4, 5 and 6 GHz Wi-Fi.</p>"
            "<p>Everything runs on this computer. The app doesn't connect to any service.</p>"
            "<p>Released under the MIT License. "
            f"Built with Qt {qVersion()} and PySide6 {pyside_version}, available under the GNU LGPLv3.</p>",
        )

    # --- Location access (macOS) ------------------------------------------------------

    def _request_location(self) -> None:
        if sys.platform != "darwin":
            return
        if not location.can_request():
            self._reopen_as_app()
            return
        status = location.status()
        if status.granted:
            self.banner.hide()
            self.scan_now()
            return
        self.banner.show()  # when asked at startup, no scan has shown it yet
        if status is not location.LocationStatus.NOT_DETERMINED:
            self.banner.show_failed(status)
            return
        self._authorization = location.AuthorizationRequest()
        self._authorization_deadline = time.monotonic() + LOCATION_TIMEOUT_S
        self.banner.show_waiting()
        self._authorization_timer.start()

    def _check_authorization(self) -> None:
        if self._authorization is None:
            return
        status = self._authorization.status
        if status is location.LocationStatus.NOT_DETERMINED and time.monotonic() < self._authorization_deadline:
            return
        self._authorization_timer.stop()
        self._authorization = None
        if status.granted:
            self.banner.hide()
            self.scan_now()
        else:
            self.banner.show_failed(status)

    def _reopen_as_app(self) -> None:
        # macOS drops Location requests from a plain python process without asking (see
        # macos/bundle.py), so continue in Wi-Fi Analyzer.app and ask from there.
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            app = bundle.build()
            bundle.open_app(app, ["-m", "wifianalyzer.gui", "-i", self._scanner.name, "--request-location"])
        except bundle.AppBuildError as e:
            self.banner.show_error(str(e))
            return
        finally:
            QApplication.restoreOverrideCursor()
        self.close()

    # --- Shutdown ---------------------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:
        self._save_settings()
        for timer in (self._poll_timer, self._scan_timer, self._authorization_timer):
            timer.stop()
        # Cut a scan in progress short, then let the worker finish whatever call it's in.
        self._scanner.cancel()
        self._thread.quit()
        self._thread.wait()
        super().closeEvent(event)
