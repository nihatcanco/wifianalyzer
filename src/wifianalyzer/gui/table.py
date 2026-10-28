"""The network table: a model over the window's entries and a delegate that draws signal meters."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QPersistentModelIndex, QRectF, QSize, Qt
from PySide6.QtGui import QFont, QGuiApplication, QPainter, QPixmap
from PySide6.QtGui import Qt as GuiQt  # QtGui's half of the Qt namespace, with the rich-text helpers
from PySide6.QtWidgets import QApplication, QStyle, QStyledItemDelegate, QStyleOptionViewItem

from ..analysis import signal_label, signal_quality
from ..channels import block_label, is_dfs
from ..display import network_name, phy_label
from . import theme
from .entries import Entry

ModelIndex = QModelIndex | QPersistentModelIndex
_ROOT = QModelIndex()


class NetworkTableModel(QAbstractTableModel):
    COLUMNS = ("#", "Network", "BSSID", "Signal", "Channel", "Width", "Security", "Standard", "SNR")
    INDEX, NAME, BSSID, SIGNAL, CHANNEL, WIDTH, SECURITY, STANDARD, SNR = range(len(COLUMNS))
    SORT_ROLE = Qt.ItemDataRole.UserRole + 1
    ENTRY_ROLE = Qt.ItemDataRole.UserRole + 2

    _NUMERIC = frozenset({INDEX, CHANNEL, WIDTH, SNR})

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._entries: list[Entry] = []
        self._sort: tuple[int, Qt.SortOrder] | None = None

    def show_sort(self, column: int, order: Qt.SortOrder) -> None:
        """Mark the sorted column with an arrow in its title.

        The header's own indicator would sit on top of right-aligned titles once the header is styled.
        """
        self._sort = (column, order)
        self.headerDataChanged.emit(Qt.Orientation.Horizontal, 0, len(self.COLUMNS) - 1)

    def set_entries(self, entries: Sequence[Entry]) -> None:
        self.beginResetModel()
        self._entries = list(entries)
        self.endResetModel()

    def refresh_colors(self) -> None:
        if self._entries:
            last = self.index(len(self._entries) - 1, len(self.COLUMNS) - 1)
            self.dataChanged.emit(self.index(0, 0), last)

    def rowCount(self, parent: ModelIndex = _ROOT) -> int:
        return 0 if parent.isValid() else len(self._entries)

    def columnCount(self, parent: ModelIndex = _ROOT) -> int:
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation is Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if self._sort and self._sort[0] == section:
                arrow = "↑" if self._sort[1] == Qt.SortOrder.AscendingOrder else "↓"
                return f"{self.COLUMNS[section]} {arrow}"
            return self.COLUMNS[section]
        if orientation is Qt.Orientation.Horizontal and role == Qt.ItemDataRole.TextAlignmentRole:
            return self._alignment(section)
        return None

    def _alignment(self, column: int) -> Qt.AlignmentFlag:
        horizontal = Qt.AlignmentFlag.AlignRight if column in self._NUMERIC else Qt.AlignmentFlag.AlignLeft
        return horizontal | Qt.AlignmentFlag.AlignVCenter

    def data(self, index: ModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        entry = self._entries[index.row()]
        n = entry.network
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(entry, column)
        if role == self.SORT_ROLE:
            return self._sort_key(entry, column)
        if role == self.ENTRY_ROLE:
            return entry
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return self._alignment(column)
        if role == Qt.ItemDataRole.DecorationRole and column == self.INDEX:
            return _swatch(entry.slot)
        if role == Qt.ItemDataRole.FontRole and n.is_current:
            font = QFont()
            font.setBold(True)
            return font
        if role == Qt.ItemDataRole.ForegroundRole and self._display(entry, column) == "—":
            return theme.current().qcolor(theme.current().muted)
        if role == Qt.ItemDataRole.ToolTipRole:
            # Qt renders tooltips as HTML whenever they look like it, and names come from strangers.
            tooltip = self._tooltip(entry, column)
            return GuiQt.convertFromPlainText(tooltip) if tooltip else None
        return None

    def _display(self, entry: Entry, column: int) -> str:
        n = entry.network
        if column == self.INDEX:
            return str(entry.index)
        if column == self.NAME:
            return network_name(n)
        if column == self.BSSID:
            return n.bssid or "—"
        if column == self.SIGNAL:
            return f"{n.rssi} dBm"
        if column == self.CHANNEL:
            return f"{n.channel}" + ("  DFS" if is_dfs(n.band, n.channel, n.width) else "")
        if column == self.WIDTH:
            return f"{n.width} MHz"
        if column == self.SECURITY:
            return n.security
        if column == self.STANDARD:
            return phy_label(n.phy, n.band)
        return "—" if n.snr is None else f"{n.snr} dB"

    def _sort_key(self, entry: Entry, column: int) -> int | str:
        n = entry.network
        keys: dict[int, int | str] = {
            self.INDEX: entry.index,
            self.NAME: network_name(n).casefold(),
            self.BSSID: n.bssid or "",
            self.SIGNAL: n.rssi,
            self.CHANNEL: n.channel,
            self.WIDTH: n.width,
            self.SECURITY: n.security,
            self.STANDARD: n.phy,
            self.SNR: -1000 if n.snr is None else n.snr,
        }
        return keys[column]

    def _tooltip(self, entry: Entry, column: int) -> str | None:
        n = entry.network
        if column == self.NAME:
            return network_name(n) + (" (connected)" if n.is_current else "")
        if column == self.SIGNAL:
            return f"{signal_label(n.rssi).capitalize()} · {signal_quality(n.rssi)}% quality"
        if column == self.CHANNEL:
            return f"Channel {block_label(n.band, n.channel, n.width)} on {n.band.label}"
        return None


_swatches: dict[tuple[bool, int | None], QPixmap] = {}


def _swatch(slot: int | None) -> QPixmap:
    """A rounded square in the network's chart color: the legend for the spectrum's filled curves."""
    t = theme.current()
    key = (t.dark, slot)
    if key not in _swatches:
        app = QGuiApplication.instance()
        ratio = app.devicePixelRatio() if isinstance(app, QGuiApplication) else 1.0
        pixmap = QPixmap(round(10 * ratio), round(10 * ratio))
        pixmap.setDevicePixelRatio(ratio)
        pixmap.fill(Qt.GlobalColor.transparent)
        with QPainter(pixmap) as painter:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(t.series_color(slot))
            painter.drawRoundedRect(QRectF(0, 0, 10, 10), 2.5, 2.5)
        _swatches[key] = pixmap
    return _swatches[key]


class SignalDelegate(QStyledItemDelegate):
    """Draws the RSSI followed by a quality meter colored by signal status."""

    METER_WIDTH = 56.0

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: ModelIndex) -> None:
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        text = opt.text
        opt.text = ""
        style = opt.widget.style() if opt.widget else QApplication.style()
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, opt.widget)

        entry: Entry = index.data(NetworkTableModel.ENTRY_ROLE)
        rssi = entry.network.rssi
        rect = QRectF(opt.rect).adjusted(6, 0, -6, 0)
        selected = bool(opt.state & QStyle.StateFlag.State_Selected)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setFont(opt.font)
        painter.setPen(opt.palette.highlightedText().color() if selected else opt.palette.text().color())
        text_rect = QRectF(rect.left(), rect.top(), 58, rect.height())
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, text)

        status = theme.STATUS[theme.SIGNAL_STATUS[signal_label(rssi)]]
        t = theme.current()
        track = QRectF(text_rect.right() + 10, rect.center().y() - 3, self.METER_WIDTH, 6)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(t.qcolor(status, 0.22))
        painter.drawRoundedRect(track, 3, 3)
        filled = QRectF(track)
        filled.setWidth(max(6.0, track.width() * signal_quality(rssi) / 100))
        painter.setBrush(t.qcolor(status))
        painter.drawRoundedRect(filled, 3, 3)
        painter.restore()

    def sizeHint(self, option: QStyleOptionViewItem, index: ModelIndex) -> QSize:
        size = super().sizeHint(option, index)
        return QSize(int(58 + 10 + self.METER_WIDTH + 16), size.height())
