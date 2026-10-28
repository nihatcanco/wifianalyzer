"""Cards around the charts: connection summary, channel recommendations and the access banner."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from .. import APP_NAME, privacy
from ..analysis import BandReport, ChannelScore, interference_level, signal_label, signal_quality, verdict
from ..channels import block_label, is_dfs
from ..display import connection_name, phy_label, withheld_name
from ..macos.location import LocationStatus
from ..models import Connection
from . import theme


def label(
    text: str = "", role: str | None = None, *, point_delta: float = 0, weight: QFont.Weight | None = None
) -> QLabel:
    """A plain-text label. SSIDs come from strangers' routers, so never let Qt parse them as HTML."""
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    if role:
        widget.setProperty("role", role)
    if point_delta or weight is not None:
        font = QFont(widget.font())
        if point_delta:
            font.setPointSizeF(font.pointSizeF() + point_delta)
        if weight is not None:
            font.setWeight(weight)
        widget.setFont(font)
    return widget


def status_dot(status: str, text: str) -> QLabel:
    """A status color always travels with a text label, never alone."""
    widget = QLabel(f'<span style="color:{theme.STATUS[status]}">●</span>&nbsp;{text}')
    widget.setTextFormat(Qt.TextFormat.RichText)
    return widget


def hairline() -> QFrame:
    line = QFrame()
    line.setObjectName("hairline")
    line.setFixedHeight(1)
    return line


class Card(QFrame):
    def __init__(self, title: str | None = None, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("card")
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(16, 12, 16, 14)
        self.layout_.setSpacing(8)
        self.title = label(title or "", "title")
        self.title.setVisible(title is not None)
        self.layout_.addWidget(self.title)


class ConnectionCard(Card):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(None, parent)
        self.caption = label("Connected network", "muted")
        self.name = label(point_delta=4, weight=QFont.Weight.DemiBold)
        self.name.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.signal = label(point_delta=12, weight=QFont.Weight.DemiBold)
        self.quality = QLabel()
        self.quality.setTextFormat(Qt.TextFormat.RichText)

        headline = QHBoxLayout()
        headline.addWidget(self.signal)
        headline.addSpacing(10)
        headline.addWidget(self.quality, alignment=Qt.AlignmentFlag.AlignBottom)
        headline.addStretch()

        self.details = QGridLayout()
        self.details.setHorizontalSpacing(12)
        self.details.setVerticalSpacing(4)
        self._values: dict[str, QLabel] = {}
        pairs = [("Channel", "Tx rate"), ("Band", "Noise"), ("Security", "Standard"), ("BSSID", None)]
        for row, keys in enumerate(pairs):
            for column, key in zip((0, 2), keys, strict=True):
                if key is None:
                    continue
                self.details.addWidget(label(key, "muted"), row, column)
                value = label()
                value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                self._values[key] = value
                self.details.addWidget(value, row, column + 1)
        self.details.setColumnStretch(1, 1)
        self.details.setColumnStretch(3, 1)

        self.layout_.addWidget(self.caption)
        self.layout_.addWidget(self.name)
        self.layout_.addLayout(headline)
        self.layout_.addSpacing(4)
        self.layout_.addLayout(self.details)
        self.layout_.addStretch()
        self.set_connection(None)

    def set_connection(self, conn: Connection | None) -> None:
        for widget in self._values.values():
            widget.setText("—")
        if conn is None:
            self.name.setText("Not connected")
            self.name.setProperty("role", "muted")
            self.signal.setText("")
            self.quality.setText("")
            self._restyle(self.name)
            return

        name = connection_name(conn.ssid)
        self.name.setText(name or withheld_name())
        self.name.setProperty("role", None if name else "muted")
        self._restyle(self.name)
        level = signal_label(conn.rssi)
        self.signal.setText(f"{conn.rssi} dBm")
        self.quality.setText(
            f'<span style="color:{theme.STATUS[theme.SIGNAL_STATUS[level]]}">●</span>&nbsp;'
            f"{level.capitalize()} · {signal_quality(conn.rssi)}%"
        )
        channel = str(conn.channel)
        if conn.width > 20:
            channel += f" ({block_label(conn.band, conn.channel, conn.width)})"
        if is_dfs(conn.band, conn.channel, conn.width):
            channel += " · DFS"
        self._values["Channel"].setText(channel)
        self._values["Band"].setText(f"{conn.band.label} · {conn.width} MHz")
        self._values["Tx rate"].setText(f"{conn.tx_rate:.0f} Mbps")
        if conn.noise is not None:
            self._values["Noise"].setText(f"{conn.noise} dBm · SNR {conn.snr} dB")
        self._values["Security"].setText(conn.security)
        self._values["Standard"].setText(phy_label(conn.phy, conn.band))
        if conn.bssid:
            self._values["BSSID"].setText(conn.bssid)

    @staticmethod
    def _restyle(widget: QWidget) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)


class RecommendationsCard(Card):
    def __init__(self, parent: QWidget | None = None):
        super().__init__("Channel recommendation", parent)
        self.subtitle = label(role="muted")
        self.subtitle.setWordWrap(True)
        self.grid_host = QWidget()
        self.verdict = label(role="secondary")
        self.verdict.setWordWrap(True)
        self.layout_.addWidget(self.subtitle)
        self.layout_.addWidget(self.grid_host)
        self.layout_.addWidget(self.verdict)
        self.layout_.addStretch()
        self.set_report(None)

    def _fresh_grid(self) -> None:
        # QGridLayout never forgets rows it once had, so rebuild it rather than emptying it.
        host = QWidget()
        self.grid = QGridLayout(host)
        self.grid.setContentsMargins(0, 4, 0, 0)
        self.grid.setHorizontalSpacing(16)
        self.grid.setVerticalSpacing(6)
        self.layout_.replaceWidget(self.grid_host, host)
        self.grid_host.deleteLater()
        self.grid_host = host

    def set_report(self, report: BandReport | None) -> None:
        self._fresh_grid()
        if report is None or not report.ranked:
            self.subtitle.setText("Scan to see which channels are quietest.")
            self.verdict.setText("")
            return

        self.subtitle.setText(f"{report.band.label} · {report.width} MHz channels, quietest first")
        self.subtitle.setToolTip(
            "Channels are ranked by the combined signal of neighbouring networks that overlap them. "
            "Your own network doesn't count."
        )
        for column, heading in enumerate(("Channel", "Networks", "Interference", "")):
            self.grid.addWidget(label(heading, "muted"), 0, column)
        for rank, score in enumerate(report.ranked[:3], start=1):
            self._add_row(rank, score, best=rank == 1)
        if report.current is not None:
            row = self.grid.rowCount()
            self.grid.addWidget(hairline(), row, 0, 1, 4)
            self._add_row(row + 1, report.current, yours=True)
            self.verdict.setText(f"{verdict(report)}.")
        else:
            self.verdict.setText(f"You're not connected on {report.band.label}.")
        self.grid.setColumnStretch(3, 1)

    def _add_row(self, row: int, score: ChannelScore, *, best: bool = False, yours: bool = False) -> None:
        name = block_label(score.band, score.channel, score.width)
        self.grid.addWidget(
            label(f"{name} (yours)" if yours else name, weight=QFont.Weight.DemiBold if best else None), row, 0
        )
        networks = label(str(score.networks))
        networks.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.grid.addWidget(networks, row, 1)
        level = interference_level(score)
        reading = "clear" if score.interference_dbm is None else f"{score.interference_dbm:.0f} dBm"
        self.grid.addWidget(status_dot(theme.INTERFERENCE_STATUS[level], reading), row, 2)
        badges = QHBoxLayout()
        badges.setSpacing(4)
        if best:
            badges.addWidget(label("Best", "badge-good"))
        if score.dfs:
            badges.addWidget(label("DFS", "badge"))
        badges.addStretch()
        holder = QWidget()
        holder.setLayout(badges)
        badges.setContentsMargins(0, 0, 0, 0)
        self.grid.addWidget(holder, row, 3)


class AccessBanner(QFrame):
    """Explains why networks or their names are hidden, and how to allow access.

    On macOS it offers to ask for Location access; elsewhere it points to the system settings.
    """

    allow_clicked = Signal()
    settings_clicked = Signal()

    def __init__(self, parent: QWidget | None = None, *, can_ask: bool = False, reopens_as_app: bool = False):
        super().__init__(parent)
        self.setObjectName("banner")
        self._can_ask = can_ask
        self._reopens_as_app = reopens_as_app
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)
        icon = label("⚠", point_delta=4)
        icon.setStyleSheet(f"color: {theme.STATUS['warning']};")
        self.message = label()
        self.message.setWordWrap(True)
        self.message.setAccessibleName("Access notice")
        self.allow = QPushButton("Allow Location Access")
        self.allow.setDefault(True)
        self.settings = QPushButton("Open Settings")
        self.settings.setVisible(privacy.settings_url() is not None)
        self.allow.clicked.connect(self.allow_clicked)
        self.settings.clicked.connect(self.settings_clicked)
        layout.addWidget(icon, alignment=Qt.AlignmentFlag.AlignTop)
        layout.addWidget(self.message, stretch=1)
        layout.addWidget(self.allow)
        layout.addWidget(self.settings)
        self.show_hidden_names()

    def show_hidden_names(self) -> None:
        text = "Network names and BSSIDs are hidden. macOS only shares them with apps that have Location access."
        if self._reopens_as_app:
            text += f" It can only ask apps, so {APP_NAME} will reopen as one to ask you."
        self.message.setText(text)
        self.allow.setEnabled(True)
        self.allow.setVisible(self._can_ask)

    def show_waiting(self) -> None:
        self.message.setText("Waiting for your answer in the macOS permission prompt…")
        self.allow.setEnabled(False)

    def show_failed(self, status: LocationStatus) -> None:
        reason = "was denied" if status is LocationStatus.DENIED else "wasn't granted"
        self.message.setText(
            f"Location access {reason}. You can turn it on for {APP_NAME} in {privacy.settings_path()}."
        )
        self.allow.setVisible(False)

    def show_error(self, message: str) -> None:
        self.message.setText(f"Couldn't build {APP_NAME}.app, which macOS needs to ask you: {message}")
        self.allow.setEnabled(True)

    def show_access_denied(self, message: str) -> None:
        """The system refuses to list networks at all until the user allows it in its settings."""
        self.message.setText(message)
        self.allow.setVisible(False)
