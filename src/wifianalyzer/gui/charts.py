"""Custom-painted charts: a band's spectrum and the connection's signal history."""

from __future__ import annotations

import html
import math
import time
from collections.abc import Sequence

from PySide6.QtCore import QEvent, QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QFont, QFontMetricsF, QMouseEvent, QPainter, QPainterPath, QPaintEvent, QPen
from PySide6.QtWidgets import QToolTip, QWidget

from ..analysis import signal_label
from ..channels import CHANNELS, DFS_RANGE, block_label, channel_frequency, is_dfs, plot_segments, span
from ..display import FLOOR_DBM, curve_dbm, network_name, phy_label
from ..models import Band
from . import theme
from .entries import Entry

_HIT_TOLERANCE = 12.0  # px either side of a line, for a 24px hover target
_SEGMENT_GAP = 14.0  # px between the 5 GHz sub-bands


def _small_font(base: QFont, delta: float = -1.5) -> QFont:
    font = QFont(base)
    font.setPointSizeF(max(8.0, base.pointSizeF() + delta))
    return font


def tooltip_html(entry: Entry, t: theme.Theme) -> str:
    """Tooltip for a network: the reading first, then what it belongs to."""
    n = entry.network
    key = f'<span style="color:{t.series_color(entry.slot).name()}">━━</span>'
    name = html.escape(network_name(n))  # SSIDs are chosen by whoever runs the access point
    channel = f"Channel {block_label(n.band, n.channel, n.width)} · {n.width} MHz"
    if is_dfs(n.band, n.channel, n.width):
        channel += " · DFS"
    lines = [
        f"<b>{n.rssi} dBm</b> &nbsp;{signal_label(n.rssi)}",
        f"{key} #{entry.index} · {name}" + (" · <i>connected</i>" if n.is_current else ""),
        channel,
        f"{html.escape(n.security)} · {phy_label(n.phy, n.band)}",
    ]
    if n.bssid:
        lines.append(html.escape(n.bssid))
    return "<br>".join(lines)


class _Axis:
    """Maps frequencies to x pixels, leaving a gap between the band's segments."""

    def __init__(self, segments: Sequence[tuple[float, float]], left: float, width: float):
        gaps = _SEGMENT_GAP * (len(segments) - 1)
        self.per_mhz = (width - gaps) / sum(hi - lo for lo, hi in segments)
        self.ranges: list[tuple[float, float, float]] = []
        x = left
        for lo, hi in segments:
            self.ranges.append((lo, hi, x))
            x += (hi - lo) * self.per_mhz + _SEGMENT_GAP

    def x(self, mhz: float) -> float | None:
        for lo, hi, x0 in self.ranges:
            if lo <= mhz <= hi:
                return x0 + (mhz - lo) * self.per_mhz
        return None

    def mhz(self, x: float) -> float | None:
        for lo, hi, x0 in self.ranges:
            mhz = lo + (x - x0) / self.per_mhz
            if lo <= mhz <= hi:
                return mhz
        return None


class SpectrumChart(QWidget):
    """Every network on a band as a curve over the frequencies it occupies, as tall as its signal."""

    hovered = Signal(object)  # Entry | None
    activated = Signal(object)  # Entry, or None for a click on empty space

    MARGINS = (44.0, 22.0, 16.0, 30.0)  # left, top, right, bottom

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setMouseTracking(True)
        self.setMinimumHeight(160)
        self.setAccessibleName("Spectrum")
        self._band = Band.GHZ_2_4
        self._entries: list[Entry] = []
        self._ceiling = -40
        self._hover: Entry | None = None
        self._selected: int | None = None

    def set_data(self, band: Band, entries: Sequence[Entry], ceiling: int) -> None:
        self._band, self._entries, self._ceiling = band, list(entries), ceiling
        self._hover = None
        self.setAccessibleDescription(self._summary())
        self.update()

    def _summary(self) -> str:
        """The chart in words, for screen readers."""
        if not self._entries:
            return f"No networks found on {self._band.label}."
        strongest = min(self._entries, key=lambda e: e.index).network
        return (
            f"{len(self._entries)} networks on {self._band.label}. The strongest, {network_name(strongest)}, "
            f"is on channel {block_label(strongest.band, strongest.channel, strongest.width)} at {strongest.rssi} dBm."
        )

    def set_selected(self, index: int | None) -> None:
        if index != self._selected:
            self._selected = index
            self.update()

    # --- Geometry ---------------------------------------------------------------------

    def _plot_rect(self) -> QRectF:
        left, top, right, bottom = self.MARGINS
        return QRectF(self.rect()).adjusted(left, top, -right, -bottom)

    def _axis(self, plot: QRectF) -> _Axis:
        segments = plot_segments(self._band, (e.network for e in self._entries))
        return _Axis(segments, plot.left(), plot.width())

    def _y(self, dbm: float, plot: QRectF) -> float:
        fraction = (dbm - FLOOR_DBM) / (self._ceiling - FLOOR_DBM)
        return plot.bottom() - max(0.0, min(1.0, fraction)) * plot.height()

    def _curve(self, entry: Entry, axis: _Axis, plot: QRectF) -> QPainterPath | None:
        n = entry.network
        lo, hi = span(n.band, n.channel, n.width)
        center, half = (lo + hi) / 2, (hi - lo) / 2
        path = QPainterPath()
        started = False
        steps = 64
        for k in range(steps + 1):
            mhz = lo + (hi - lo) * k / steps
            x = axis.x(mhz)
            if x is None:
                continue
            point = QPointF(x, self._y(curve_dbm(n.rssi, (mhz - center) / half), plot))
            if started:
                path.lineTo(point)
            else:
                path.moveTo(point)
                started = True
        return path if started else None

    def entry_at(self, pos: QPointF) -> Entry | None:
        """The network under the pointer: the nearest curve within reach, or the innermost one around it."""
        plot = self._plot_rect()
        if not self._entries or not plot.adjusted(0, -_HIT_TOLERANCE, 0, 0).contains(pos):
            return None
        mhz = self._axis(plot).mhz(pos.x())
        if mhz is None:
            return None
        best, best_distance = None, math.inf
        for entry in self._entries:
            n = entry.network
            lo, hi = span(n.band, n.channel, n.width)
            if not lo <= mhz <= hi:
                continue
            y = self._y(curve_dbm(n.rssi, (mhz - (lo + hi) / 2) / ((hi - lo) / 2)), plot)
            distance = abs(pos.y() - y)
            if (distance <= _HIT_TOLERANCE or pos.y() > y) and distance < best_distance:
                best, best_distance = entry, distance
        return best

    # --- Painting ---------------------------------------------------------------------

    def paintEvent(self, event: QPaintEvent) -> None:
        plot = self._plot_rect()
        if plot.width() < 40 or plot.height() < 40:
            return
        with QPainter(self) as painter:
            self._paint(painter, plot)

    def _paint(self, painter: QPainter, plot: QRectF) -> None:
        t = theme.current()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        axis = self._axis(plot)
        small = _small_font(self.font())
        painter.setFont(small)
        metrics = QFontMetricsF(small)

        self._paint_dfs(painter, t, axis, plot, metrics)
        self._paint_grid(painter, t, axis, plot, metrics)
        self._paint_channels(painter, t, axis, plot, metrics)

        if not self._entries:
            painter.setPen(t.qcolor(t.muted))
            painter.setFont(self.font())
            painter.drawText(plot, Qt.AlignmentFlag.AlignCenter, f"No networks found on {self._band.label}")
            return

        focus = self._hover.index if self._hover else self._selected
        curves = [(e, path) for e in self._entries if (path := self._curve(e, axis, plot)) is not None]
        # Gray networks first, then colored ones weakest first (yours wins ties), the focused one on top.
        order = sorted(
            curves,
            key=lambda c: (c[0].index == focus, c[0].slot is not None, c[0].network.rssi, c[0].network.is_current),
        )
        for entry, path in order:
            self._paint_curve(painter, t, entry, path, focus)
        self._paint_labels(painter, t, axis, plot, metrics, focus)

    def _paint_dfs(self, painter: QPainter, t: theme.Theme, axis: _Axis, plot: QRectF, metrics: QFontMetricsF) -> None:
        if self._band is not Band.GHZ_5:
            return
        for lo, hi, _ in axis.ranges:
            start, end = max(lo, DFS_RANGE[0]), min(hi, DFS_RANGE[1])
            x0, x1 = axis.x(start), axis.x(end)
            if start >= end or x0 is None or x1 is None:
                continue
            band = QRectF(x0, plot.top(), x1 - x0, plot.height())
            painter.fillRect(band, t.qcolor(t.text, 0.035))
            painter.setPen(t.qcolor(t.muted))
            painter.drawText(QPointF(x0 + 4, plot.top() - 6), "DFS")

    def _paint_grid(self, painter: QPainter, t: theme.Theme, axis: _Axis, plot: QRectF, metrics: QFontMetricsF) -> None:
        for dbm in range(FLOOR_DBM, self._ceiling + 1, 10):
            y = self._y(dbm, plot)
            painter.setPen(QPen(t.qcolor(t.axis if dbm == FLOOR_DBM else t.grid), 1))
            for lo, hi, x0 in axis.ranges:
                painter.drawLine(QPointF(x0, y), QPointF(x0 + (hi - lo) * axis.per_mhz, y))
            painter.setPen(t.qcolor(t.muted))
            label = QRectF(0, y - metrics.height() / 2, plot.left() - 8, metrics.height())
            painter.drawText(label, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, str(dbm))
        painter.drawText(QPointF(4, plot.top() - 6), "dBm")

    def _paint_channels(
        self, painter: QPainter, t: theme.Theme, axis: _Axis, plot: QRectF, metrics: QFontMetricsF
    ) -> None:
        last_right = -math.inf
        for channel in CHANNELS[self._band]:
            x = axis.x(channel_frequency(self._band, channel))
            if x is None:
                continue
            text = str(channel)
            width = metrics.horizontalAdvance(text)
            left = x - width / 2
            if left < last_right + 6 or left + width > self.width():
                continue
            last_right = left + width
            painter.setPen(QPen(t.qcolor(t.axis), 1))
            painter.drawLine(QPointF(x, plot.bottom()), QPointF(x, plot.bottom() + 4))
            painter.setPen(t.qcolor(t.muted))
            painter.drawText(QPointF(left, plot.bottom() + 6 + metrics.ascent()), text)

    def _paint_curve(
        self, painter: QPainter, t: theme.Theme, entry: Entry, path: QPainterPath, focus: int | None
    ) -> None:
        colored = entry.slot is not None
        if focus is None:
            line_alpha, fill_alpha = (1.0, 0.10) if colored else (0.55, 0.05)
        elif entry.index == focus:
            line_alpha, fill_alpha = 1.0, 0.20
        else:
            line_alpha, fill_alpha = 0.25, 0.03
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(t.series_color(entry.slot, fill_alpha))
        painter.drawPath(path)
        pen = QPen(t.series_color(entry.slot, line_alpha), 2.0 if colored or entry.index == focus else 1.25)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)

    def _paint_labels(
        self, painter: QPainter, t: theme.Theme, axis: _Axis, plot: QRectF, metrics: QFontMetricsF, focus: int | None
    ) -> None:
        """Label colored networks (and the focused one) above their peaks; skip any that would collide.

        Near-identical curves, such as one access point's several SSIDs, share a label.
        """
        # The focused network, then yours, then the strongest: they win any collision.
        candidates = sorted(
            (e for e in self._entries if e.slot is not None or e.index == focus),
            key=lambda e: (e.index != focus, not e.network.is_current, -e.network.rssi),
        )
        groups: list[tuple[float, float, list[Entry]]] = []
        for entry in candidates:
            n = entry.network
            lo, hi = span(n.band, n.channel, n.width)
            x = axis.x((lo + hi) / 2)
            if x is None:
                continue
            y = self._y(n.rssi, plot)
            group = next((g for g in groups if abs(g[0] - x) < 1 and abs(g[1] - y) < metrics.height()), None)
            if group:
                group[2].append(entry)
            else:
                groups.append((x, y, [entry]))

        placed: list[QRectF] = []
        dot = 8.0
        for x, y, members in groups:
            names = [
                (network_name(m.network) if m.network.ssid else f"#{m.index}")
                + (" (connected)" if m.network.is_current else "")
                for m in members
            ]
            text = ", ".join(names[:2]) + (f" +{len(names) - 2}" if len(names) > 2 else "")
            text = metrics.elidedText(text, Qt.TextElideMode.ElideRight, 220)
            width = dot + 4 + metrics.horizontalAdvance(text)
            left = max(plot.left(), min(plot.right() - width, x - width / 2))
            rect = QRectF(left, y - 8 - metrics.height(), width, metrics.height())
            if rect.top() < 0:
                rect.moveTop(0)
            if any(rect.adjusted(-3, -1, 3, 1).intersects(other) for other in placed):
                continue
            placed.append(rect)
            is_focus = any(m.index == focus for m in members)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(t.series_color(members[0].slot))
            painter.drawEllipse(QRectF(rect.left(), rect.center().y() - dot / 2, dot, dot))
            painter.setPen(t.qcolor(t.text if is_focus else t.text_secondary))
            painter.drawText(QPointF(rect.left() + dot + 4, rect.top() + metrics.ascent()), text)

    # --- Interaction ------------------------------------------------------------------

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        entry = self.entry_at(event.position())
        if entry != self._hover:
            self._hover = entry
            self.update()
            self.hovered.emit(entry)
        if entry is None:
            QToolTip.hideText()
        else:
            QToolTip.showText(event.globalPosition().toPoint(), tooltip_html(entry, theme.current()), self)

    def leaveEvent(self, event: QEvent) -> None:
        if self._hover is not None:
            self._hover = None
            self.update()
            self.hovered.emit(None)
        QToolTip.hideText()

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.activated.emit(self.entry_at(event.position()))


class SignalHistoryChart(QWidget):
    """The connected network's signal over the last few minutes."""

    WINDOW_SECONDS = 300
    MARGINS = (44.0, 12.0, 70.0, 24.0)  # right margin leaves room for the end label

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setMouseTracking(True)
        self.setMinimumHeight(120)
        self.setAccessibleName("Signal strength history")
        self._samples: list[tuple[float, int | None]] = []
        self._crosshair: tuple[float, int] | None = None

    def set_samples(self, samples: Sequence[tuple[float, int | None]]) -> None:
        """Samples are (unix time, RSSI), with None while disconnected."""
        self._samples = list(samples)
        readings = [v for _, v in self._samples if v is not None]
        if readings:
            self.setAccessibleDescription(
                f"Now {readings[-1]} dBm. Over the last {self.WINDOW_SECONDS // 60} minutes: "
                f"lowest {min(readings)}, highest {max(readings)} dBm."
            )
        self.update()

    def _plot_rect(self) -> QRectF:
        left, top, right, bottom = self.MARGINS
        return QRectF(self.rect()).adjusted(left, top, -right, -bottom)

    def _range(self) -> tuple[int, int]:
        values = [v for _, v in self._samples if v is not None]
        lo = math.floor((min(values) - 3) / 10) * 10
        hi = math.ceil((max(values) + 3) / 10) * 10
        if hi - lo < 20:
            hi = lo + 20
        return max(FLOOR_DBM, lo), min(-10, hi)

    def _point(self, sample_time: float, rssi: float, now: float, plot: QRectF, lo: int, hi: int) -> QPointF:
        x = plot.right() - (now - sample_time) / self.WINDOW_SECONDS * plot.width()
        y = plot.bottom() - (rssi - lo) / (hi - lo) * plot.height()
        return QPointF(x, y)

    def paintEvent(self, event: QPaintEvent) -> None:
        with QPainter(self) as painter:
            self._paint(painter)

    def _paint(self, painter: QPainter) -> None:
        t = theme.current()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        plot = self._plot_rect()
        small = _small_font(self.font())
        painter.setFont(small)
        metrics = QFontMetricsF(small)

        if not any(v is not None for _, v in self._samples):
            painter.setPen(t.qcolor(t.muted))
            message = "Not connected" if self._samples else "Waiting for the first reading…"
            painter.drawText(QRectF(self.rect()), Qt.AlignmentFlag.AlignCenter, message)
            return

        lo, hi = self._range()
        now = self._samples[-1][0]
        self._paint_axes(painter, t, plot, metrics, lo, hi)
        self._paint_line(painter, t, plot, now, lo, hi)

        last_time, last_rssi = next((s, v) for s, v in reversed(self._samples) if v is not None)
        end = self._point(last_time, last_rssi, now, plot, lo, hi)
        self._paint_dot(painter, t, end)
        painter.setPen(t.qcolor(t.text))
        painter.drawText(QPointF(end.x() + 10, end.y() + metrics.ascent() / 2 - 1), f"{last_rssi} dBm")

        if self._crosshair is not None:
            sample_time, rssi = self._crosshair
            point = self._point(sample_time, rssi, now, plot, lo, hi)
            painter.setPen(QPen(t.qcolor(t.axis), 1))
            painter.drawLine(QPointF(point.x(), plot.top()), QPointF(point.x(), plot.bottom()))
            self._paint_dot(painter, t, point)

    def _paint_axes(
        self, painter: QPainter, t: theme.Theme, plot: QRectF, metrics: QFontMetricsF, lo: int, hi: int
    ) -> None:
        step = 5 if hi - lo <= 30 else 10
        for dbm in range(lo, hi + 1, step):
            y = plot.bottom() - (dbm - lo) / (hi - lo) * plot.height()
            painter.setPen(QPen(t.qcolor(t.axis if dbm == lo else t.grid), 1))
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            painter.setPen(t.qcolor(t.muted))
            label = QRectF(0, y - metrics.height() / 2, plot.left() - 8, metrics.height())
            painter.drawText(label, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, str(dbm))
        for minutes in range(self.WINDOW_SECONDS // 60 + 1):
            x = plot.right() - minutes * 60 / self.WINDOW_SECONDS * plot.width()
            text = "now" if minutes == 0 else f"−{minutes}m"
            width = metrics.horizontalAdvance(text)
            painter.drawText(QPointF(x - width / 2, plot.bottom() + 6 + metrics.ascent()), text)

    def _paint_line(self, painter: QPainter, t: theme.Theme, plot: QRectF, now: float, lo: int, hi: int) -> None:
        # Split into runs at disconnections, so the line doesn't bridge the gap.
        runs: list[list[QPointF]] = [[]]
        for sample_time, rssi in self._samples:
            if now - sample_time > self.WINDOW_SECONDS:
                continue
            if rssi is None:
                runs.append([])
            else:
                runs[-1].append(self._point(sample_time, rssi, now, plot, lo, hi))
        line = QPen(t.series_color(0), 2.0)
        line.setCapStyle(Qt.PenCapStyle.RoundCap)
        line.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.save()
        painter.setClipRect(plot.adjusted(-2, -2, 2, 2))
        for run in (r for r in runs if r):
            path = QPainterPath(run[0])
            for point in run[1:]:
                path.lineTo(point)
            area = QPainterPath(path)
            area.lineTo(run[-1].x(), plot.bottom())
            area.lineTo(run[0].x(), plot.bottom())
            area.closeSubpath()
            painter.fillPath(area, t.series_color(0, 0.10))
            painter.strokePath(path, line)
        painter.restore()

    @staticmethod
    def _paint_dot(painter: QPainter, t: theme.Theme, center: QPointF) -> None:
        painter.setPen(QPen(t.qcolor(t.surface), 2))  # surface ring keeps the dot legible on the line
        painter.setBrush(t.series_color(0))
        painter.drawEllipse(center, 5, 5)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        readings = [(s, v) for s, v in self._samples if v is not None]
        plot = self._plot_rect()
        if not readings or not plot.adjusted(-8, 0, 8, 0).contains(event.position()):
            self.leaveEvent(event)
            return
        now = self._samples[-1][0]
        at = now - (plot.right() - event.position().x()) / plot.width() * self.WINDOW_SECONDS
        sample_time, rssi = min(readings, key=lambda r: abs(r[0] - at))
        self._crosshair = (sample_time, rssi)
        self.update()
        clock = time.strftime("%H:%M:%S", time.localtime(sample_time))
        QToolTip.showText(
            event.globalPosition().toPoint(), f"<b>{rssi} dBm</b> &nbsp;{signal_label(rssi)}<br>{clock}", self
        )

    def leaveEvent(self, event: QEvent) -> None:
        if self._crosshair is not None:
            self._crosshair = None
            self.update()
        QToolTip.hideText()
