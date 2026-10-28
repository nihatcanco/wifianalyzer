"""The app's icon: a few networks' spectrum curves, drawn in code so it's sharp at every size."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap

# Center, half width and height of each curve on a 64-unit grid, with its color.
_CURVES = (
    (21.0, 13.0, 27.0, "#3987e5"),
    (43.0, 13.0, 33.0, "#1baf7a"),
    (33.0, 9.0, 18.0, "#eb6834"),
)
_BASELINE = 48.0
_SIZES = (16, 24, 32, 48, 64, 128, 256, 512)


def app_icon() -> QIcon:
    icon = QIcon()
    for size in _SIZES:
        icon.addPixmap(render(size))
    return icon


def render(size: int) -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    scale = size / 64
    with QPainter(pixmap) as painter:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.scale(scale, scale)

        tile = QRectF(3, 3, 58, 58)
        background = QLinearGradient(tile.topLeft(), tile.bottomLeft())
        background.setColorAt(0, QColor("#1f2d44"))
        background.setColorAt(1, QColor("#0f1724"))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(background)
        painter.drawRoundedRect(tile, 13, 13)

        # Thicker lines at small sizes, where a thin one would vanish.
        line = 2.6 if size >= 48 else 3.4
        axis = QPen(QColor("#8fa3bf"), line * 0.8)
        axis.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(axis)
        painter.drawLine(QPointF(10, _BASELINE + 1.5), QPointF(54, _BASELINE + 1.5))
        for center, half, height, color in _CURVES:
            path = QPainterPath(QPointF(center - half, _BASELINE))
            steps = 24
            for k in range(steps + 1):
                t = -1 + 2 * k / steps
                path.lineTo(center + t * half, _BASELINE - height * (1 - t**4))
            fill = QColor(color)
            fill.setAlphaF(0.28)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(fill)
            painter.drawPath(path)
            pen = QPen(QColor(color), line)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(path)

    return pixmap
