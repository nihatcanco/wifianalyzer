"""Pictures of the window and the spectrum chart, as PNG and SVG.

Each picture is returned as bytes, so the window writes every export the same way and can report
why a file couldn't be saved.
"""

from __future__ import annotations

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QPoint, QRect, QSize
from PySide6.QtGui import QImage, QImageWriter, QPaintDevice, QPainter
from PySide6.QtSvg import QSvgGenerator
from PySide6.QtWidgets import QWidget

from . import theme


def _png(image: QImage) -> bytes:
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    writer = QImageWriter(buffer, QByteArray(b"PNG"))
    if not writer.write(image):
        raise OSError(f"the image couldn't be encoded ({writer.errorString()})")
    buffer.close()
    return bytes(data.data())


def widget_png(widget: QWidget) -> bytes:
    """The widget and everything in it as it looks now, at the screen's pixel density."""
    return _png(widget.grab().toImage())


def _paint_on_surface(widget: QWidget, device: QPaintDevice) -> None:
    # The charts draw on the card behind them, so give the picture that card's color.
    t = theme.current()
    with QPainter(device) as painter:
        painter.fillRect(QRect(QPoint(), widget.size()), t.qcolor(t.surface))
        widget.render(painter, QPoint(), renderFlags=QWidget.RenderFlag.DrawChildren)


def chart_png(chart: QWidget) -> bytes:
    """A chart at its size on screen, at the screen's pixel density."""
    ratio = chart.devicePixelRatioF()
    image = QImage(
        QSize(round(chart.width() * ratio), round(chart.height() * ratio)), QImage.Format.Format_ARGB32_Premultiplied
    )
    image.setDevicePixelRatio(ratio)
    _paint_on_surface(chart, image)
    return _png(image)


def chart_svg(chart: QWidget, title: str) -> bytes:
    """A chart as a vector drawing at its size on screen, with its text kept as text."""
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    generator = QSvgGenerator()
    generator.setOutputDevice(buffer)
    generator.setSize(chart.size())
    generator.setViewBox(QRect(QPoint(), chart.size()))
    generator.setResolution(chart.logicalDpiX())  # so fonts come out the size they are on screen
    generator.setTitle(title)
    _paint_on_surface(chart, generator)
    buffer.close()
    return bytes(data.data())
