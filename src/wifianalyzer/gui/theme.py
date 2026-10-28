"""Colors for the desktop UI, in light and dark variants."""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication


@dataclass(frozen=True)
class Theme:
    dark: bool
    page: str
    surface: str
    """Card and chart background."""
    text: str
    text_secondary: str
    muted: str
    grid: str
    axis: str
    border: str
    accent: str
    """Primary buttons, the selected band and table selection: the connected network's blue."""
    series: tuple[str, ...]

    def qcolor(self, hex_color: str, alpha: float = 1.0) -> QColor:
        color = QColor(hex_color)
        color.setAlphaF(alpha)
        return color

    def series_color(self, slot: int | None, alpha: float = 1.0) -> QColor:
        return self.qcolor(self.muted if slot is None else self.series[slot], alpha)


# One color per network on the chart, in the order they're handed out. Neighbouring slots differ
# in hue as well as lightness, so curves that overlap stay apart. Each mode has its own shades of
# the same hues, so a network keeps its color when the system switches between light and dark.
LIGHT = Theme(
    dark=False,
    page="#f9f9f7",
    surface="#fcfcfb",
    text="#0b0b0b",
    text_secondary="#52514e",
    muted="#898781",
    grid="#e1e0d9",
    axis="#c3c2b7",
    border="#e4e4e2",
    accent="#2a78d6",
    series=("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"),
)
DARK = Theme(
    dark=True,
    page="#0d0d0d",
    surface="#1a1a19",
    text="#f0efec",
    text_secondary="#c3c2b7",
    muted="#898781",
    grid="#2c2c2a",
    axis="#383835",
    border="#313130",
    accent="#3987e5",
    series=("#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"),
)
SERIES_COUNT = len(LIGHT.series)

# Status colors are reserved for good/bad states and always appear next to a text label.
STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}
SIGNAL_STATUS = {"excellent": "good", "good": "good", "fair": "warning", "weak": "serious", "poor": "critical"}
INTERFERENCE_STATUS = {"clear": "good", "low": "good", "moderate": "warning", "high": "critical"}


def current() -> Theme:
    scheme = QGuiApplication.styleHints().colorScheme()
    if scheme == Qt.ColorScheme.Unknown:
        return DARK if QGuiApplication.palette().window().color().lightness() < 128 else LIGHT
    return DARK if scheme == Qt.ColorScheme.Dark else LIGHT


def _rgba(hex_color: str, alpha: float) -> str:
    color = QColor(hex_color)
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {alpha})"


def stylesheet(t: Theme) -> str:
    hover = _rgba(t.text, 0.06)
    return f"""
    QMainWindow, QWidget#page, QScrollArea#scroll {{ background: {t.page}; }}
    QFrame#card {{ background: {t.surface}; border: 1px solid {t.border}; border-radius: 12px; }}
    QFrame#card QLabel {{ color: {t.text}; background: transparent; }}
    QLabel[role="title"] {{ font-weight: 600; }}
    QLabel[role="muted"], QFrame#card QLabel[role="muted"] {{ color: {t.muted}; }}
    QLabel[role="secondary"], QFrame#card QLabel[role="secondary"] {{ color: {t.text_secondary}; }}
    QFrame#card QLabel[role="badge"] {{
        color: {t.text_secondary}; background: {hover}; border-radius: 9px;
        padding: 1px 8px; min-height: 16px;
    }}
    QFrame#card QLabel[role="badge-good"] {{
        color: {t.text}; background: {_rgba(STATUS["good"], 0.16)}; border-radius: 9px;
        padding: 1px 8px; min-height: 16px; font-weight: 600;
    }}
    QFrame#banner {{
        background: {_rgba(STATUS["warning"], 0.14)};
        border: 1px solid {_rgba(STATUS["warning"], 0.45)};
        border-radius: 12px;
    }}
    QFrame#banner QLabel {{ color: {t.text}; background: transparent; }}
    QFrame#hairline {{ background: {t.border}; max-height: 1px; border: none; }}

    QToolBar {{ background: {t.page}; border: none; padding: 6px; spacing: 8px; }}
    QToolBar QLabel {{ color: {t.text_secondary}; }}
    QToolButton {{
        color: {t.text}; background: transparent; border: 1px solid {t.border};
        border-radius: 8px; padding: 4px 12px;
    }}
    QToolButton:hover {{ background: {hover}; }}
    QToolButton:checked {{
        color: {t.accent}; background: {_rgba(t.accent, 0.12)}; border-color: {_rgba(t.accent, 0.35)};
    }}
    QToolButton#primary {{ color: #ffffff; background: {t.accent}; border-color: {t.accent}; font-weight: 600; }}
    QToolButton#primary:hover {{ background: {_rgba(t.accent, 0.85)}; }}
    QToolButton#primary:disabled {{ background: {_rgba(t.accent, 0.45)}; border-color: transparent; }}

    QFrame#segmented {{ background: {hover}; border-radius: 9px; }}
    QFrame#segmented QPushButton {{
        color: {t.text_secondary}; background: transparent; border: 1px solid transparent;
        border-radius: 7px; padding: 4px 16px;
    }}
    QFrame#segmented QPushButton:hover {{ color: {t.text}; }}
    QFrame#segmented QPushButton:checked {{
        color: {t.text}; background: {t.surface}; border-color: {t.border}; font-weight: 600;
    }}

    QTableView {{
        background: {t.surface}; border: none; outline: none;
        selection-background-color: {_rgba(t.accent, 0.16)}; selection-color: {t.text};
    }}
    QTableView::item {{ border-bottom: 1px solid {t.grid}; }}
    QTableView::item:hover {{ background: {hover}; }}
    QTableView::item:selected {{ background: {_rgba(t.accent, 0.16)}; color: {t.text}; }}
    QHeaderView {{ background: {t.surface}; border: none; }}
    QHeaderView::section {{
        color: {t.muted}; background: {t.surface}; border: none; border-bottom: 1px solid {t.border};
        padding: 6px 4px;
    }}

    QSplitter::handle {{ background: transparent; }}
    QStatusBar {{ background: {t.page}; color: {t.text_secondary}; border-top: 1px solid {t.border}; }}
    QStatusBar::item {{ border: none; }}
    QStatusBar QLabel {{ color: {t.text_secondary}; padding: 2px 8px; }}
    QProgressBar {{ background: {hover}; border: none; border-radius: 3px; }}
    QProgressBar::chunk {{ background: {t.accent}; border-radius: 3px; }}
    """
