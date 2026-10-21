"""Visual style for the inspector window."""

from __future__ import annotations

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

STYLESHEET = """
QMainWindow, QDialog, QScrollArea, QWidget#root {
    background: #f3f6f8;
    color: #1c2430;
    font-size: 13px;
}
QGroupBox {
    background: #ffffff;
    border: 1px solid #d5dde6;
    border-radius: 8px;
    margin-top: 14px;
    padding: 12px 12px 10px 12px;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 4px;
}
QLineEdit, QSpinBox, QComboBox, QPlainTextEdit {
    background: #ffffff;
    border: 1px solid #c5ced8;
    border-radius: 6px;
    padding: 6px 8px;
    selection-background-color: #1f6feb;
}
QPushButton {
    background: #e7eef6;
    border: 1px solid #c5ced8;
    border-radius: 6px;
    padding: 7px 14px;
}
QPushButton:hover { background: #dce7f4; }
QPushButton:disabled { color: #8b97a6; background: #eef2f6; }
QPushButton#primary {
    background: #1f6feb;
    color: #ffffff;
    border: none;
    font-weight: 600;
}
QPushButton#primary:hover { background: #1a5fd0; }
QPushButton#primary:disabled { background: #9eb6dc; color: #f4f7fb; }
QTableWidget {
    background: #ffffff;
    alternate-background-color: #f7f9fb;
    gridline-color: #e6ebf1;
    border: 1px solid #d5dde6;
    border-radius: 6px;
}
QHeaderView::section {
    background: #eef3f8;
    padding: 6px;
    border: none;
    font-weight: 600;
}
QLabel#notice {
    background: #fff7e8;
    border: 1px solid #efd3a0;
    border-radius: 6px;
    padding: 8px;
}
QLabel#hint { color: #526173; }
QStatusBar { background: #e7eef5; color: #243140; }
"""


def apply_theme(app: QApplication) -> None:
    """Apply a light, high-contrast Fusion theme."""

    app.setStyle("Fusion")
    palette = app.palette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#f3f6f8"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#1c2430"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#1c2430"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#e7eef6"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#1f6feb"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)
    app.setStyleSheet(STYLESHEET)
