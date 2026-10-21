"""The window can be constructed and a synthetic inspection can be shown."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def test_main_window_demo_connection_fills_the_report(tmp_path: Path) -> None:
    pytest.importorskip("PySide6")
    try:
        from PySide6.QtCore import QElapsedTimer
        from PySide6.QtWidgets import QApplication

        from security.credentials import MemoryCredentialStore
        from services.settings_store import SettingsStore
        from ui.main_window import MainWindow
    except ImportError as exc:
        pytest.skip(f"Qt platform libraries are not installed: {exc}")

    application = QApplication.instance() or QApplication([])
    window = MainWindow(SettingsStore(tmp_path / "settings.json"), MemoryCredentialStore())
    window.show()
    window.url_edit.setText("https://demo.invalid")
    window.mac_edit.setText("00:1A:79:00:00:01")
    window._connect()

    timer = QElapsedTimer()
    timer.start()
    while window._report is None and timer.elapsed() < 3000:
        application.processEvents()

    assert window._report is not None
    assert window._report.demo is True
    assert "synthetic" in window.report_view.toPlainText()
    assert "No portal was contacted" in window.report_view.toPlainText()
    assert window.table.rowCount() == 4
    assert window.channel_values["records"].text() == "4"
    assert window.channel_values["unique"].text() == "3"
    assert window._account_values["sncut"].isVisible() is False

    window.search_edit.setText("cinema")
    hidden = [window.table.isRowHidden(row) for row in range(window.table.rowCount())]
    assert hidden.count(False) == 1

    window._disconnect()
    assert window.report_view.toPlainText() == ""
    assert window.table.rowCount() == 0
    window.close()
