"""Launch the portal account inspector."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from app_info import APP_NAME
from app_logging import configure_logging
from ui.main_window import MainWindow
from ui.theme import apply_theme


def main() -> int:
    configure_logging()
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("StalkerPortalInspector")
    apply_theme(app)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
