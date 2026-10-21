"""Background inspection so the window stays responsive."""

from __future__ import annotations

import logging

from PySide6.QtCore import QObject, Signal, Slot

from adapters.base import PortalAdapter
from models.errors import PortalError
from services.inspection import run_inspection

logger = logging.getLogger(__name__)


class InspectionWorker(QObject):
    """Run one inspection off the UI thread and return a safe message on failure."""

    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, adapter: PortalAdapter) -> None:
        super().__init__()
        self._adapter = adapter

    @Slot()
    def run(self) -> None:
        try:
            report = run_inspection(self._adapter)
        except PortalError as exc:
            logger.info("Inspection stopped: %s", exc.user_message)
            self.failed.emit(exc.user_message)
        except Exception:
            logger.exception("Unexpected inspection failure")
            self.failed.emit("An unexpected error occurred. Details are in the application log.")
        else:
            self.succeeded.emit(report)
