"""Main window for connection settings, account fields, channel counts, and the report."""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QThread, Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from pydantic import ValidationError

from adapters.demo_adapter import DemoAdapter
from adapters.documented_api_adapter import DocumentedApiAdapter
from app_info import APP_NAME, APP_VERSION
from models.api_spec import ApiSpec, load_api_spec
from models.errors import CredentialStoreError, InvalidInputError, PortalError
from models.portal_models import AuthMethod, ConnectionSettings, InspectionReport, portal_host
from security.credentials import (
    ALLOWED_SECRET_NAMES,
    CredentialStore,
    KeyringCredentialStore,
    SecretBundle,
)
from services.app_paths import app_data_dir
from services.report_service import NOT_AVAILABLE, display, report_document
from services.settings_store import SettingsStore
from ui.dialogs import CredentialsDialog, HelpDialog, validation_text
from ui.workers import InspectionWorker

_ACCOUNT_ROWS = (
    ("portal", "Portal"),
    ("panel_id", "Panel ID"),
    ("mac", "MAC"),
    ("api_mac", "API MAC"),
    ("status", "Status"),
    ("expires", "Expires"),
    ("serial", "SN"),
    ("sncut", "SNCUT"),
    ("dev1", "DEV1"),
    ("dev2", "DEV2"),
    ("auth", "Authentication"),
    ("last_connection", "Last connection"),
    ("session", "This session"),
)
_PROPRIETARY_ROWS = ("sncut", "dev1", "dev2")


class MainWindow(QMainWindow):
    """Desktop inspector. Network work runs on a background thread."""

    def __init__(
        self,
        settings_store: SettingsStore | None = None,
        credential_store: CredentialStore | None = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(1080, 860)
        self._settings_store = settings_store or SettingsStore(app_data_dir() / "settings.json")
        self._credentials = credential_store
        self._adapter: DemoAdapter | DocumentedApiAdapter | None = None
        self._thread: QThread | None = None
        self._worker: InspectionWorker | None = None
        self._report: InspectionReport | None = None
        self._pending_secrets: SecretBundle | None = None
        self._closing = False
        self._user_disconnect = False
        self._account_labels: dict[str, QLabel] = {}
        self._account_values: dict[str, QLabel] = {}
        self._build()
        self._load_settings()

    def _build(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        layout = QVBoxLayout(root)
        layout.addWidget(self._connection_group())
        layout.addWidget(self._account_group())
        layout.addWidget(self._channel_group())
        layout.addWidget(self._report_group())
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(root)
        self.setCentralWidget(scroll)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Ready. Stream playback is not part of this application.")
        help_menu = self.menuBar().addMenu("Help")
        help_action = help_menu.addAction("About this tool")
        help_action.triggered.connect(self._show_help)

    def _connection_group(self) -> QGroupBox:
        box = QGroupBox("Connection")
        form = QGridLayout(box)
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://portal.example.com")
        self.mode_combo = QComboBox()
        self.mode_combo.addItem("Synthetic demo", AuthMethod.DEMO.value)
        self.mode_combo.addItem("Documented administrator API", AuthMethod.DOCUMENTED_API.value)
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        self.mac_edit = QLineEdit()
        self.mac_edit.setPlaceholderText("00:1A:79:00:00:01")
        self.serial_edit = QLineEdit()
        self.serial_edit.setPlaceholderText("Optional. Sent only if the specification asks for it.")
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(3, 60)
        self.timeout_spin.setValue(15)
        self.timeout_spin.setSuffix(" seconds")
        self.spec_edit = QLineEdit()
        self.spec_button = QPushButton("Browse…")
        self.spec_button.clicked.connect(self._browse_spec)
        self.spec_edit.textChanged.connect(self._refresh_spec_label)
        spec_row = QHBoxLayout()
        spec_row.addWidget(self.spec_edit)
        spec_row.addWidget(self.spec_button)
        self.spec_label = QLabel("Demo mode uses built-in synthetic data and does not contact a portal.")
        self.spec_label.setObjectName("hint")
        self.spec_label.setWordWrap(True)
        self.notice = QLabel(
            "A MAC address identifies a device. It does not by itself authorize access to an account."
        )
        self.notice.setObjectName("hint")
        self.notice.setWordWrap(True)

        form.addWidget(QLabel("Portal URL"), 0, 0)
        form.addWidget(self.url_edit, 0, 1)
        form.addWidget(QLabel("Connection mode"), 1, 0)
        form.addWidget(self.mode_combo, 1, 1)
        form.addWidget(QLabel("Device MAC"), 2, 0)
        form.addWidget(self.mac_edit, 2, 1)
        form.addWidget(QLabel("Serial number"), 3, 0)
        form.addWidget(self.serial_edit, 3, 1)
        form.addWidget(QLabel("Timeout"), 4, 0)
        form.addWidget(self.timeout_spin, 4, 1)
        form.addWidget(QLabel("API specification"), 5, 0)
        form.addLayout(spec_row, 5, 1)
        form.addWidget(self.spec_label, 6, 1)
        form.addWidget(self.notice, 7, 1)

        self.connect_button = QPushButton("Connect")
        self.connect_button.setObjectName("primary")
        self.connect_button.clicked.connect(self._connect)
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.setEnabled(False)
        self.disconnect_button.clicked.connect(self._disconnect)
        self.credentials_button = QPushButton("Credentials…")
        self.credentials_button.clicked.connect(self._edit_credentials)
        self.forget_button = QPushButton("Forget saved credentials")
        self.forget_button.clicked.connect(self._forget_credentials)
        buttons = QHBoxLayout()
        buttons.addWidget(self.connect_button)
        buttons.addWidget(self.disconnect_button)
        buttons.addWidget(self.credentials_button)
        buttons.addWidget(self.forget_button)
        buttons.addStretch(1)
        form.addLayout(buttons, 8, 0, 1, 2)
        return box

    def _account_group(self) -> QGroupBox:
        box = QGroupBox("Account")
        form = QFormLayout(box)
        for key, label in _ACCOUNT_ROWS:
            name = QLabel(label)
            value = QLabel(NOT_AVAILABLE)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value.setWordWrap(True)
            self._account_labels[key] = name
            self._account_values[key] = value
            form.addRow(name, value)
        for key in _PROPRIETARY_ROWS:
            self._account_labels[key].setVisible(False)
            self._account_values[key].setVisible(False)
        return box

    def _channel_group(self) -> QGroupBox:
        box = QGroupBox("Channels")
        layout = QVBoxLayout(box)
        form = QFormLayout()
        self.channel_values = {}
        for key, label in (
            ("records", "Channel records"),
            ("unique", "Unique channels"),
            ("live", "Live channels"),
            ("categories", "Categories"),
        ):
            value = QLabel(NOT_AVAILABLE)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.channel_values[key] = value
            form.addRow(label, value)
        layout.addLayout(form)
        hint = QLabel("Channel records count every returned row. Unique channels count distinct channel ids.")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.channel_note = QLabel("")
        self.channel_note.setWordWrap(True)
        layout.addWidget(self.channel_note)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search channel id, name, or category")
        self.search_edit.textChanged.connect(self._apply_filter)
        layout.addWidget(self.search_edit)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["ID", "Name", "Category", "Live"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setMinimumHeight(180)
        layout.addWidget(self.table)
        return box

    def _report_group(self) -> QGroupBox:
        box = QGroupBox("Report")
        layout = QVBoxLayout(box)
        self.notice_label = QLabel("")
        self.notice_label.setObjectName("notice")
        self.notice_label.setWordWrap(True)
        self.notice_label.setVisible(False)
        layout.addWidget(self.notice_label)
        self.report_view = QPlainTextEdit()
        self.report_view.setReadOnly(True)
        self.report_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.report_view.setFont(QFont("Consolas", 10))
        self.report_view.setMinimumHeight(220)
        self.report_view.setPlaceholderText("Connect to produce a report.")
        layout.addWidget(self.report_view)
        self.copy_button = QPushButton("Copy report")
        self.copy_button.setEnabled(False)
        self.copy_button.clicked.connect(self._copy_report)
        self.export_button = QPushButton("Export JSON")
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._export_json)
        row = QHBoxLayout()
        row.addWidget(self.copy_button)
        row.addWidget(self.export_button)
        row.addStretch(1)
        layout.addLayout(row)
        return box

    def _load_settings(self) -> None:
        data = self._settings_store.load()
        self.url_edit.setText(str(data.get("portal_url") or "https://demo.invalid"))
        mode = str(data.get("auth_method") or AuthMethod.DEMO.value)
        index = self.mode_combo.findData(mode)
        self.mode_combo.setCurrentIndex(index if index >= 0 else 0)
        self.mac_edit.setText(str(data.get("mac_address") or "00:1A:79:00:00:01"))
        self.serial_edit.setText(str(data.get("serial_number") or ""))
        timeout = data.get("timeout_seconds", 15)
        self.timeout_spin.setValue(int(timeout) if isinstance(timeout, (int, float)) else 15)
        self.spec_edit.setText(str(data.get("spec_path") or ""))
        self._on_mode_changed()

    def _draft(self) -> dict[str, object]:
        return {
            "portal_url": self.url_edit.text().strip(),
            "auth_method": str(self.mode_combo.currentData()),
            "mac_address": self.mac_edit.text().strip(),
            "serial_number": self.serial_edit.text().strip(),
            "timeout_seconds": int(self.timeout_spin.value()),
            "spec_path": self.spec_edit.text().strip(),
        }

    def _save_draft(self) -> None:
        try:
            self._settings_store.save(self._draft())
        except OSError:
            self.statusBar().showMessage("Connection settings could not be saved.")

    def _on_mode_changed(self) -> None:
        documented = self.mode_combo.currentData() == AuthMethod.DOCUMENTED_API.value
        for widget in (self.spec_edit, self.spec_button, self.credentials_button, self.forget_button):
            widget.setEnabled(documented)
        self._refresh_spec_label()

    def _refresh_spec_label(self) -> None:
        if self.mode_combo.currentData() != AuthMethod.DOCUMENTED_API.value:
            self.spec_label.setText("Demo mode uses built-in synthetic data and does not contact a portal.")
            return
        path = self.spec_edit.text().strip()
        if not path:
            self.spec_label.setText("Choose the administrator API specification before connecting.")
            return
        try:
            spec = load_api_spec(Path(path))
        except PortalError as exc:
            self.spec_label.setText(exc.user_message)
            return
        self.spec_label.setText(f"{spec.title}. Authentication defined by the specification: {spec.auth.type}.")

    def _browse_spec(self) -> None:
        path, _selected = QFileDialog.getOpenFileName(self, "API specification", "", "JSON (*.json)")
        if path:
            self.spec_edit.setText(path)

    def _settings_from_form(self) -> ConnectionSettings:
        serial = self.serial_edit.text().strip() or None
        spec_path = self.spec_edit.text().strip() or None
        return ConnectionSettings(
            portal_url=self.url_edit.text(),
            auth_method=AuthMethod(str(self.mode_combo.currentData())),
            mac_address=self.mac_edit.text(),
            serial_number=serial,
            timeout_seconds=float(self.timeout_spin.value()),
            spec_path=spec_path,
        )

    def _connect(self) -> None:
        if self._thread_is_running():
            return
        try:
            settings = self._settings_from_form()
        except ValidationError as exc:
            QMessageBox.warning(self, APP_NAME, validation_text(exc))
            return
        except ValueError as exc:
            QMessageBox.warning(self, APP_NAME, str(exc))
            return
        try:
            adapter = self._make_adapter(settings)
        except PortalError as exc:
            QMessageBox.warning(self, APP_NAME, exc.user_message)
            return
        if adapter is None:
            return
        self._save_draft()
        self._adapter = adapter
        self._set_busy(True)
        if adapter.is_demo:
            self.statusBar().showMessage("Loading synthetic demo data…")
        else:
            self.statusBar().showMessage("Contacting the configured portal…")
        self._start_worker(adapter)

    def _make_adapter(self, settings: ConnectionSettings) -> DemoAdapter | DocumentedApiAdapter | None:
        if settings.auth_method is AuthMethod.DEMO:
            return DemoAdapter(settings)
        if not settings.spec_path:
            raise InvalidInputError("Choose the administrator API specification for this portal.")
        spec = load_api_spec(Path(settings.spec_path))
        secrets = self._resolve_secrets(settings, spec)
        if secrets is None:
            return None
        return DocumentedApiAdapter(settings, spec, secrets)

    def _resolve_secrets(self, settings: ConnectionSettings, spec: ApiSpec) -> SecretBundle | None:
        required = spec.auth.required_secret_names()
        if not required:
            return SecretBundle()
        if self._pending_secrets and all(getattr(self._pending_secrets, name) for name in required):
            return self._pending_secrets
        host = portal_host(settings.portal_url)
        stored: dict[str, str | None] = {}
        try:
            store = self._credential_store()
            stored = {name: store.get_secret(host, name) for name in required}
        except CredentialStoreError:
            stored = {}
        if stored and all(stored.values()):
            return SecretBundle(**{name: stored[name] for name in required})
        return self._prompt_secrets(spec, host, required, str(stored.get("username") or ""))

    def _prompt_secrets(
        self,
        spec: ApiSpec,
        host: str,
        required: tuple[str, ...],
        username: str,
    ) -> SecretBundle | None:
        dialog = CredentialsDialog(self, spec.auth.type, username)
        if dialog.exec() != CredentialsDialog.DialogCode.Accepted:
            return None
        bundle = dialog.bundle()
        if not all(getattr(bundle, name) for name in required):
            raise InvalidInputError("Enter the credentials required by the API specification.")
        self._pending_secrets = bundle
        store = self._credential_store()
        if dialog.remember():
            for name in required:
                store.set_secret(host, name, str(getattr(bundle, name)))
        else:
            for name in required:
                store.delete_secret(host, name)
        return bundle

    def _edit_credentials(self) -> None:
        try:
            settings = self._settings_from_form()
            if settings.auth_method is not AuthMethod.DOCUMENTED_API or not settings.spec_path:
                raise InvalidInputError("Choose a documented API specification before saving credentials.")
            spec = load_api_spec(Path(settings.spec_path))
        except (ValidationError, ValueError) as exc:
            message = validation_text(exc) if isinstance(exc, ValidationError) else str(exc)
            QMessageBox.warning(self, APP_NAME, message)
            return
        except PortalError as exc:
            QMessageBox.warning(self, APP_NAME, exc.user_message)
            return
        required = spec.auth.required_secret_names()
        if not required:
            QMessageBox.information(self, APP_NAME, "This specification does not use credentials.")
            return
        try:
            bundle = self._prompt_secrets(spec, portal_host(settings.portal_url), required, "")
        except PortalError as exc:
            QMessageBox.warning(self, APP_NAME, exc.user_message)
            return
        if bundle is not None:
            self.statusBar().showMessage("Credentials updated for this portal.")

    def _forget_credentials(self) -> None:
        try:
            settings = self._settings_from_form()
            host = portal_host(settings.portal_url)
            store = self._credential_store()
            for name in ALLOWED_SECRET_NAMES:
                store.delete_secret(host, name)
        except ValidationError as exc:
            QMessageBox.warning(self, APP_NAME, validation_text(exc))
            return
        except PortalError as exc:
            QMessageBox.warning(self, APP_NAME, exc.user_message)
            return
        if self._pending_secrets is not None:
            self._pending_secrets.clear()
            self._pending_secrets = None
        self.statusBar().showMessage("Saved credentials for this portal were removed.")

    def _credential_store(self) -> CredentialStore:
        if self._credentials is None:
            self._credentials = KeyringCredentialStore()
        return self._credentials

    def _start_worker(self, adapter: DemoAdapter | DocumentedApiAdapter) -> None:
        thread = QThread(self)
        worker = InspectionWorker(adapter)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.succeeded.connect(self._on_success)
        worker.failed.connect(self._on_failure)
        worker.succeeded.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(self._clear_thread)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        self._thread = thread
        self._worker = worker
        thread.start()

    def _clear_thread(self) -> None:
        self._thread = None
        self._worker = None

    def _thread_is_running(self) -> bool:
        thread = self._thread
        if thread is None:
            return False
        try:
            return thread.isRunning()
        except RuntimeError:
            self._clear_thread()
            return False

    def _on_success(self, report: object) -> None:
        if self._closing or self._user_disconnect or not isinstance(report, InspectionReport):
            self._user_disconnect = False
            return
        self._release_connection()
        self._report = report
        self._render(report)
        self._set_busy(False)
        self.disconnect_button.setEnabled(True)
        self.copy_button.setEnabled(True)
        self.export_button.setEnabled(True)
        self.statusBar().showMessage("Inspection finished. In-memory session tokens were discarded.")

    def _on_failure(self, message: str) -> None:
        if self._closing:
            return
        cancelled = self._user_disconnect
        self._user_disconnect = False
        self._release_connection()
        self._set_busy(False)
        if cancelled:
            self._clear_display()
            self.statusBar().showMessage("Disconnected.")
            return
        self.statusBar().showMessage(message)
        QMessageBox.warning(self, APP_NAME, message)

    def _disconnect(self) -> None:
        self._user_disconnect = True
        if self._thread_is_running():
            self._release_connection()
            thread = self._thread
            if thread is not None:
                thread.quit()
                thread.wait(2000)
            return
        self._user_disconnect = False
        self._release_connection()
        self._clear_display()
        self.statusBar().showMessage("Disconnected. In-memory credentials were discarded.")

    def _release_connection(self) -> None:
        adapter = self._adapter
        self._adapter = None
        if adapter is not None:
            adapter.disconnect()
        if self._pending_secrets is not None:
            self._pending_secrets.clear()
            self._pending_secrets = None

    def _render(self, report: InspectionReport) -> None:
        account = report.account
        values = {
            "portal": report.portal_url,
            "panel_id": account.portal_id,
            "mac": report.mac_address,
            "api_mac": account.mac_address,
            "status": account.status,
            "expires": account.expires_at,
            "serial": account.serial_number,
            "sncut": account.sncut,
            "dev1": account.dev1,
            "dev2": account.dev2,
            "auth": account.auth_status,
            "last_connection": account.last_connection_at,
            "session": report.session_connected_at,
        }
        for key, value in values.items():
            shown = display(value)
            if key in account.proprietary_meanings:
                shown = f"{shown}\nConfirmed meaning: {account.proprietary_meanings[key]}"
            self._account_values[key].setText(shown)
        for key in _PROPRIETARY_ROWS:
            visible = key in account.proprietary_meanings
            self._account_labels[key].setVisible(visible)
            self._account_values[key].setVisible(visible)
        channels = report.channels
        self.channel_values["records"].setText(display(None if not channels.available else channels.total_records))
        self.channel_values["unique"].setText(display(None if not channels.available else channels.unique_channels))
        self.channel_values["live"].setText(display(None if not channels.available else channels.live_channels))
        self.channel_values["categories"].setText(
            display(None if not channels.available else channels.category_count)
        )
        notes = [note for note in [*report.notices, channels.unavailable_reason, *channels.notes] if note]
        unique_notes: list[str] = []
        for note in notes:
            if note not in unique_notes:
                unique_notes.append(note)
        self.channel_note.setText("\n".join(unique_notes))
        self.notice_label.setText("\n".join(report.notices))
        self.notice_label.setVisible(bool(report.notices))
        self.report_view.setPlainText(report.report_text)
        self._fill_table(channels.records if channels.available else [])

    def _fill_table(self, records: list[object]) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(records))
        for row, record in enumerate(records):
            live = getattr(record, "is_live", None)
            live_text = NOT_AVAILABLE if live is None else ("Yes" if live else "No")
            values = [
                display(getattr(record, "record_id", None)),
                display(getattr(record, "name", None)),
                display(getattr(record, "category", None)),
                live_text,
            ]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(value))
        self.table.setSortingEnabled(True)
        self._apply_filter()

    def _apply_filter(self) -> None:
        query = self.search_edit.text().strip().lower()
        for row in range(self.table.rowCount()):
            values = []
            for column in range(self.table.columnCount()):
                item = self.table.item(row, column)
                values.append(item.text().lower() if item is not None else "")
            self.table.setRowHidden(row, bool(query) and all(query not in value for value in values))

    def _clear_display(self) -> None:
        self._report = None
        for key, label in self._account_values.items():
            label.setText(NOT_AVAILABLE)
            if key in _PROPRIETARY_ROWS:
                label.setVisible(False)
                self._account_labels[key].setVisible(False)
        for label in self.channel_values.values():
            label.setText(NOT_AVAILABLE)
        self.channel_note.setText("")
        self.notice_label.clear()
        self.notice_label.setVisible(False)
        self.report_view.clear()
        self.table.setRowCount(0)
        self.search_edit.clear()
        self.disconnect_button.setEnabled(False)
        self.copy_button.setEnabled(False)
        self.export_button.setEnabled(False)

    def _copy_report(self) -> None:
        if self._report is None:
            return
        self.report_view.selectAll()
        self.report_view.copy()
        cursor = self.report_view.textCursor()
        cursor.clearSelection()
        self.report_view.setTextCursor(cursor)
        self.statusBar().showMessage("Report copied. Secrets are not included in the report.")

    def _export_json(self) -> None:
        if self._report is None:
            return
        path, _selected = QFileDialog.getSaveFileName(self, "Export JSON report", "portal-report.json", "JSON (*.json)")
        if not path:
            return
        document = report_document(self._report)
        try:
            Path(path).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        except OSError:
            QMessageBox.warning(self, APP_NAME, "The report could not be written.")
            return
        self.statusBar().showMessage("JSON report exported. Tokens, passwords, and cookies are redacted.")

    def _set_busy(self, busy: bool) -> None:
        self.connect_button.setEnabled(not busy)
        self.disconnect_button.setEnabled(True)
        self.mode_combo.setEnabled(not busy)
        self.url_edit.setEnabled(not busy)
        self.mac_edit.setEnabled(not busy)
        self.serial_edit.setEnabled(not busy)
        self.timeout_spin.setEnabled(not busy)

    def _show_help(self) -> None:
        HelpDialog(self).exec()

    def closeEvent(self, event: object) -> None:
        self._closing = True
        self._save_draft()
        self._release_connection()
        if self._thread_is_running():
            thread = self._thread
            if thread is not None:
                thread.quit()
                thread.wait(2000)
        if hasattr(event, "accept"):
            event.accept()
