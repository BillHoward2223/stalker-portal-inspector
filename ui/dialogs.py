"""Small dialogs for credentials and for explaining what the application will not do."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
)
from pydantic import ValidationError

from app_info import APP_NAME
from security.credentials import SecretBundle

HELP_TEXT = """\
This tool inspects an account on a Stalker or Ministra portal that you administer.

Demo mode shows fictional Northwind data and does not open a network connection.

Documented mode calls only the HTTPS endpoints listed in an administrator API
specification that you provide. It sends the username, password, API key, or
bearer token you store in the operating-system credential manager. It does not
invent a set-top-box handshake, guess authentication signatures, scan MAC
addresses, or enumerate accounts.

SNCUT, DEV1, and DEV2 are shown only when that specification confirms what they
mean. Otherwise the report says they are not available.

The application counts channel metadata returned by the declared endpoint. It
does not download, decrypt, or play streams, and it does not send account data
to any third-party service.

Before a live connection, supply the middleware version and the official API
documentation or your administrator endpoint specification. A MAC address is a
device identifier, not proof that this application is authorized.
"""


def validation_text(exc: ValidationError) -> str:
    """Turn a settings validation error into a short message."""

    messages: list[str] = []
    for error in exc.errors():
        message = str(error.get("msg", "Check the connection settings."))
        prefix = "Value error, "
        if message.startswith(prefix):
            message = message[len(prefix) :]
        if message not in messages:
            messages.append(message)
    return "\n".join(messages) or "Check the connection settings."


class CredentialsDialog(QDialog):
    """Collect administrator credentials without writing them into a config file."""

    def __init__(self, parent: QDialog | None, auth_type: str, username: str = "") -> None:
        super().__init__(parent)
        self.setWindowTitle("Administrator credentials")
        self._auth_type = auth_type
        self.username_edit = QLineEdit(username)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.token_edit = QLineEdit()
        self.token_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.remember_box = QCheckBox("Save in the operating-system credential store")
        self.remember_box.setChecked(True)

        form = QFormLayout()
        if auth_type in {"basic", "session"}:
            form.addRow("Username", self.username_edit)
            form.addRow("Password", self.password_edit)
        elif auth_type == "bearer":
            form.addRow("Bearer token", self.token_edit)
        elif auth_type == "api_key":
            form.addRow("API key", self.token_edit)
        else:
            form.addRow(QLabel("This specification does not require credentials."))

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Credentials are kept out of the settings file and the report."))
        layout.addLayout(form)
        layout.addWidget(self.remember_box)
        layout.addWidget(buttons)
        self.resize(460, 220)

    def bundle(self) -> SecretBundle:
        if self._auth_type in {"basic", "session"}:
            return SecretBundle(username=self.username_edit.text(), password=self.password_edit.text())
        if self._auth_type == "bearer":
            return SecretBundle(bearer_token=self.token_edit.text())
        if self._auth_type == "api_key":
            return SecretBundle(api_key=self.token_edit.text())
        return SecretBundle()

    def remember(self) -> bool:
        return self.remember_box.isChecked()


class HelpDialog(QDialog):
    """Explain the demo, the specification file, and the inspection boundary."""

    def __init__(self, parent: QDialog | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(APP_NAME)
        text = QPlainTextEdit(HELP_TEXT)
        text.setReadOnly(True)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout = QVBoxLayout(self)
        layout.addWidget(text)
        layout.addWidget(buttons)
        self.resize(640, 460)
