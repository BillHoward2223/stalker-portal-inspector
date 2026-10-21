"""Plain-text and JSON reports. Exported JSON is passed through redaction."""

from __future__ import annotations

from typing import Any

from app_info import APP_NAME, APP_VERSION
from models.portal_models import AccountInfo, InspectionReport
from security.redaction import redact_data

NOT_AVAILABLE = "Not available"
_PROPRIETARY = ("sncut", "dev1", "dev2")


def display(value: object) -> str:
    if value is None or value == "":
        return NOT_AVAILABLE
    return str(value)


def proprietary_notice(account: AccountInfo) -> str | None:
    """Explain identifiers that this specification does not define."""

    missing = [name.upper() for name in _PROPRIETARY if name not in account.proprietary_meanings]
    if not missing:
        return None
    if len(missing) == 1:
        return f"{missing[0]} is not shown because the specification does not confirm its meaning."
    joined = ", ".join(missing)
    return f"{joined} are not shown because the specification does not confirm their meaning."


def format_report(report: InspectionReport) -> str:
    """Build the readable report. Missing API values become 'Not available'."""

    account = report.account
    channels = report.channels
    lines = [
        _row("Mode", "Synthetic demo" if report.demo else "Administrator API"),
        _row("Portal", report.portal_url),
        _row("Panel ID", account.portal_id),
        _row("MAC", report.mac_address),
        _row("API MAC", account.mac_address),
        _row("Status", account.status),
        _row("Expires", account.expires_at),
        _row("SN", account.serial_number),
    ]
    for name in _PROPRIETARY:
        if name not in account.proprietary_meanings:
            continue
        lines.append(_row(name.upper(), getattr(account, name)))
        lines.append(_row(f"{name.upper()} meaning", account.proprietary_meanings[name]))
    lines.extend(
        [
            _row("Authentication", account.auth_status),
            _row("Last connection", account.last_connection_at),
            _row("This session", report.session_connected_at),
            "",
            _row("Channel records", None if not channels.available else channels.total_records),
            _row("Unique channels", None if not channels.available else channels.unique_channels),
            _row("Live channels", None if not channels.available else channels.live_channels),
            _row("Categories", None if not channels.available else channels.category_count),
        ]
    )
    if report.spec_title:
        lines.insert(1, _row("Specification", report.spec_title))
    notes = _notes(report)
    if notes:
        lines.extend(["", "Notes:"])
        lines.extend(f"- {note}" for note in notes)
    return "\n".join(lines) + "\n"


def report_document(report: InspectionReport) -> dict[str, Any]:
    """JSON export with secrets removed even if a future field is named like a token."""

    return redact_data(
        {
            "application": APP_NAME,
            "version": APP_VERSION,
            "demo": report.demo,
            "portal_url": report.portal_url,
            "mac_address": report.mac_address,
            "specification": report.spec_title,
            "account": report.account.model_dump(),
            "channels": report.channels.model_dump(),
            "notices": report.notices,
            "session_connected_at": report.session_connected_at,
        }
    )


def _notes(report: InspectionReport) -> list[str]:
    notes: list[str] = []
    for note in [*report.notices, report.channels.unavailable_reason, *report.channels.notes]:
        if note and note not in notes:
            notes.append(note)
    return notes


def _row(label: str, value: object) -> str:
    return f"{label:<20}{display(value)}"
