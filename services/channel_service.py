"""Count channel metadata without treating duplicate rows as extra channels."""

from __future__ import annotations

from adapters.base import PortalAdapter
from models.portal_models import ChannelCatalogue, ChannelRecord


def summarize_channels(
    records: list[ChannelRecord],
    *,
    live_field_supported: bool,
    category_field_supported: bool,
) -> ChannelCatalogue:
    """Count returned rows separately from distinct channel ids."""

    total = len(records)
    if total == 0:
        return ChannelCatalogue(
            available=True,
            total_records=0,
            unique_channels=0,
            live_channels=0 if live_field_supported else None,
            category_count=0 if category_field_supported else None,
            records=[],
        )

    notes: list[str] = []
    if not live_field_supported:
        notes.append("The API specification does not define a live-channel field.")
    if not category_field_supported:
        notes.append("The API specification does not define a category field.")

    if any(record.record_id is None for record in records):
        notes.append("Unique channel count is not calculable because one or more records have no channel id.")
        if live_field_supported:
            notes.append("Live channel count is not calculable because channel identity is incomplete.")
        return ChannelCatalogue(
            available=True,
            total_records=total,
            unique_channels=None,
            live_channels=None,
            category_count=_category_count(records, category_field_supported, notes),
            records=list(records),
            notes=notes,
        )

    merged: dict[str, ChannelRecord] = {}
    live_conflict = False
    category_conflict = False
    for record in records:
        record_id = record.record_id or ""
        current = merged.get(record_id)
        if current is None:
            merged[record_id] = record
            continue
        if current.is_live != record.is_live and current.is_live is not None and record.is_live is not None:
            live_conflict = True
        if current.category and record.category and current.category != record.category:
            category_conflict = True
        merged[record_id] = ChannelRecord(
            record_id=record_id,
            name=current.name or record.name,
            category=current.category or record.category,
            is_live=current.is_live if current.is_live is not None else record.is_live,
        )

    unique_records = list(merged.values())
    unique_count = len(unique_records)
    if total > unique_count:
        notes.append("Duplicate channel records were returned. Channel records and unique channels are both shown.")

    if not live_field_supported or live_conflict or any(record.is_live is None for record in unique_records):
        live_count = None
        if live_field_supported and (live_conflict or any(record.is_live is None for record in unique_records)):
            notes.append("Live channel count is not calculable for this response.")
    else:
        live_count = sum(1 for record in unique_records if record.is_live)

    if category_conflict:
        notes.append("Category count is not calculable because duplicate records disagree.")
        category_count = None
    else:
        category_count = _category_count(unique_records, category_field_supported, notes)

    return ChannelCatalogue(
        available=True,
        total_records=total,
        unique_channels=unique_count,
        live_channels=live_count,
        category_count=category_count,
        records=list(records),
        notes=notes,
    )


def _category_count(records: list[ChannelRecord], supported: bool, notes: list[str]) -> int | None:
    if not supported:
        return None
    if any(record.category is None for record in records):
        notes.append("Category count is not calculable because some channels omit a category.")
        return None
    return len({record.category for record in records})


class ChannelService:
    """Turn adapter metadata into counted catalogue rows."""

    def __init__(self, adapter: PortalAdapter) -> None:
        self._adapter = adapter

    def load(self) -> ChannelCatalogue:
        metadata = self._adapter.get_channel_metadata()
        catalogue = summarize_channels(
            metadata.records,
            live_field_supported=metadata.live_field_supported,
            category_field_supported=metadata.category_field_supported,
        )
        catalogue.notes = [*metadata.notes, *catalogue.notes]
        return catalogue
