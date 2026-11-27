import csv
from dataclasses import dataclass, field
from io import StringIO
import re
from typing import Literal


PARSER_VERSION = "1"
PROFILE = "utf8_csv_literal_v1"
LOCATOR_REVISION = 1
MAX_CSV_BYTES = 4 * 1024 * 1024
MAX_CSV_RECORDS = 20_000
MAX_CSV_COLUMNS = 128
MAX_CSV_CELL_LENGTH = 32_768
UNSUPPORTED_CONTROLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
AMOUNT = re.compile(r"[+-]?[0-9]+(?:\.[0-9]+)?")
AMOUNT_ROLES = ("amount", "unit", "condition", "exception")
EXCEPTION_LINK_ROLES = ("exception_ref", "exception_key")
MISSING_VALUES = frozenset({"", "-", "?", "tbd", "unknown"})
QuarantineReason = Literal["empty", "invalid_encoding", "unsupported_structure", "size_limit"]


@dataclass(frozen=True)
class CsvRow:
    record_number: int
    values: tuple[str, ...] = field(repr=False)


@dataclass(frozen=True)
class CsvCandidate:
    outcome: Literal["pending_review", "quarantined"]
    reason: QuarantineReason | None = None
    headers: tuple[str, ...] = field(default=(), repr=False)
    rows: tuple[CsvRow, ...] = ()


@dataclass(frozen=True)
class AmountLayout:
    amount: str
    unit: str
    condition: str
    exception: str
    exception_link: tuple[str, str] | None = None
    alternate_columns: tuple[str | None, ...] | None = None

    def __post_init__(self):
        if self.exception_link is not None and (
            not isinstance(self.exception_link, tuple) or len(self.exception_link) != 2
        ):
            raise ValueError("A CSV exception link requires reference and note key column headers.")
        if self.alternate_columns is not None and (
            not isinstance(self.alternate_columns, tuple) or len(self.alternate_columns) != len(AMOUNT_ROLES)
            or all(header is None for header in self.alternate_columns)
        ):
            raise ValueError("Declare one optional alternate column per CSV amount role.")
        headers = self.headers + (self.exception_link or ()) + tuple(
            header for header in self.alternate_columns or () if header is not None
        )
        if any(
            not isinstance(header, str) or not header.strip() or len(header) > 128
            or any(ord(character) < 32 or ord(character) == 127 for character in header)
            for header in headers
        ) or len(set(headers)) != len(headers):
            raise ValueError("A CSV amount layout must declare distinct literal column headers.")

    @property
    def headers(self) -> tuple[str, str, str, str]:
        return self.amount, self.unit, self.condition, self.exception


@dataclass(frozen=True)
class AmountUnitCandidate:
    record_number: int
    columns: tuple[int, ...]
    reason: Literal["missing_column", "missing_value", "invalid_amount", "invalid_exception_link"] | None
    exception_record: int | None = None
    alternatives: tuple[tuple[str, int], ...] = ()


def amount_units(candidate: CsvCandidate, layout: AmountLayout) -> tuple[AmountUnitCandidate, ...]:
    return amount_units_for_rows(candidate.headers, candidate.rows, layout)


def amount_units_for_rows(
    header_values: tuple[str, ...], rows: tuple[CsvRow, ...], layout: AmountLayout,
) -> tuple[AmountUnitCandidate, ...]:
    columns = {header: index for index, header in enumerate(header_values)}
    headers = layout.headers + (layout.exception_link or ())
    if not all(header in columns for header in headers):
        return tuple(AmountUnitCandidate(row.record_number, (), "missing_column") for row in rows)
    indexes = tuple(columns[header] for header in layout.headers)
    positions = tuple(index + 1 for index in indexes)
    alternatives = tuple(
        (role, primary, columns[header])
        for role, primary, header in zip(
            AMOUNT_ROLES, indexes, layout.alternate_columns or (None,) * len(AMOUNT_ROLES), strict=True
        ) if header in columns
    )
    reference_index, key_index = (columns[header] for header in layout.exception_link) if layout.exception_link else (None, None)
    reserved = indexes[:3] + tuple(alternate for role, _, alternate in alternatives if role != "exception")
    notes = {}
    if key_index is not None:
        for row in rows:
            if key := row.values[key_index]:
                notes.setdefault(key, []).append(row)
    units = []
    for row in rows:
        if key_index is not None and row.values[key_index]:
            continue
        values = tuple(row.values[index].strip() for index in indexes)
        reference = row.values[reference_index] if reference_index is not None else ""
        reason = None
        note = None
        member_columns = positions
        if any(value.casefold() in MISSING_VALUES for value in values[:3]):
            reason = "missing_value"
        elif reference:
            matches = notes.get(reference, ())
            if values[3] or len(matches) != 1 or not _valid_note(
                matches[0], reserved, indexes[3], reference_index, reference,
            ):
                reason = "invalid_exception_link"
            else:
                note = matches[0]
                member_columns += (reference_index + 1, key_index + 1)
        elif values[3].casefold() in MISSING_VALUES:
            reason = "missing_value"
        if reason is None and (len(values[0]) > 64 or not AMOUNT.fullmatch(values[0])):
            reason = "invalid_amount"
        if reason is not None:
            units.append(AmountUnitCandidate(row.record_number, (), reason))
            continue
        members = []
        for role, primary, alternate in alternatives:
            source_row = note if note is not None and role == "exception" else row
            if source_row.values[primary] == source_row.values[alternate]:
                members.append((role, alternate + 1))
        units.append(AmountUnitCandidate(
            row.record_number, member_columns, None, note.record_number if note else None, tuple(members),
        ))
    return tuple(units)


def _valid_note(row: CsvRow, reserved: tuple[int, ...], exception_index: int, reference_index: int, key: str) -> bool:
    return (
        len(key) <= 128 and key.strip() == key and key.casefold() not in MISSING_VALUES
        and "\n" not in key and "\r" not in key
        and not row.values[reference_index]
        and all(not row.values[index].strip() for index in reserved)
        and row.values[exception_index].strip().casefold() not in MISSING_VALUES
    )


def parse_csv(payload: bytes) -> CsvCandidate:
    """Read exact cell text; numbers refer to records, not physical lines."""
    if len(payload) > MAX_CSV_BYTES:
        return CsvCandidate("quarantined", "size_limit")
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        return CsvCandidate("quarantined", "invalid_encoding")
    if UNSUPPORTED_CONTROLS.search(text):
        return CsvCandidate("quarantined", "unsupported_structure")

    reader = csv.reader(StringIO(text, newline=""), dialect="excel", strict=True)
    try:
        header = next(reader, None)
        if header is None:
            return CsvCandidate("quarantined", "empty")
        if len(header) > MAX_CSV_COLUMNS or any(len(value) > MAX_CSV_CELL_LENGTH for value in header):
            return CsvCandidate("quarantined", "size_limit")
        keys = {value.strip().casefold() for value in header}
        if not header or "" in keys or len(keys) != len(header) or any(
            "\r" in value or "\n" in value for value in header
        ):
            return CsvCandidate("quarantined", "unsupported_structure")

        rows = []
        for record_number, values in enumerate(reader, start=2):
            if (
                record_number > MAX_CSV_RECORDS + 1 or len(values) > MAX_CSV_COLUMNS
                or any(len(value) > MAX_CSV_CELL_LENGTH for value in values)
            ):
                return CsvCandidate("quarantined", "size_limit")
            if len(values) != len(header):
                return CsvCandidate("quarantined", "unsupported_structure")
            rows.append(CsvRow(record_number, tuple(values)))
    except csv.Error:
        return CsvCandidate("quarantined", "unsupported_structure")
    if not rows:
        return CsvCandidate("quarantined", "empty")
    return CsvCandidate("pending_review", headers=tuple(header), rows=tuple(rows))
