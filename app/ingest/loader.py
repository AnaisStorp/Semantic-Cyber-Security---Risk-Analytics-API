from __future__ import annotations

from pathlib import Path
from typing import IO

import pandas as pd

from app.ingest.schema import REQUIRED_COLUMNS, EmptyScanError, IngestError, MissingColumnsError


def read_scan_csv(source: str | Path | IO[bytes] | IO[str]) -> pd.DataFrame:
    """Read a scanner CSV export into a dataframe of strings"""
    try:
        df = pd.read_csv(
            source,
            dtype=str,
            keep_default_na=False,
            na_values=["", "NA", "N/A", "n/a", "null", "NULL", "-"],
            skipinitialspace=True,
        )
    except pd.errors.EmptyDataError as exc:
        raise EmptyScanError("The file is empty or has no header row.") from exc
    except pd.errors.ParserError as exc:
        raise IngestError(f"Could not parse the file as CSV: {exc}") from exc
    if df.empty:
        raise EmptyScanError("The file has a header but no data rows.")
    return df


def validate_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Raise if any required column is absent. Returns the frame for chaining."""
    missing = REQUIRED_COLUMNS - set(df.columns)
    # Set difference: "everything required that is not present". One operation,
    # no loop, and the result is already the error message.
    if missing:
        raise MissingColumnsError(
            f"Missing required column(s): {', '.join(sorted(missing))}. "
            f"Found: {', '.join(sorted(df.columns))}"
        )
        # sorted() so the message is deterministic - set iteration order varies
        # between runs, and a test asserting on the message would be flaky.
    return df
