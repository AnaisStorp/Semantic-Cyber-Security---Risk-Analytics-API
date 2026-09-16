"""the composed cleaning pipeline: 1 fonction in teh right order"""

from __future__ import annotations

from pathlib import Path
from typing import IO

import pandas as pd

from app.ingest import filters as f
from app.ingest.loader import read_scan_csv, validate_columns
from app.ingest.schema import EmptyScanError


def clean_scan_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    return (
        df.pipe(f.normalise_column_names)
        .pipe(validate_columns)
        .pipe(f.strip_string_columns)
        .pipe(f.coerce_types)
        .pipe(f.normalise_attack_vector)
        .pipe(f.drop_unusable_rows)
        .pipe(f.nullify_invalid_findings)
        .pipe(f.clip_criticality)
        .pipe(f.deduplicate_findings)
    )


def ingest_scan_csv(source: str | Path | IO[bytes] | IO[str]) -> pd.DataFrame:
    """Read a scan export from disk or an upload and return a clean dataframe."""
    df = clean_scan_dataframe(read_scan_csv(source))
    if df.empty:
        raise EmptyScanError("No usable rows remained after cleaning.")
    return df
