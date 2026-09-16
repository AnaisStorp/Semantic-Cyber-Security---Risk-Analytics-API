"""Cleaning and filtering functions for scan dataframes.

DESIGN RULE for this module: every function takes a DataFrame and returns a NEW
DataFrame. None of them mutate their input, none of them touch the filesystem,
none of them depend on global state.
"""

from __future__ import annotations

import re

import pandas as pd

from app.ingest.schema import (
    ATTACK_VECTOR_MAP,
    CRITICALITY_MAX,
    CRITICALITY_MIN,
    CVSS_MAX,
    CVSS_MIN,
    FINDING_COLUMNS,
)

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
# Compiled once at import rather than on every call. re.compile caches
# internally, but an explicit module-level pattern also documents the intent and
# keeps the function body readable.


def normalise_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """'  IP Address ' -> 'ip_address'."""
    out = df.copy()
    out.columns = [_NON_ALNUM.sub("_", str(c).strip().lower()).strip("_") for c in out.columns]
    return out


def strip_string_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Remove leading/trailing whitespace from every text cell.
    """
    out = df.copy()
    for col in out.columns:
        if pd.api.types.is_string_dtype(out[col]):
            out[col] = out[col].str.strip()
    return out


def coerce_types(df: pd.DataFrame) -> pd.DataFrame:
    """Convert numeric columns from text to numbers, invalid values to NaN."""
    out = df.copy()

    out["cvss_score"] = pd.to_numeric(out["cvss_score"], errors="coerce")

    for col in ("criticality", "port"):
        if col in out.columns:
            out[col] = pd.to_numeric(out[col], errors="coerce").astype("Int64")

    if "detected_at" in out.columns:
        out["detected_at"] = pd.to_datetime(out["detected_at"], errors="coerce")
    return out


def normalise_attack_vector(df: pd.DataFrame) -> pd.DataFrame:
    """Map every spelling of an attack vector to one canonical term."""
    out = df.copy()
    out["attack_vector"] = out["attack_vector"].str.strip().str.lower().map(ATTACK_VECTOR_MAP)
    return out


def drop_unusable_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Drop rows that do not describe an asset at all."""
    out = df.copy()
    return out.dropna(subset=["hostname", "product"]).reset_index(drop=True)


def nullify_invalid_findings(df: pd.DataFrame) -> pd.DataFrame:
    """Blank out finding columns on rows whose vulnerability data is unusable.

    THE KEY POLICY DECISION OF THIS MODULE, and worth defending explicitly."""
    out = df.copy()

    score = out["cvss_score"]
    valid = (
        out["cve_id"].notna()
        & score.notna()
        & score.between(CVSS_MIN, CVSS_MAX)
        & out["attack_vector"].notna()
    )

    out.loc[~valid, list(FINDING_COLUMNS)] = pd.NA
    return out


def clip_criticality(df: pd.DataFrame) -> pd.DataFrame:
    """Force criticality into the documented 1-5 range."""
    out = df.copy()
    out["criticality"] = out["criticality"].clip(CRITICALITY_MIN, CRITICALITY_MAX)
    return out


def deduplicate_findings(df: pd.DataFrame) -> pd.DataFrame:
    """Collapse repeats of the same (host, software, CVE) to the worst score."""
    out = df.copy()
    key = ["hostname", "product", "version", "cve_id"]
    return (
        out.sort_values("cvss_score", ascending=False, na_position="last")
        .drop_duplicates(subset=key, keep="first")
        .sort_values(["hostname", "cve_id"], na_position="last")
        .reset_index(drop=True)
    )


def filter_by_severity(df: pd.DataFrame, min_score: float) -> pd.DataFrame:
    """Keep only rows whose CVSS score is at least min_score."""
    return df.loc[df["cvss_score"] >= min_score].reset_index(drop=True)


def filter_by_attack_vector(df: pd.DataFrame, vectors: set[str]) -> pd.DataFrame:
    """Keep only rows whose canonical attack vector is in `vectors`."""
    return df.loc[df["attack_vector"].isin(vectors)].reset_index(drop=True)


def filter_by_zone(df: pd.DataFrame, zones: set[str]) -> pd.DataFrame:
    """Keep only rows whose host sits in one of the given zones."""
    return df.loc[df["zone"].isin(zones)].reset_index(drop=True)


def filter_findings_only(df: pd.DataFrame) -> pd.DataFrame:
    """Keep only rows that actually carry a vulnerability."""
    return df.loc[df["cve_id"].notna()].reset_index(drop=True)
