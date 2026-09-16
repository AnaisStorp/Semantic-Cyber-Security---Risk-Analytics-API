from __future__ import annotations

REQUIRED_COLUMNS: frozenset[str] = frozenset(
    {
        "hostname",
        "ip_address",
        "zone",
        "criticality",
        "service",
        "product",
        "version",
    }
)

FINDING_COLUMNS: frozenset[str] = frozenset({"cve_id", "cvss_score", "attack_vector"})

OPTIONAL_COLUMNS: frozenset[str] = frozenset({"port", "detected_at"})

ALL_COLUMNS = REQUIRED_COLUMNS | FINDING_COLUMNS | OPTIONAL_COLUMNS

ATTACK_VECTOR_MAP: dict[str, str] = {
    # CVSS vector-string notation
    "av:n": "AV_Network",
    "av:a": "AV_Adjacent",
    "av:l": "AV_Local",
    "av:p": "AV_Physical",
    # single letters
    "n": "AV_Network",
    "a": "AV_Adjacent",
    "l": "AV_Local",
    "p": "AV_Physical",
    # full words, as various tools emit them
    "network": "AV_Network",
    "remote": "AV_Network",
    "adjacent": "AV_Adjacent",
    "adjacent_network": "AV_Adjacent",
    "adjacent network": "AV_Adjacent",
    "local": "AV_Local",
    "physical": "AV_Physical",
}

CANONICAL_ATTACK_VECTORS: tuple[str, ...] = (
    "AV_Network",
    "AV_Adjacent",
    "AV_Local",
    "AV_Physical",
)

ATTACK_VECTOR_MAP.update({v.lower(): v for v in CANONICAL_ATTACK_VECTORS})

CVSS_MIN, CVSS_MAX = 0.0, 10.0
CRITICALITY_MIN, CRITICALITY_MAX = 1, 5


class IngestError(ValueError):
    """Base class for every ingestion failure.

    Subclassing ValueError rather than Exception means a caller who only cares
    that the input was bad can write `except ValueError`, while a caller who
    needs the detail can catch the specific subclass. Defining a base class for
    the module also lets the Streamlit app write one `except IngestError` around
    the whole upload flow.
    """


class MissingColumnsError(IngestError):
    """The file does not have the columns we require."""


class EmptyScanError(IngestError):
    """The file parsed, but contains no usable rows."""
