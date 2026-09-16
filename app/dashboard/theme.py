"""design token for the dashboard: 1 place for every color"""

from __future__ import annotations

FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"

SURFACE = "#1a1a19"
PLANE = "#0d0d0d"
INK_PRIMARY = "#ffffff"
INK_SECONDARY = "#c3c2b7"
INK_MUTED = "#898781"
GRID = "#2c2c2a"
BASELINE = "#383835"

SLOT_1 = "#3987e5"  # blue
SLOT_2 = "#d95926"  # orange
SLOT_3 = "#199e70"  # aqua
SLOT_4 = "#c98500"  # yellow

ATTACK_VECTOR_COLORS: dict[str, str] = {
    "AV_Network": SLOT_1,
    "AV_Adjacent": SLOT_2,
    "AV_Local": SLOT_3,
    "AV_Physical": SLOT_4,
}

ATTACK_VECTOR_ORDER = list(ATTACK_VECTOR_COLORS)

STATUS_GOOD = "#0ca30c"
STATUS_WARNING = "#fab219"
STATUS_SERIOUS = "#ec835a"
STATUS_CRITICAL = "#d03b3b"

SEVERITY_COLORS = {
    "Critical": STATUS_CRITICAL,
    "High": STATUS_SERIOUS,
    "Medium": STATUS_WARNING,
    "Low": STATUS_GOOD,
}


def severity_band(score: float) -> str:
    """CVSS v3.1 qualitative severity rating."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"
