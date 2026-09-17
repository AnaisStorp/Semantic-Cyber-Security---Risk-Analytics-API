"""Design tokens for the dashboard: one place for every colour."""

from __future__ import annotations

FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"

PLANE = "#08090a"
SURFACE = "#111214"
SURFACE_RAISED = "#17191c"
BORDER = "#26282d"

INK_PRIMARY = "#f4f4f5"
INK_SECONDARY = "#a1a1aa"
INK_MUTED = "#71717a"

GRID = "#1e2024"
BASELINE = "#2a2d32"
NODE_NEUTRAL = "#22252a"

SLOT_1 = "#6f6bef"
SLOT_2 = "#13a3a3"
SLOT_3 = "#c98500"
SLOT_4 = "#d55181"

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
