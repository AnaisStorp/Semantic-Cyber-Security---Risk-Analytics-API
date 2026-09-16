"""Build the network diagram as a Graphviz DOT string."""

from __future__ import annotations

from app.dashboard.theme import (
    BASELINE,
    GRID,
    INK_MUTED,
    INK_PRIMARY,
    INK_SECONDARY,
    STATUS_CRITICAL,
    STATUS_SERIOUS,
)

_NODE_CLEAN = GRID


def build_network_dot(
    hosts: list[dict],
    zones: dict[str, bool],
    network_edges: list[tuple[str, str]],
    attack_edges: list[tuple[str, str]],
    entry_points: set[str],
) -> str:
    """Render the estate as DOT.

    hosts: dicts with at least id, zone, vulnerable
    zones: {zone_id: is_internet_facing}
    network_edges: asserted connectsTo pairs
    attack_edges: derived attackStepTo pairs
    entry_points: hosts derived as scs:EntryPoint
    """
    attack_set = set(attack_edges)
    lines = [
        "digraph estate {",
        " rankdir=LR;",
        ' bgcolor="transparent";',
        " compound=true;",
        f' node [shape=box style="rounded,filled" fontname="Helvetica" '
        f'fontsize=11 fontcolor="{INK_PRIMARY}" color="{BASELINE}" penwidth=1];',
        f' edge [color="{INK_MUTED}" fontname="Helvetica" fontsize=9 penwidth=1];',
    ]

    by_zone: dict[str, list[dict]] = {}
    for h in hosts:
        by_zone.setdefault(h.get("zone") or "unzoned", []).append(h)

    for zone, members in sorted(by_zone.items()):
        facing = zones.get(zone, False)
        label = f"{zone} (internet-facing)" if facing else zone
        lines += [
            f'  subgraph "cluster_{zone}" {{',
            f'    label="{label}";',
            f'    fontname="Helvetica"; fontsize=10; fontcolor="{INK_SECONDARY}";',
            f'    color="{BASELINE}"; style="rounded";',
        ]
        for h in sorted(members, key=lambda x: x["id"]):
            if h["id"] in entry_points:
                fill, tag = STATUS_CRITICAL, "entry point"
            elif h.get("vulnerable"):
                fill, tag = STATUS_SERIOUS, "vulnerable"
            else:
                fill, tag = _NODE_CLEAN, "no known vulnerability"
            crit = h.get("criticality")
            sub = f"criticality {crit}" if crit is not None else ""
            lines.append(
                f'    "{h["id"]}" [fillcolor="{fill}" ' f'label="{h["id"]}\\n{tag}\\n{sub}"];'
            )

        lines.append("  }")

    for src, dst in sorted(network_edges):
        if (src, dst) in attack_set:
            lines.append(
                f'  "{src}" -> "{dst}" [color="{STATUS_CRITICAL}" penwidth=2.5 '
                f'label="attack step" fontcolor="{STATUS_CRITICAL}"];'
            )
        else:
            lines.append(f'  "{src}" -> "{dst}" [style=solid];')

    lines.append("}")
    return "\n".join(lines)
