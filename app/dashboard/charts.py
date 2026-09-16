from __future__ import annotations

import altair as alt
import pandas as pd

from app.dashboard.theme import (
    ATTACK_VECTOR_COLORS,
    ATTACK_VECTOR_ORDER,
    BASELINE,
    FONT,
    GRID,
    INK_MUTED,
    INK_PRIMARY,
    INK_SECONDARY,
    SURFACE,
)

_VECTOR_SCALE = alt.Scale(
    domain=ATTACK_VECTOR_ORDER,
    range=[ATTACK_VECTOR_COLORS[v] for v in ATTACK_VECTOR_ORDER],
)


def _style(chart: alt.Chart) -> alt.Chart:
    """Apply the dashboard's chrome. Call once, on the TOP-LEVEL chart only."""
    return (
        chart.configure_view(strokeWidth=0, fill=SURFACE)
        .configure_axis(
            grid=True,
            gridColor=GRID,
            gridWidth=1,
            gridDash=[],
            domainColor=BASELINE,
            tickColor=BASELINE,
            labelColor=INK_MUTED,
            titleColor=INK_SECONDARY,
            labelFont=FONT,
            titleFont=FONT,
            labelFontSize=11,
            titleFontSize=11,
        )
        .configure_legend(
            labelColor=INK_SECONDARY,
            titleColor=INK_SECONDARY,
            labelFont=FONT,
            titleFont=FONT,
            labelFontSize=11,
            titleFontSize=11,
            symbolType="square",
            orient="top",
            direction="horizontal",
            offset=8,
        )
        .configure_scale(bandPaddingInner=0.28)
        .configure_text(font=FONT, color=INK_PRIMARY)
    )
    # gridDash=[] forces SOLID gridlines. Dashes read as "projection" or
    # "threshold" when they are just a grid, and add noise for nothing.
    # bandPaddingInner is what creates the gap between bars - a gap, not a border.
    # Altair rejects .configure_* on a sub-chart of a layer, hence "top-level only".


def severity_chart(vulns: pd.DataFrame) -> alt.Chart:
    """Horizontal bars: CVSS score per CVE, coloured by attack vector."""
    base = alt.Chart(vulns).encode(
        y=alt.Y("cve:N", sort="-x", title=None, axis=alt.Axis(labelLimit=180, labelFontSize=11)),
        x=alt.X("cvss:Q", title="CVSS v3.1 base score", scale=alt.Scale(domain=[0, 10])),
        tooltip=[
            alt.Tooltip("cve:N", title="CVE"),
            alt.Tooltip("cvss:Q", title="CVSS", format=".1f"),
            alt.Tooltip("severity:N", title="Severity"),
            alt.Tooltip("attack_vector:N", title="Attack vector"),
            alt.Tooltip("affected_hosts:Q", title="Affected hosts"),
        ],
    )

    bars = base.mark_bar(cornerRadiusEnd=4, height=14).encode(
        color=alt.Color(
            "attack_vector:N", scale=_VECTOR_SCALE, legend=alt.Legend(title="Attack vector")
        ),
    )
    labels = base.mark_text(align="left", dx=6, fontSize=11, color=INK_PRIMARY).encode(
        text=alt.Text("cvss:Q", format=".1f"),
    )

    return _style((bars + labels).properties(height=alt.Step(26), background=SURFACE))


def findings_per_host_chart(findings: pd.DataFrame) -> alt.Chart:
    """Stacked bars: how many findings each host carries, split by attack vector."""
    chart = (
        alt.Chart(findings)
        .mark_bar(cornerRadiusEnd=4, stroke=SURFACE, strokeWidth=2)
        .encode(
            x=alt.X("host:N", sort="-y", title=None, axis=alt.Axis(labelAngle=0)),
            y=alt.Y("count():Q", title="Findings", axis=alt.Axis(tickMinStep=1)),
            color=alt.Color(
                "attack_vector:N",
                scale=_VECTOR_SCALE,
                legend=alt.Legend(title="Attack vector"),
                sort=ATTACK_VECTOR_ORDER,
            ),
            tooltip=[
                alt.Tooltip("host:N", title="Host"),
                alt.Tooltip("attack_vector:N", title="Attack vector"),
                alt.Tooltip("count():Q", title="Findings"),
            ],
        )
        .properties(height=260, background=SURFACE)
    )
    return _style(chart)
