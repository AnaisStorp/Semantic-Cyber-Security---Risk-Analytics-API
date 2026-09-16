"""Tests for the pure dashboard logic - no Streamlit involved."""

from __future__ import annotations

import pandas as pd
import pytest

from app.dashboard.charts import findings_per_host_chart, severity_chart
from app.dashboard.diagram import build_network_dot
from app.dashboard.theme import ATTACK_VECTOR_COLORS, severity_band

HOSTS = [
    {"id": "web01", "zone": "zone_dmz", "vulnerable": True, "criticality": 3},
    {"id": "db01", "zone": "zone_data", "vulnerable": True, "criticality": 5},
    {"id": "ws07", "zone": "zone_internal", "vulnerable": False, "criticality": 2},
]
ZONES = {"zone_dmz": True, "zone_data": False, "zone_internal": False}


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (10.0, "Critical"),
        (9.0, "Critical"),
        (8.9, "High"),
        (7.0, "High"),
        (6.9, "Medium"),
        (4.0, "Medium"),
        (3.9, "Low"),
        (0.0, "Low"),
    ],
)
def test_severity_bands_match_the_cvss_spec(score, band):
    """Every boundary, from both sides. CVSS v3.1 §5."""
    assert severity_band(score) == band


def test_attack_vector_colours_are_fixed_and_unique():
    """Colour follows the entity, so the mapping must be stable and injective."""
    assert set(ATTACK_VECTOR_COLORS) == {"AV_Network", "AV_Adjacent", "AV_Local", "AV_Physical"}
    assert len(set(ATTACK_VECTOR_COLORS.values())) == 4


def test_dot_places_each_host_in_its_zone_cluster():
    dot = build_network_dot(HOSTS, ZONES, [("web01", "db01")], [], set())
    assert 'subgraph "cluster_zone_dmz"' in dot
    assert '"web01"' in dot and '"db01"' in dot


def test_dot_marks_the_internet_facing_zone():
    dot = build_network_dot(HOSTS, ZONES, [], [], set())
    assert "zone_dmz (internet-facing)" in dot
    assert "zone_data (internet-facing)" not in dot


def test_dot_highlights_attack_edges_differently_from_firewall_edges():
    edges = [("web01", "db01"), ("ws07", "db01")]
    dot = build_network_dot(HOSTS, ZONES, edges, [("web01", "db01")], {"web01"})
    assert 'label="attack step"' in dot
    assert dot.count("->") == 2  # both edges drawn
    assert dot.count("penwidth=2.5") == 1  # only one styled as an attack step


def test_dot_labels_status_in_text_not_only_colour():
    """Accessibility: a status colour must never carry meaning alone."""
    dot = build_network_dot(HOSTS, ZONES, [], [], {"web01"})
    assert "entry point" in dot
    assert "no known vulnerability" in dot


def test_severity_chart_builds_without_error():
    df = pd.DataFrame(
        {
            "cve": ["CVE-1", "CVE-2"],
            "cvss": [9.8, 7.4],
            "attack_vector": ["AV_Network", "AV_Adjacent"],
            "severity": ["Critical", "High"],
            "affected_hosts": [1, 2],
        }
    )
    chart = severity_chart(df)
    spec = chart.to_dict()
    assert spec["background"] == "#1a1a19"


def test_severity_chart_pins_the_axis_to_zero():
    """A bar chart with a truncated axis lies about magnitude."""
    df = pd.DataFrame(
        {
            "cve": ["CVE-1"],
            "cvss": [9.8],
            "attack_vector": ["AV_Network"],
            "severity": ["Critical"],
            "affected_hosts": [1],
        }
    )
    spec = severity_chart(df).to_dict()
    encodings = spec["layer"][0]["encoding"]
    assert encodings["x"]["scale"]["domain"] == [0, 10]


def test_findings_chart_pins_colours_to_attack_vectors():
    df = pd.DataFrame(
        {
            "host": ["web01", "db01"],
            "attack_vector": ["AV_Network", "AV_Adjacent"],
        }
    )
    spec = findings_per_host_chart(df).to_dict()
    scale = spec["encoding"]["color"]["scale"]
    assert scale["domain"] == ["AV_Network", "AV_Adjacent", "AV_Local", "AV_Physical"]
