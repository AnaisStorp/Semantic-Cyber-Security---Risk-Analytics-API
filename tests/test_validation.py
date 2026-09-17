"""test SHACL layer: clean data must conform, and each kind of broken data
must be reported, not silently accepted
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from rdflib import XSD, Graph, Literal

from app.graph.namespaces import CORP, SCS
from app.graph.store import DEFAULT_SOURCES, ONTOLOGY_DIR, KnowledgeGraph
from app.graph.validation import shacl_violations, validate_scan_graph
from app.ingest.to_rdf import graph_from_scan_csv

SAMPLE_SCAN = ONTOLOGY_DIR.parent / "data" / "samples" / "scan_2026_09_15.csv"


@pytest.fixture
def broken(graph) -> Graph:
    """A private copy of the reasoned graph, so a test can damage it freely.
    The session-scoped `graph` is shared by every test and must stay clean."""
    copy = Graph()
    copy += graph
    return copy


def _errors_on(violations: list[dict], node: str) -> set[str | None]:
    return {v["path"] for v in violations if v["focus_node"] == node}


def test_sample_estate_conforms(graph):
    assert shacl_violations(graph) == []


def test_missing_ip_address_is_reported(broken):
    broken.remove((CORP.db01, SCS.ipAddress, None))
    assert _errors_on(shacl_violations(broken), "db01") == {"ipAddress"}


def test_cvss_score_out_of_range_is_reported(broken):
    cve = CORP["CVE-2020-1938"]
    broken.set((cve, SCS.cvssScore, Literal(Decimal("12.0"), datatype=XSD.decimal)))
    violations = shacl_violations(broken)
    assert _errors_on(violations, "CVE-2020-1938") == {"cvssScore"}
    assert violations[0]["value"] == "12.0"


def test_unknown_attack_vector_is_reported(broken):
    """A typo is still a valid IRI: OWL accepts it, sh:in does not."""
    broken.set((CORP["CVE-2021-23017"], SCS.hasAttackVector, SCS.AV_Netwrok))
    assert _errors_on(shacl_violations(broken), "CVE-2021-23017") == {"hasAttackVector"}


def test_string_boolean_on_zone_is_reported(broken):
    """A quoted "true" is a string, and would break every internetFacing filter."""
    broken.set((CORP.zone_dmz, SCS.internetFacing, Literal("true")))
    assert _errors_on(shacl_violations(broken), "zone_dmz") == {"internetFacing"}


def test_orphan_service_is_reported(broken):
    broken.remove((None, SCS.runs, CORP.svc_nginx_web01))
    messages = [
        v["message"] for v in shacl_violations(broken) if v["focus_node"] == "svc_nginx_web01"
    ]
    assert messages == ["A service must run on exactly one host."]


def test_misused_domain_is_caught_through_the_full_pipeline(tmp_path):
    """rdfs:domain retypes instead of checking: a CVE given a hostname becomes a
    Host. The shapes then notice this 'host' has no IP address and no zone."""
    typo = tmp_path / "typo.ttl"
    typo.write_text(
        "@prefix scs: <https://anaisstorp.github.io/scsra/ontology#> .\n"
        "@prefix corp: <https://anaisstorp.github.io/scsra/data#> .\n"
        'corp:CVE-2022-1552 scs:hostname "db01.corp.example" .\n'
    )
    kg = KnowledgeGraph(sources=(*DEFAULT_SOURCES, typo))
    kg.load()
    assert {"ipAddress", "locatedIn"} <= _errors_on(shacl_violations(kg.graph), "CVE-2022-1552")


def test_imported_scan_is_validated_against_the_estate():
    """The sample scan conforms once merged with the network model..."""
    scan = graph_from_scan_csv(SAMPLE_SCAN)
    assert validate_scan_graph(scan) == []


def test_imported_scan_with_an_unknown_zone_is_reported(tmp_path):
    """...but a zone the network model has never heard of has no internetFacing
    flag, so its hosts could never be entry points. SHACL says so."""
    csv = tmp_path / "scan.csv"
    csv.write_text(
        SAMPLE_SCAN.read_text().replace("zone_dmz", "zone_guest", 1),
    )
    violations = validate_scan_graph(graph_from_scan_csv(csv))
    assert _errors_on(violations, "zone_guest") == {"internetFacing"}
