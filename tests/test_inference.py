"""test inference layer: we need to know if the reasoner
does what it is supposed to
"""

from __future__ import annotations

from rdflib import RDF

from app.graph import queries as q
from app.graph.namespaces import CORP, SCS


def test_property_chain_derives_host_vulnerability(graph):
    assert (CORP.web01, SCS.hasVulnerability, CORP["CVE-2021-23017"]) in graph


def test_transitive_closure_derives_multi_hop_reachability(graph):
    assert (CORP.web01, SCS.canReach, CORP.backup01) in graph
    assert (CORP.web01, SCS.connectsTo, CORP.backup01) not in graph
    # 4 asserted edges must yied the 3 hop route


def test_sparql_rules_produce_expected_counts(graph):
    assert len(set(graph.subjects(RDF.type, SCS.RemotelyExploitable))) == 3
    assert len(set(graph.subjects(RDF.type, SCS.EntryPoint))) == 1
    assert len(set(graph.subject_objects(SCS.attackStepTo))) == 4


# regression test for the rule set. each number is a deliberate claim


def test_adjacent_vector_is_not_remotely_exploitable(graph):
    assert (CORP["CVE-2020-15778"], RDF.type, SCS.RemotelyExploitable) not in graph
    assert (CORP.backup01, SCS.hasVulnerability, CORP["CVE-2020-15778"]) in graph


# if this test fails, the tool has started telling users that a flaw requiring same-segment
# access can be exploited from the internet


def test_full_attack_path_is_found(graph):
    """The end-to-end claim of the project, as one assertion."""
    routes = [p["path"] for p in q.find_attack_paths(graph)]
    assert ["web01", "app01", "db01", "backup01"] in routes


def test_internal_host_is_not_an_entry_point(graph):
    """ws_analyst_07 can reach backup01, but not from the internet."""
    entry_hosts = {e["host"] for e in q.list_entry_points(graph)}
    assert entry_hosts == {"web01"}


def test_graph_is_logically_consistent(graph):
    """No individual inferred into owl:Nothing."""
    assert q.integrity_violations(graph) == []
