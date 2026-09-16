"""smoke test"""

from __future__ import annotations

from app.graph import queries as q


def test_list_hosts_returns_expected_keys(kg):
    hosts = q.list_hosts(kg.graph)
    assert hosts, "expected at least one host"
    assert {"id", "iri", "vulnerable", "criticality"} <= hosts[0].keys()
    # `<=` on dict keys is a SUBSET test: every key on the left must be present.
    # It asserts the contract the UI depends on without breaking whenever we add
    # a new field.


def test_attack_paths_are_ranked_descending(kg):
    paths = q.rank_attack_paths(kg.graph, q.find_attack_paths(kg.graph))
    scores = [p["risk_score"] for p in paths]
    assert scores == sorted(scores, reverse=True)
