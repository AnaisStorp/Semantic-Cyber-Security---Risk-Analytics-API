from __future__ import annotations

import pytest
from rdflib import Graph

from app.graph.store import KnowledgeGraph


@pytest.fixture(scope="session")
def kg() -> KnowledgeGraph:
    """A fully loaded and reasoned knowledge graph, built once per test session.
    scope="session" means pytest instantiates this fixture once and shares it
    across every test, module and class. The default (scope="function") would
    re-run the reasoner before each of the 9 tests.
    """
    graph = KnowledgeGraph()
    graph.load()
    return graph


@pytest.fixture(scope="session")
def graph(kg: KnowledgeGraph) -> Graph:
    """raw rdflib graph -> for tests"""
    return kg.graph
