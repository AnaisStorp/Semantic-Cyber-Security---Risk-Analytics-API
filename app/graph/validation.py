"""SHACL validation: check that the data has the shape the rules expect.

The reasoner never complains about missing data. Under the open-world assumption
a host without a zone is simply a host whose zone is unknown, so it quietly drops
out of every attack path. SHACL is the closed-world check that turns that silence
into an explicit error.

The shapes live in ontology/shapes.ttl, in their own graph. They are never merged
into the knowledge graph: shapes describe the data, they are not part of it.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pyshacl import validate

# pySHACL takes a data graph and a shapes graph and returns
# (conforms, results_graph, results_text). The results graph is itself RDF,
# described with the SHACL vocabulary - so we read it back with SPARQL.
from rdflib import Graph

from app.graph.store import DEFAULT_SOURCES, ONTOLOGY_DIR, GraphStats

SHAPES_PATH = ONTOLOGY_DIR / "shapes.ttl"


@lru_cache(maxsize=1)
def load_shapes(path: Path = SHAPES_PATH) -> Graph:
    """Parse the shapes file once per process. The shapes never change at runtime."""
    shapes = Graph()
    shapes.parse(path, format="turtle")
    return shapes


Q_RESULTS = """
PREFIX sh: <http://www.w3.org/ns/shacl#>
SELECT ?focus ?path ?value ?message ?severity ?shape WHERE {
    ?result a sh:ValidationResult ;
            sh:focusNode ?focus ;
            sh:resultSeverity ?severity ;
            sh:sourceShape ?shape .
    OPTIONAL { ?result sh:resultPath ?path }
    OPTIONAL { ?result sh:value ?value }
    OPTIONAL { ?result sh:resultMessage ?message }
}
ORDER BY ?focus ?path
"""
# OPTIONAL because a result only carries a path when a property shape failed,
# and a value only when a specific value was wrong (a missing value has none).


def _local(term) -> str | None:
    """IRI -> its short name ('...#web01' -> 'web01'). Literals and blank nodes as text."""
    if term is None:
        return None
    text = str(term)
    return text.rsplit("#", 1)[-1].rsplit("/", 1)[-1] if "#" in text or "/" in text else text


def shacl_violations(graph: Graph, shapes: Graph | None = None) -> list[dict]:
    """Validate `graph` against the shapes. Returns [] when the data conforms.

    inference="none": the graph is already materialised by the OWL 2 RL
    reasoner, so every Server is already typed as a Host. Asking pySHACL to
    reason again would only redo the same work.
    """
    conforms, results, _ = validate(
        graph,
        shacl_graph=shapes if shapes is not None else load_shapes(),
        inference="none",
    )
    if conforms:
        return []
    return [
        {
            "focus_node": _local(row.focus),
            "path": _local(row.path),
            "value": None if row.value is None else str(row.value),
            "message": str(row.message) if row.message is not None else "",
            "severity": _local(row.severity),
        }
        for row in results.query(Q_RESULTS)
    ]


def validate_scan_graph(scan: Graph) -> list[dict]:
    """Validate an imported scan in the context of the estate, in an isolated graph.

    A scan alone would always fail: it names zones but never says
    whether they face the internet - that comes from the network model. So the
    scan is merged with the ontology and the sample estate, reasoned, and then
    validated. The running knowledge graph is never touched.
    """
    from app.graph.reasoner import apply_all_inference

    merged = Graph()
    for source in DEFAULT_SOURCES:
        merged.parse(source, format="turtle")
    merged += scan
    apply_all_inference(merged, GraphStats(asserted=len(merged)))
    return shacl_violations(merged)
