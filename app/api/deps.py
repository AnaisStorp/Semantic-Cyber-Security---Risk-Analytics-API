"""shared api dependencies

a "dependency" in FastAPI is just a callable you declare as a param.
the framework calls it before your endpoint and it passes the result it.
The benefit over importing the object directly is that a test can OVERRIDE the dependency,
swapping the real graph for a fixture without touching the endpoint code
"""

from __future__ import annotations

from fastapi import HTTPException, status

# HTTPException is how you return an error response: raise it, and FastAPI
# converts it to the right status code and JSON body.
# `status` holds readable constants - status.HTTP_404_NOT_FOUND instead of 404.
from rdflib import URIRef

from app.graph import queries as q
from app.graph.namespaces import CORP
from app.graph.store import KnowledgeGraph, knowledge_graph


def get_graph() -> KnowledgeGraph:
    """Provide the loaded knowledge graph, or fail clearly if it is not ready."""
    if len(knowledge_graph) == 0:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Knowledge graph is not loaded.",
        )
    return knowledge_graph
    # 503 Service Unavailable, not 500. 500 means "we have a bug"; 503 means
    # "try again shortly". Getting status codes right is most of what makes an
    # API pleasant to integrate against.


def resolve_host(host_id: str, kg: KnowledgeGraph) -> URIRef:
    """Turn a short id like 'web01' into its IRI, or raise 404.

    CORP[host_id] concatenates the data namespace with the id. Note that this
    string never reaches a query as TEXT - it becomes a URIRef term, bound
    through initBindings. So a host_id of "web01> } DELETE {" is simply an IRI
    that does not exist, and produces a 404. Not a vulnerability.
    """
    iri = CORP[host_id]
    if not q.host_exists(kg.graph, iri):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No host with id '{host_id}' in the knowledge graph.",
        )
    return iri
