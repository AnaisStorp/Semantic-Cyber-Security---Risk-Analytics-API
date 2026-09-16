"""Raw SPARQL endpoint.

Exposing arbitrary query execution to the network is genuinely risky, so the
protections are worth stating explicitly rather than assuming.

WHAT PROTECTS US
1. ARCHITECTURAL (the real one): rdflib separates Graph.query() from
     Graph.update(). query() physically cannot modify the graph - INSERT,
     DELETE and DROP are not part of the query grammar it parses. We never call
     update() anywhere in this codebase. So write protection does not depend on
     us correctly spotting bad input.
2. A parse check before execution, so malformed input yields a clean 400.
3. A row cap, so a cartesian product cannot stream gigabytes.
4. Length bounds on the request body (in the Pydantic model).

WHAT DOES NOT PROTECT US
  A keyword blocklist. Those are trivially bypassed and give false confidence.
  We do not use one.

WHAT REMAINS UNSOLVED stated plainly rather than hidden:
  rdflib has no query timeout. A deliberately expensive query can consume CPU
  for a long time. The row cap limits output, not work. Mitigations:
  - set enable_sparql_endpoint=false for any deployment that is not a demo
  - Stage 6 moves execution to Apache Jena Fuseki, which HAS a real per-query
    timeout, and that is the proper fix.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from rdflib.plugins.sparql import prepareQuery

# prepareQuery parses and compiles a SPARQL query string WITHOUT executing it.
# Two uses: catching syntax errors early (so we answer 400 instead of 500), and
# the fact that it accepts the QUERY grammar only - update syntax fails to parse
# here, which is a second independent barrier on top of point 1 above.
from rdflib.term import Literal, URIRef

from app.api.deps import get_graph
from app.config import settings
from app.graph.namespaces import PREFIX_MAP
from app.graph.store import KnowledgeGraph
from app.models import SparqlRequest, SparqlResponse

router = APIRouter(prefix="/sparql", tags=["sparql"])

GraphDep = Annotated[KnowledgeGraph, Depends(get_graph)]


def _term_to_json(term):
    """Convert an RDF term into something JSON can carry."""
    if term is None:
        return None
    if isinstance(term, Literal):
        return term.toPython()
        # toPython() maps a typed literal to its native equivalent:
        # xsd:integer -> int, xsd:decimal -> Decimal, xsd:boolean -> bool.
        # Decimal is not JSON-serialisable, hence the float() fallback below.
    if isinstance(term, URIRef):
        return str(term)
    return str(term)


def _jsonable(value):
    from decimal import Decimal

    return float(value) if isinstance(value, Decimal) else value


@router.post("", response_model=SparqlResponse, summary="Execute a read-only SPARQL query")
async def run_sparql(payload: SparqlRequest, kg: GraphDep) -> dict:
    """Run a SPARQL SELECT or ASK query against the materialised graph.

    The graph already contains all inferred triples, so a query here sees the
    derived facts (hasVulnerability, canReach, EntryPoint, attackStepTo) exactly
    as if they had been asserted.
    """
    if not settings.enable_sparql_endpoint:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The SPARQL endpoint is disabled in this deployment.",
        )

    try:
        prepared = prepareQuery(payload.query, initNs=PREFIX_MAP)
        # initNs pre-binds our prefixes, so a caller can write scs:Host without
        # repeating the PREFIX lines. A convenience, not a security control.
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid SPARQL query: {exc}",
        ) from exc
        # `from exc` preserves the original exception as __cause__, so the
        # traceback in your logs shows the real parse error. Dropping it makes
        # debugging needlessly hard.

    def _execute() -> dict:
        result = kg.graph.query(prepared)

        if result.type == "ASK":
            return {
                "columns": ["result"],
                "rows": [{"result": bool(result.askAnswer)}],
                "row_count": 1,
                "truncated": False,
            }

        columns = [str(v) for v in result.vars or []]
        rows, truncated = [], False
        for i, row in enumerate(result):
            if i >= settings.sparql_max_rows:
                truncated = True
                break
            rows.append({c: _jsonable(_term_to_json(row[idx])) for idx, c in enumerate(columns)})
        return {"columns": columns, "rows": rows, "row_count": len(rows), "truncated": truncated}
        # Breaking out of the loop matters: rdflib's Result is a generator, so
        # we stop PRODUCING rows at the cap rather than building the full list
        # and slicing it afterwards.

    return await run_in_threadpool(_execute)
