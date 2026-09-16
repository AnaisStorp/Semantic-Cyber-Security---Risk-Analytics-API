"""Inventory endpoints: what exists in the estate."""

from __future__ import annotations

from typing import Annotated

# Annotated[T, metadata] attaches extra information to a type hint. FastAPI uses
# it for dependencies and parameter metadata. It is the current recommended
# style for FastAPI, instead of the older Depends[T] and Query[T] generics.
from fastapi import APIRouter, Depends, Path
from fastapi.concurrency import run_in_threadpool

# THE KEY IMPORT OF THIS STAGE.
# run_in_threadpool(fn, *args) runs a BLOCKING function on a worker thread and
# gives you an awaitable. The event loop stays free to accept other requests
# while the graph query runs.
# What it does NOT do: make the query faster. Python's GIL means only one thread
# executes bytecode at a time, so CPU-bound work is not parallelised. The single
# benefit, and it is a real one, is that one slow SPARQL query cannot freeze
# the whole server for everyone else.
# Equivalent shortcut: defining the endpoint as plain `def` instead of
# `async def` makes FastAPI do exactly this automatically. We do it explicitly
# so the offload is visible in the code rather than implied by a keyword.
from app.api.deps import get_graph, resolve_host
from app.graph import queries as q
from app.graph.store import KnowledgeGraph
from app.models import HostDetail, HostSummary, VulnerabilitySummary

router = APIRouter(prefix="/assets", tags=["assets"])
# APIRouter is a group of routes that gets mounted into the app later. `prefix`
# is prepended to every path below; `tags` groups them into a labelled section
# on the /docs page.

GraphDep = Annotated[KnowledgeGraph, Depends(get_graph)]
# A named alias for the dependency, so each endpoint signature stays short.


@router.get("/hosts", response_model=list[HostSummary], summary="List all hosts")
async def list_hosts(kg: GraphDep) -> list[dict]:
    """Every host in the graph, with its inferred vulnerability status.

    This docstring becomes the endpoint's long description in the OpenAPI docs.
    """
    return await run_in_threadpool(q.list_hosts, kg.graph)
    # response_model=list[HostSummary] makes FastAPI validate each dict against
    # the model and drop any field not declared there. That is a feature: it
    # stops internal data leaking into a response by accident.


@router.get("/hosts/{host_id}", response_model=HostDetail, summary="One host in detail")
async def get_host(
    kg: GraphDep,
    host_id: Annotated[
        str,
        Path(description="Short host identifier, e.g. 'web01'.", pattern=r"^[A-Za-z0-9_.-]{1,64}$"),
    ],
) -> dict:
    """A single host plus the vulnerabilities inferred for it."""
    # The `pattern` is a whitelist applied by FastAPI BEFORE the handler runs.
    # A non-matching id gets an automatic 422 and never reaches our code.
    # Defence in depth: resolve_host is already safe, but rejecting nonsense at
    # the edge keeps the logs clean and the attack surface small.
    iri = await run_in_threadpool(resolve_host, host_id, kg)

    def _collect() -> dict:
        # A small closure so the whole multi-query read happens in ONE thread
        # hop instead of three. Cheaper, and the three queries see a consistent
        # view of the graph.
        summary = next(h for h in q.list_hosts(kg.graph) if h["iri"] == str(iri))
        vulns = q.host_vulnerabilities(kg.graph, iri)
        entry = any(e["host"] == summary["id"] for e in q.list_entry_points(kg.graph))
        return {**summary, "vulnerabilities": vulns, "entry_point": entry}
        # {**a, "k": v} unpacks dict a and adds keys - a merge without mutating
        # the original.

    return await run_in_threadpool(_collect)


@router.get(
    "/vulnerabilities",
    response_model=list[VulnerabilitySummary],
    summary="List all known vulnerabilities",
)
async def list_vulnerabilities(kg: GraphDep) -> list[dict]:
    """Every CVE in the graph, with how many hosts it affects."""
    return await run_in_threadpool(q.list_vulnerabilities, kg.graph)
