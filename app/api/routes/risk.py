"""Risk analytics: the endpoints that justify the project."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query
from fastapi.concurrency import run_in_threadpool

from app.api.deps import get_graph, resolve_host
from app.config import settings
from app.graph import queries as q
from app.graph.store import KnowledgeGraph
from app.graph.validation import shacl_violations
from app.models import AttackPath, BlastRadiusEntry, EntryPoint, IntegrityReport

router = APIRouter(prefix="/risk", tags=["risk"])

GraphDep = Annotated[KnowledgeGraph, Depends(get_graph)]


@router.get(
    "/entry-points",
    response_model=list[EntryPoint],
    summary="Hosts an external attacker can reach first",
)
async def entry_points(kg: GraphDep) -> list[dict]:
    """Hosts in an internet-facing zone carrying a remotely exploitable flaw.

    Fully inferred: no triple in the source data says 'entry point'. It follows
    from the zone's internetFacing flag, the OWL property chain that derives
    hasVulnerability, and the CVSS/attack-vector rule.
    """
    return await run_in_threadpool(q.list_entry_points, kg.graph)


@router.get(
    "/attack-paths", response_model=list[AttackPath], summary="Enumerate justified attack paths"
)
async def attack_paths(
    kg: GraphDep,
    max_depth: Annotated[
        int, Query(ge=1, le=15, description="Maximum hops to explore.")
    ] = settings.max_attack_depth,
    min_risk: Annotated[
        float, Query(ge=0.0, le=10.0, description="Drop paths below this risk score.")
    ] = 0.0,
) -> list[dict]:
    """Every path from an entry point where each hop is backed by a usable CVE.

    Unlike plain network reachability, each step here required the target to
    carry a vulnerability whose attack vector permits that specific move -
    remote from anywhere, or adjacent only within the same zone.
    """

    def _compute() -> list[dict]:
        paths = q.find_attack_paths(kg.graph, max_depth=max_depth)
        ranked = q.rank_attack_paths(kg.graph, paths)
        return [p for p in ranked if p["risk_score"] >= min_risk]

    return await run_in_threadpool(_compute)
    # Query(ge=..., le=...) bounds max_depth at the edge. Without it, a caller
    # passing max_depth=10000 would make the BFS explore an enormous state space
    # and pin a CPU. Validating range on every numeric parameter that feeds an
    # algorithm is not paranoia, it is the job.


@router.get(
    "/blast-radius/{asset_id}",
    response_model=list[BlastRadiusEntry],
    summary="What breaks if this asset falls",
)
async def blast_radius(
    kg: GraphDep,
    asset_id: Annotated[str, Path(pattern=r"^[A-Za-z0-9_.-]{1,64}$")],
) -> list[dict]:
    """Transitive closure of dependsOn, inbound: everything that depends on this asset."""
    iri = await run_in_threadpool(resolve_host, asset_id, kg)
    return await run_in_threadpool(q.blast_radius, kg.graph, iri)


@router.get("/integrity", response_model=IntegrityReport, summary="Semantic integrity check")
async def integrity(kg: GraphDep) -> dict:
    """Detect data that contradicts the ontology or does not have the expected shape.

    Two checks, because they catch different mistakes:
    - OWL: individuals the reasoner placed in owl:Nothing - the empty class.
      Membership there is a logical impossibility, so the data violates a
      disjointness axiom: something both a Host and a Vulnerability, for instance.
    - SHACL: nodes that break a shape in ontology/shapes.ttl - a host with no
      zone, a CVSS score of 12, an unknown attack vector. OWL cannot see these,
      because under the open-world assumption missing data is just unknown.

    Clean data returns consistent=true with two empty lists.
    """
    violations = await run_in_threadpool(q.integrity_violations, kg.graph)
    shape_errors = await run_in_threadpool(shacl_violations, kg.graph)
    return {
        "consistent": not violations and not shape_errors,
        "violations": violations,
        "shacl_violations": shape_errors,
    }
