"""Application entry point: builds the FastAPI app and manages its lifecycle."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

# asynccontextmanager turns an async generator into an async `with` block.
# FastAPI's lifespan protocol uses exactly this shape: everything before the
# `yield` runs once at startup, everything after runs once at shutdown.
# It replaced the old @app.on_event("startup") decorators, which are deprecated.
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Middleware wraps every request and response. CORSMiddleware adds the
# Access-Control-Allow-Origin headers a browser needs before it will let
# JavaScript from another origin read our responses.
from app.api.routes import assets, risk, sparql
from app.config import settings
from app.graph.store import knowledge_graph
from app.models import HealthResponse

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load and reason over the graph once, before the first request."""
    logger.info("Loading knowledge graph...")
    stats = knowledge_graph.load()
    logger.info(
        "Ready: %d triples (%d derived) in %.2fs",
        stats.after_rules,
        stats.derived,
        stats.load_seconds,
    )

    yield  # the application serves requests here

    logger.info("Shutting down.")
    # This is why the graph is NOT loaded at import time. Import must stay cheap
    # and side-effect-free: tests import modules, tooling inspects them, and
    # uvicorn's --reload re-imports on every file change. Expensive startup work
    # belongs in the lifespan, which runs exactly once per server process.


app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    lifespan=lifespan,
    description="""
Proactive IT security risk detection over a W3C-conformant knowledge graph.

Infrastructure, software inventory and vulnerability data are modelled in
RDF/OWL. An OWL 2 RL reasoner materialises structural inferences (vulnerability
propagation through the software stack, transitive network reachability), and
forward-chained SPARQL rules add the value-conditional facts OWL cannot express
(CVSS thresholds, attack-vector applicability, internet exposure). Attack paths
are then reconstructed by bounded breadth-first search over the derived
single-hop attack steps.

**Note on risk scores:** the `risk_score` field is a heuristic ordering aid, not
a validated metric. CVSS scores vulnerabilities in isolation and has no notion
of chained exploitation.
""",
    # Markdown in the description is rendered on the /docs page. This block is
    # the first thing a visitor to the API reads - worth writing properly, and
    # worth stating the limitation in.
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
# allow_credentials=False alongside allow_origins=["*"] is deliberate: browsers
# reject that combination outright, which means this configuration cannot
# accidentally become a credential leak if authentication is added later.
# It is still a permissive setting, correct only for a public read-only demo.

app.include_router(assets.router, prefix=settings.api_prefix)
app.include_router(risk.router, prefix=settings.api_prefix)
app.include_router(sparql.router, prefix=settings.api_prefix)
# Final paths: /api/v1/assets/hosts, /api/v1/risk/attack-paths, ...


@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health() -> dict:
    """Liveness check plus graph statistics.

    Deliberately NOT under /api/v1: monitoring systems and container
    orchestrators should not have to track your API version.
    """
    s = knowledge_graph.stats
    return {
        "status": "ok" if len(knowledge_graph) > 0 else "degraded",
        "version": settings.version,
        "graph": {
            "asserted_triples": s.asserted,
            "after_owl_closure": s.after_owl,
            "after_sparql_rules": s.after_rules,
            "derived_triples": s.derived,
            "load_seconds": round(s.load_seconds, 3),
        },
    }
