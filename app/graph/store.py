"""In memory RDF store: loads the ontology nd data, exposes SPARQL access

Design decision: the graph is build ONce at application startup and then treated
as read-only."""

from __future__ import annotations

# makes all type annotations lazy (stored as strings, evaluated only if asked)
# you can write `-> KnowledgeGraph` inside of the class that
# defines KnowledgeGraph, and annotations cost nothing at import time
import logging
import threading

# we need a lock. FastAPI serves synchronous work on a thread pool, so 2
# requests really can run in parallel OS threads.
import time
from dataclasses import dataclass

# dataclass generates __inits, __repr__ and __eq__ from annotatied attributes
# field is needed for defaults that are mutable or computed
from pathlib import Path

from rdflib import Graph

# THE central class. A Graph is a set of (subject, predicate, object) triples
# plus a SPARQL engine and parsers/serialisers. Our entire knowledge base is one
# of these. By default it uses an in-memory store; the same API also talks to a
# remote SPARQL server, which is how Stage 6 will swap in Fuseki with almost no
# code change.
from app.graph.namespaces import PREFIX_MAP

logger = logging.getLogger(__name__)
# __file__ is this file's path. .resolve() makes it absolute (important: it must
# not depend on the working directory you happened to launch from).
# parents[0] = app/graph, parents[1] = app, parents[2] = the repository root.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
ONTOLOGY_DIR = _PROJECT_ROOT / "ontology"

DEFAULT_SOURCES = (
    ONTOLOGY_DIR / "cybersec.ttl",  # T-Box: the rules
    ONTOLOGY_DIR / "sample_infrastructure.ttl",  # A-Box: the facts
)


@dataclass
class GraphStats:
    """triple counts at each stage of the pipeline. Returned by the /health endpoint"""

    asserted: int = 0  # what the .ttl file literally contain
    after_owl: int = 0  # after the owl 2 rl closure
    after_rules: int = 0  # after sparql construct rules
    load_seconds: float = 0.0

    @property
    def derived(self) -> int:
        return self.after_rules - self.asserted


class KnowledgeGraph:
    """Owns the rdflib Graph and everything done to it"""

    def __init__(self, sources: tuple[Path, ...] = DEFAULT_SOURCES) -> None:
        self._sources = sources
        self._graph = Graph()
        self._lock = threading.Lock()
        self.stats = GraphStats()

    def load(self, *, reason: bool = True) -> GraphStats:
        """Parse the source files and (optionally) materialise all inferences.

        The `*` makes `reason` keyword-only: callers must write
        load(reason=False), never load(False). Bare booleans at call sites are
        unreadable six months later.
        """
        started = time.perf_counter()

        with self._lock:
            graph = Graph()  # build into a NEW graph, swap at the end
            for source in self._sources:
                if not source.exists():
                    raise FileNotFoundError(f"Ontology source not found: {source}")
                graph.parse(source, format="turtle")
                logger.info("Parsed %s", source.name)

            stats = GraphStats(asserted=len(graph))
            # len(Graph) is the number of triples. Graph also supports
            # `in`, iteration, and set operations - it behaves like a set of triples.

            if reason:
                # Imported here, not at module top, purely to keep the dependency
                # direction clear: store -> reasoner, never the reverse.
                from app.graph.reasoner import apply_all_inference

                stats = apply_all_inference(graph, stats)

            for prefix, namespace in PREFIX_MAP.items():
                graph.bind(prefix, namespace)
            # bind() only affects SERIALISATION - how triples are printed. It has
            # no effect on what the graph contains or on query results.

            stats.load_seconds = time.perf_counter() - started
            self._graph = graph  # atomic swap: readers never see a half-built graph
            self.stats = stats

        logger.info(
            "Graph ready: %d asserted -> %d total (%d derived) in %.2fs",
            stats.asserted,
            stats.after_rules,
            stats.derived,
            stats.load_seconds,
        )
        return stats

    @property
    def graph(self) -> Graph:
        """The underlying rdflib Graph. Read-only by convention."""
        return self._graph

    def query(self, query_string: str, init_bindings: dict | None = None):
        """Run a SPARQL SELECT/ASK/CONSTRUCT and return rdflib's Result.

        `init_bindings` is the ONLY correct way to inject a value into a query.
        It binds a variable to a term in the query's execution context, so the
        value is never parsed as SPARQL syntax. Building queries with f-strings
        or concatenation is SPARQL injection - the exact same class of bug as SQL
        injection - and in a security-analysis tool it would be embarrassing.
        """
        return self._graph.query(query_string, initBindings=init_bindings or {})

    def __len__(self) -> int:
        return len(self._graph)


# module-level singleton
# One shared instance for the running application. It is created empty and
# EXPLICITLY loaded by FastAPI's lifespan handler in Stage 4 - never at import
# time, because importing a module must not do seconds of work or touch disk
# (it would make every test import slow and break tooling that merely inspects
# the module).
knowledge_graph = KnowledgeGraph()
