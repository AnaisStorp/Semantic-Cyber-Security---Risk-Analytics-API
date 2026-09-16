"""pydantic response models, the API's contarct

These do 3 jobs at one:
1. validate what we sent (a typo fails in tests, not in pro)
2. serialise python objects to json
3. generate the openAPI schema. every field description below
becomes documentation on the /docs page, for free"""

from __future__ import annotations

from pydantic import BaseModel, Field


class HostSummary(BaseModel):
    id: str = Field(description="Short identifier, e.g. 'web01'.")
    iri: str = Field(description="Full IRI of the host in the knowledge graph.")
    label: str | None = Field(default=None, description="Human-readable name.")
    ip_address: str | None = None
    zone: str | None = Field(default=None, description="Network zone, e.g. 'zone_dmz'.")
    criticality: int | None = Field(default=None, description="Business impact, 1-5.")
    vulnerable: bool = Field(description="Inferred: carries at least one known vulnerability.")
    # "str | None" is Python syntax for Optional[str]. Combined with
    # default=None it means "may be absent", which matches RDF's open world,
    # where a missing triple is normal rather than an error.


class VulnerabilityRef(BaseModel):
    cve: str
    cvss: float = Field(ge=0.0, le=10.0)
    attack_vector: str = Field(
        description="CVSS AV metric: AV_Network, AV_Adjacent, AV_Local, AV_Physical."
    )


class HostDetail(HostSummary):
    """A host plus its inferred vulnerabilities. Inherits every field above."""

    vulnerabilities: list[VulnerabilityRef] = []
    entry_point: bool = Field(
        default=False,
        description="Inferred: internet-facing AND remotely exploitable.",
    )


class VulnerabilitySummary(BaseModel):
    cve: str
    cvss: float
    attack_vector: str
    remotely_exploitable: bool = Field(
        description="Rule-derived: AV_Network and CVSS above threshold."
    )
    affected_hosts: int


class EntryPoint(BaseModel):
    host: str
    ip_address: str | None = None
    zone: str
    cve: str
    cvss: float


class AttackPath(BaseModel):
    entry_point: str
    target: str
    hops: int
    path: list[str] = Field(description="Ordered host sequence, entry point first.")
    max_cvss: float
    target_criticality: int
    risk_score: float = Field(
        description="HEURISTIC, not a standard: max_cvss x target_criticality / 5. "
        "CVSS scores vulnerabilities in isolation and has no notion of "
        "chained exploitation; this is an ordering aid only.",
    )
    # Putting the caveat in the field description means it appears in the public
    # API documentation. Someone integrating against this cannot miss it.


class BlastRadiusEntry(BaseModel):
    asset: str
    criticality: int | None = None


class IntegrityReport(BaseModel):
    consistent: bool
    violations: list[str] = Field(
        default=[],
        description="Individuals the reasoner placed in owl:Nothing - i.e. data "
        "that contradicts the ontology's disjointness axioms.",
    )


class GraphStatsResponse(BaseModel):
    asserted_triples: int
    after_owl_closure: int
    after_sparql_rules: int
    derived_triples: int
    load_seconds: float


class HealthResponse(BaseModel):
    status: str
    version: str
    graph: GraphStatsResponse


class SparqlRequest(BaseModel):
    query: str = Field(
        min_length=8,
        max_length=8000,
        description="A SPARQL 1.1 SELECT or ASK query. Updates are not accepted.",
    )
    # Length bounds are the cheapest possible denial-of-service brake: they
    # reject an absurd payload before the SPARQL parser ever sees it.


class SparqlResponse(BaseModel):
    columns: list[str]
    rows: list[dict]
    row_count: int
    truncated: bool = Field(description="True if the result was cut at the configured row limit.")
