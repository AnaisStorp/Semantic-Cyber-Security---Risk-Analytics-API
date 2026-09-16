"""SPARQL queries and the attack-path search.

Queries return plain Python dicts. Converting those to Pydantic response models
is Stage 4's job, this module must stay usable from a script or a test with no
web framework in sight.
"""

from __future__ import annotations

from collections import deque

# A double-ended queue with O(1) append and popleft. Using a plain list as a
# queue means list.pop(0), which is O(n) because every remaining element shifts.
# deque is the correct data structure for breadth-first search.
from rdflib import Graph, URIRef

from app.graph.namespaces import CORP, SCS

# URIRef is the type for "a resource identified by an IRI" - one of the three
# kinds of RDF term (URIRef, Literal, BNode). We need it to bind values into
# parameterised queries.


PREFIXES = f"""
PREFIX scs:  <{SCS}>
PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
"""


def _local(term) -> str:
    """Strip a full IRI down to its readable tail, for display only."""
    return str(term).rsplit("#", 1)[-1]


#  1. INVENTORY

Q_HOSTS = (
    PREFIXES
    + """
SELECT ?host ?label ?ip ?zone ?criticality ?vulnerable
WHERE {
    ?host a scs:Host .
    OPTIONAL { ?host rdfs:label      ?label }
    OPTIONAL { ?host scs:ipAddress   ?ip }
    OPTIONAL { ?host scs:locatedIn   ?zone }
    OPTIONAL { ?host scs:criticality ?criticality }
    BIND( EXISTS { ?host a scs:VulnerableHost } AS ?vulnerable )
}
ORDER BY DESC(?criticality)
"""
)
# OPTIONAL is SPARQL's LEFT JOIN: match if present, leave the variable unbound
# otherwise, but keep the row. Without it, a host missing any one field would
# vanish from the results entirely - RDF has no NULL, so absence is the norm and
# OPTIONAL is not optional in practice.
# BIND(EXISTS{...} AS ?v) computes a boolean per row without a join.


def list_hosts(graph: Graph) -> list[dict]:
    return [
        {
            "id": _local(r.host),
            "iri": str(r.host),
            "label": str(r.label) if r.label else None,
            "ip_address": str(r.ip) if r.ip else None,
            "zone": _local(r.zone) if r.zone else None,
            "criticality": int(r.criticality) if r.criticality is not None else None,
            "vulnerable": bool(r.vulnerable),
        }
        for r in graph.query(Q_HOSTS)
    ]
    # Result rows support attribute access by variable name (r.host). rdflib
    # returns RDF terms, not Python natives - int(Literal("5")) does the
    # conversion via the literal's declared datatype.


#  2. RISK POSTURE

Q_ENTRY_POINTS = (
    PREFIXES
    + """
SELECT ?host ?ip ?zone ?cve ?score
WHERE {
    ?host a scs:EntryPoint ;
          scs:locatedIn ?zone ;
          scs:hasVulnerability ?vuln .
    ?vuln a scs:RemotelyExploitable ;
          scs:cveId ?cve ;
          scs:cvssScore ?score .
    OPTIONAL { ?host scs:ipAddress ?ip }
}
ORDER BY DESC(?score)
"""
)


def list_entry_points(graph: Graph) -> list[dict]:
    return [
        {
            "host": _local(r.host),
            "ip_address": str(r.ip) if r.ip else None,
            "zone": _local(r.zone),
            "cve": str(r.cve),
            "cvss": float(r.score),
        }
        for r in graph.query(Q_ENTRY_POINTS)
    ]


Q_HOST_VULNERABILITIES = (
    PREFIXES
    + """
SELECT ?cve ?score ?vector
WHERE {
    ?host scs:hasVulnerability ?vuln .
    ?vuln scs:cveId ?cve ;
          scs:cvssScore ?score ;
          scs:hasAttackVector ?vector .
}
ORDER BY DESC(?score)
"""
)
# ?host is left FREE. The caller binds it via init_bindings - see below. This is
# the parameterised-query pattern: one compiled query, many different subjects,
# and no string building anywhere near user input.


def host_vulnerabilities(graph: Graph, host: URIRef) -> list[dict]:
    return [
        {"cve": str(r.cve), "cvss": float(r.score), "attack_vector": _local(r.vector)}
        for r in graph.query(Q_HOST_VULNERABILITIES, initBindings={"host": host})
    ]


#  3. BLAST RADIUS

Q_BLAST_RADIUS = (
    PREFIXES
    + """
SELECT DISTINCT ?affected ?criticality
WHERE {
    ?affected scs:dependsOn+ ?asset .
    OPTIONAL { ?affected scs:criticality ?criticality }
}
ORDER BY DESC(?criticality)
"""
)
# `scs:dependsOn+` is a PROPERTY PATH: "one or more dependsOn edges". This is
# the feature that has no equivalent in standard SQL, and the main reason a
# graph store is the right tool here.
# Quantifiers: + = one or more, * = zero or more, ? = zero or one,
# / = sequence, | = alternative, ^ = inverse direction.
# We use it even though dependsOn is already a transitive OWL property, so the
# query is correct against a NON-materialised graph too - useful in Stage 6 when
# the reasoner may not have run on the remote store.


def blast_radius(graph: Graph, asset: URIRef) -> list[dict]:
    return [
        {
            "asset": _local(r.affected),
            "criticality": int(r.criticality) if r.criticality is not None else None,
        }
        for r in graph.query(Q_BLAST_RADIUS, initBindings={"asset": asset})
    ]


#  4. ATTACK PATHS
#  Where SPARQL stops and Python takes over.

Q_ATTACK_EDGES = (
    PREFIXES
    + """
SELECT ?source ?target
WHERE { ?source scs:attackStepTo ?target }
"""
)

Q_ENTRY_HOSTS = (
    PREFIXES
    + """
SELECT DISTINCT ?host WHERE { ?host a scs:EntryPoint }
"""
)

# WHY NOT JUST A PROPERTY PATH?
# `?entry scs:attackStepTo+ ?target` correctly answers "is ?target reachable?"
# - and that is ALL it answers. SPARQL 1.1 property paths are defined to test
# for the EXISTENCE of a path; they do not return the path itself, and the spec
# explicitly leaves the route unspecified so engines can optimise freely.
# For a security report, "backup01 is reachable" is nearly useless. The analyst
# needs "via app01 then db01, using these three CVEs". So we pull the one-hop
# edges out of the graph and walk them ourselves. This is a real limitation of
# the standard, not an rdflib quirk, and knowing where a standard ends is worth
# more than pretending it doesn't.


def find_attack_paths(graph: Graph, max_depth: int = 6) -> list[dict]:
    """Breadth-first enumeration of attack paths starting at every entry point.

    BFS rather than DFS so that the SHORTEST route to each target is found
    first - the shortest path is the one a defender should break.
    """
    # adjacency list: source -> list of targets
    adjacency: dict[URIRef, list[URIRef]] = {}
    for row in graph.query(Q_ATTACK_EDGES):
        adjacency.setdefault(row.source, []).append(row.target)
    # setdefault(k, []) returns the existing list or inserts a new one. One
    # dictionary lookup instead of the `if k not in d` two-step.

    entry_points = [row.host for row in graph.query(Q_ENTRY_HOSTS)]
    paths: list[dict] = []

    for entry in entry_points:
        # Queue holds whole paths, not just nodes, so the route is reconstructed
        # for free. Memory cost is fine at this scale; for a large estate you
        # would store predecessors instead.
        queue: deque[list[URIRef]] = deque([[entry]])
        seen: set[URIRef] = {entry}

        while queue:
            path = queue.popleft()
            current = path[-1]

            if len(path) > max_depth:
                continue
            # Bounds the search. Real networks contain cycles, and an attacker
            # with unlimited hops is not an actionable finding anyway.

            for neighbour in adjacency.get(current, []):
                if neighbour in path:
                    continue  # never revisit a host within one path
                new_path = path + [neighbour]
                paths.append(
                    {
                        "entry_point": _local(entry),
                        "target": _local(neighbour),
                        "hops": len(new_path) - 1,
                        "path": [_local(node) for node in new_path],
                    }
                )
                if neighbour not in seen:
                    seen.add(neighbour)
                    queue.append(new_path)
        # `seen` prevents re-expanding a host we have already explored from this
        # entry point. Note it guards EXPANSION, not reporting: a host reachable
        # by two different routes is reported twice, once per route, which is
        # what an analyst wants.

    paths.sort(key=lambda p: (p["hops"], p["target"]))
    return paths


def rank_attack_paths(graph: Graph, paths: list[dict]) -> list[dict]:
    """Attach a crude risk score to each path.

    HONESTY: this is a heuristic of my own invention, not a standard. CVSS
    deliberately scores a vulnerability in isolation and has no notion of chained
    exploitation; the research field that does (attack-graph analysis) uses
    probabilistic models well beyond this project's scope. The formula below is
    a defensible ordering, not a measurement, and the README should say so.

        score = max CVSS along the path  x  target criticality / 5
    """
    criticality: dict[str, int] = {}
    for row in graph.query(
        PREFIXES
        + """
        SELECT ?host ?c WHERE { ?host a scs:Host ; scs:criticality ?c }
    """
    ):
        criticality[_local(row.host)] = int(row.c)

    worst_cvss: dict[str, float] = {}
    for row in graph.query(
        PREFIXES
        + """
        SELECT ?host (MAX(?s) AS ?worst) WHERE {
            ?host scs:hasVulnerability ?v . ?v scs:cvssScore ?s .
        } GROUP BY ?host
    """
    ):
        worst_cvss[_local(row.host)] = float(row.worst)
    # SPARQL supports GROUP BY and aggregates (MAX, MIN, SUM, COUNT, AVG),
    # same idea as SQL. The (expr AS ?name) form is required for aggregates.

    for path in paths:
        peak = max((worst_cvss.get(h, 0.0) for h in path["path"]), default=0.0)
        crit = criticality.get(path["target"], 1)
        path["max_cvss"] = peak
        path["target_criticality"] = crit
        path["risk_score"] = round(peak * crit / 5, 2)

    paths.sort(key=lambda p: p["risk_score"], reverse=True)
    return paths


#  5. INTEGRITY CHECK


Q_INTEGRITY = (
    PREFIXES
    + """
SELECT ?thing WHERE { ?thing a <http://www.w3.org/2002/07/owl#Nothing> }
"""
)


def integrity_violations(graph: Graph) -> list[str]:
    """Individuals the reasoner placed in owl:Nothing - i.e. contradictions.

    owl:Nothing is the empty class. Nothing can belong to it, so if the reasoner
    derives that something does, the data contradicts the ontology - typically a
    violation of an owl:disjointWith axiom, such as an individual asserted to be
    both a Host and a Vulnerability.
    On clean data this returns []. It is the "semantic integrity check" the
    project description promises, and it costs one query.
    """
    return [_local(row.thing) for row in graph.query(Q_INTEGRITY)]


Q_VULNERABILITIES = (
    PREFIXES
    + """
SELECT ?vuln ?cve ?score ?vector ?remote (COUNT(DISTINCT ?host) AS ?affected_hosts)
WHERE {
    ?vuln a scs:Vulnerability ;
          scs:cveId ?cve ;
          scs:cvssScore ?score ;
          scs:hasAttackVector ?vector .
    BIND( EXISTS { ?vuln a scs:RemotelyExploitable } AS ?remote )
    OPTIONAL { ?host scs:hasVulnerability ?vuln }
}
GROUP BY ?vuln ?cve ?score ?vector ?remote
ORDER BY DESC(?score)
"""
)
# GROUP BY + COUNT: same semantics as SQL. Every non-aggregated variable in the
# SELECT must appear in the GROUP BY, or SPARQL rejects the query.
# COUNT(DISTINCT ?host) counts distinct hosts, so a host affected through two
# different services is not double-counted.


def list_vulnerabilities(graph: Graph) -> list[dict]:
    return [
        {
            "cve": str(r.cve),
            "cvss": float(r.score),
            "attack_vector": _local(r.vector),
            "remotely_exploitable": bool(r.remote),
            "affected_hosts": int(r.affected_hosts),
        }
        for r in graph.query(Q_VULNERABILITIES)
    ]


Q_HOST_EXISTS = PREFIXES + "ASK { ?host a scs:Host }"
# ASK returns a single boolean instead of a table - the cheapest possible
# existence check. Used to turn "unknown host" into a clean 404 instead of an
# empty result the caller has to interpret.


def host_exists(graph: Graph, host: URIRef) -> bool:
    return bool(graph.query(Q_HOST_EXISTS, initBindings={"host": host}).askAnswer)


Q_HOST_ZONES = (
    PREFIXES
    + """
SELECT ?host ?zone WHERE { ?host a scs:Host ; scs:locatedIn ?zone }
"""
)


def host_zone_map(graph: Graph) -> dict[str, str]:
    """{'web01': 'zone_dmz', ...} - needed to evaluate the adjacent-vector rule."""
    return {_local(r.host): _local(r.zone) for r in graph.query(Q_HOST_ZONES)}


Q_ZONES = (
    PREFIXES
    + """
SELECT ?zone ?facing WHERE {
    ?zone a scs:NetworkZone .
    OPTIONAL { ?zone scs:internetFacing ?facing }
}
"""
)


def zone_map(graph: Graph) -> dict[str, bool]:
    return {_local(r.zone): bool(r.facing) for r in graph.query(Q_ZONES)}


Q_NETWORK_EDGES = (
    PREFIXES
    + """
SELECT ?source ?target WHERE { ?source scs:connectsTo ?target }
"""
)


def network_edges(graph: Graph) -> list[tuple[str, str]]:
    return [(_local(r.source), _local(r.target)) for r in graph.query(Q_NETWORK_EDGES)]


def attack_edges(graph: Graph) -> list[tuple[str, str]]:
    return [(_local(r.source), _local(r.target)) for r in graph.query(Q_ATTACK_EDGES)]


Q_TARGET_VULNS = (
    PREFIXES
    + """
SELECT ?cve ?score ?vector ?remote WHERE {
    ?target scs:hasVulnerability ?vuln .
    ?vuln scs:cveId ?cve ; scs:cvssScore ?score ; scs:hasAttackVector ?vector .
    BIND( EXISTS { ?vuln a scs:RemotelyExploitable } AS ?remote )
}
ORDER BY DESC(?score)
"""
)


def attack_step_evidence(
    graph: Graph, source: str, target: str, zones: dict[str, str], threshold: float
) -> list[dict]:
    """Which CVEs justify this specific hop, and under which rule."""
    same_zone = zones.get(source) is not None and zones.get(source) == zones.get(target)
    evidence = []
    for r in graph.query(Q_TARGET_VULNS, initBindings={"target": CORP[target]}):
        vector, score = _local(r.vector), float(r.score)
        if bool(r.remote):
            rule = "Remotely exploitable — reachable from any connected host"
            usable = True
        elif vector == "AV_Adjacent" and same_zone and score >= threshold:
            rule = f"Adjacent vector — both hosts sit in {zones[source]}"
            usable = True
        else:
            rule = "Present but not usable from this position"
            usable = False
        evidence.append(
            {
                "cve": str(r.cve),
                "cvss": score,
                "attack_vector": vector,
                "justification": rule,
                "usable": usable,
            }
        )
    return evidence
