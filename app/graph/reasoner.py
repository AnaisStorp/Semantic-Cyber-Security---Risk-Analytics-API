""" Inference: OWL 2 RL closure, then value-conditional SPARQL rules

WHY 2 ENGINES
OWL 2 RL composes relationships. It cannot compare values: "CVSS >= 7.0",
"internetFacing = true", "attack vector IS AV_Network" are all outside the
profile, by design - allowing them is what makes description logics slow or
undecidable.
so the pipeline is:
 1. owlrl materialises the structural closure (subclasses, inverses, property
    chains, transitive reachability)
 2. SPAQRL CONSTRUCT rules run on top, adding the value conditional facts
 
 Step 2 is FORWARD CHAINING: each rule reads the graph and writes new triples
 back into t, so later rules can see earlier rules' outup. We iterate to a 
 fixpoint, repeat until full pass adds nothing new, rather than relying on
 hand-orienting the rules correctly
 """

from __future__ import annotations

import logging
import time 

import owlrl 
# The reasoner. It implements the OWL 2 RL/RDF rule set as forward-chaining
# rules over an rdflib Graph, MUTATING THE GRAPH IN PLACE. There is no separate
# "inferred graph" - after expand(), asserted and derived triples are
# indistinguishable unless you snapshotted beforehand. That is the defining
# property of materialisation, and the reason we record counts as we go.

from rdflib import Graph
from app.graph.namespaces import SCS

logger = logging.getLogger(__name__)

MAX_RULE_ITERATIONS = 10
# Safety valve. Our rules are monotonic (they only add triples) over a finite
# vocabulary, so a fixpoint is guaranteed. The cap turns a hypothetical bug in a
# future rule into a logged warning instead of an infinite loop in production.

_PREFIXES = f"""
PREFIX scs:  <{SCS}>
PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd:  <http://www.w3.org/2001/XMLSchema#>
"""
# f-string interpolation of OUR OWN constant is fine - it is not user input.
# The injection warning in store.query() applies to values from requests.


# THE RULES 
# each is a SPARQL CONSTRUCT: the WHERE clasue matches a pattern in the graph,
# the CONSTRUCT clasue describes tripes to build from each match. It is a
# template engine over graph patterns, "whenever you see this shape, add
# that shape"

RULE_REMOTELY_EXPLOITABLE = _PREFIXES + """
CONSTRUCT {
    ?vuln a scs:RemotelyExploitable .
}
WHERE {
    ?vuln a scs:Vulnerability ;
          scs:hasAttackVector scs:AV_Network ;
          scs:cvssScore ?score .
    FILTER (?score >= 7.0)
}
"""
# R1. Two conditions OWL cannot express: an exact individual as the vector, and
# a numeric threshold. 7.0 is the CVSS v3.1 boundary between MEDIUM and HIGH.
# It is a policy choice, not a law of nature - a real deployment would make it
# configurable, and Stage 4 puts it in settings.

RULE_EXPOSED_SERVICE = _PREFIXES + """
CONSTRUCT {
    ?service a scs:ExposedService .
}
WHERE {
    ?service scs:hostedInZone ?zone .
    ?zone    scs:internetFacing true .
}
"""
# R2. Note what this rule does NOT do: it never mentions hosts. The
# `hostedInZone` edge was derived by the OWL property chain (runsOn o locatedIn)
# in step 1. Layer 2 consumes layer 1's output - that is the whole point of the
# two-stage design.
# "true" with no quotes is the xsd:boolean literal. Quoted, it would be the
# string "true", which does not match, and the rule would silently never fire.

RULE_ENTRY_POINT = _PREFIXES + """
CONSTRUCT {
    ?host a scs:EntryPoint .
}
WHERE {
    ?host scs:locatedIn ?zone ;
          scs:hasVulnerability ?vuln .
    ?zone scs:internetFacing true .
    ?vuln a scs:RemotelyExploitable .
}
"""
# R3. Depends on R1 having already run. With the fixpoint loop we do not have to
# care about ordering - if R3 runs first it simply matches nothing, and the next
# iteration picks it up.
# `hasVulnerability` itself came from the OWL property chain. So this single
# rule sits on top of three layers of inference and zero hand-written joins.

RULE_ATTACK_STEP_REMOTE = _PREFIXES + """
CONSTRUCT {
    ?source scs:attackStepTo ?target .
}
WHERE {
    ?source scs:connectsTo ?target .
    ?target scs:hasVulnerability ?vuln .
    ?vuln   a scs:RemotelyExploitable .
}
"""
# R4a. Deliberately uses connectsTo (the ASSERTED one-hop edge), not canReach
# (the derived transitive one). An attack step is a single move. Using canReach
# here would let the attacker teleport across the network in one step and every
# path would be trivially length 1.

RULE_ATTACK_STEP_ADJACENT = _PREFIXES + """
CONSTRUCT {
    ?source scs:attackStepTo ?target .
}
WHERE {
    ?source scs:connectsTo ?target ;
            scs:locatedIn  ?zone .
    ?target scs:locatedIn  ?zone ;
            scs:hasVulnerability ?vuln .
    ?vuln   scs:hasAttackVector scs:AV_Adjacent ;
            scs:cvssScore ?score .
    FILTER (?score >= 7.0)
}
"""
# R4b. The nuance that makes the model honest. AV:Adjacent means "exploitable
# only from the same network segment". So it can NEVER be the first move from
# the internet - but once an attacker is already inside that segment, it is
# perfectly usable.
# `?zone` appearing in both host patterns forces them into the SAME zone: in
# SPARQL, repeating a variable is a join. This is exactly how CVE-2020-15778 on
# backup01 becomes usable from db01 (both in zone_data) and from nowhere else.

ALL_RULES: tuple[tuple[str, str], ...] = (
    ("RemotelyExploitable", RULE_REMOTELY_EXPLOITABLE),
    ("ExposedService",  RULE_EXPOSED_SERVICE),
    ("EntryPoint",  RULE_ENTRY_POINT),
    ("AttackStep/remote", RULE_ATTACK_STEP_REMOTE),
    ("AttackStep/adjacent", RULE_ATTACK_STEP_ADJACENT),
)

# EXECUTION 

def run_owl_closure(graph: Graph) -> int:
    """Materialise the OWL 2 RL deductive closure. Returns triples added."""
    before = len(graph)
    started = time.perf_counter()

    owlrl.DeductiveClosure(owlrl.OWLRL_Semantics).expand(graph)
    # DeductiveClosure(semantics) picks the rule set; .expand(graph) applies it
    # to a fixpoint, in place.
    # OWLRL_Semantics = OWL 2 RL. Alternatives: RDFS_Semantics (weaker, faster),
    # or RDFS_OWLRL_Semantics (both). OWL 2 RL already subsumes what we need.
    # Caveat worth knowing: the closure includes a large amount of trivially
    # true bookkeeping (everything is owl:sameAs itself, rdf:type owl:Thing,
    # every class rdfs:subClassOf itself...). On our data roughly 90% of the new
    # triples are of that kind. It is correct, just not interesting.

    added = len(graph) - before
    logger.info("OWL RL closure: +%d triples in %.2fs", added, time.perf_counter() - started)
    return added

def run_sparql_rules(graph: Graph) -> int:
    """Forward-chain the CONSTRUCT rules until a full pass adds nothing."""
    total_added = 0

    for iteration in range(1, MAX_RULE_ITERATIONS + 1):
        added_this_pass = 0

        for name, rule in ALL_RULES:
            constructed = graph.query(rule)
            # A CONSTRUCT query returns a Result you can iterate as triples.
            # Crucially it does NOT modify the graph - it builds new triples and
            # hands them to you. Writing them back is our decision.

            new = 0
            for triple in constructed:
                if triple not in graph:
                    graph.add(triple)
                    new += 1
            # The `if` is what makes the fixpoint detectable. graph.add() on an
            # existing triple is a silent no-op (a graph is a SET), so without
            # this check we could never tell a productive pass from an idle one.

            if new:
                logger.debug("  rule %-22s +%d", name, new)
            added_this_pass += new

        total_added += added_this_pass
        if added_this_pass == 0:
            logger.info("SPARQL rules reached fixpoint after %d pass(es): +%d triples",
                        iteration, total_added)
            return total_added

    logger.warning("SPARQL rules did not converge within %d iterations", MAX_RULE_ITERATIONS)
    return total_added


def apply_all_inference(graph: Graph, stats):
    """Run both engines in order and fill in the statistics object."""
    run_owl_closure(graph)
    stats.after_owl = len(graph)

    run_sparql_rules(graph)
    stats.after_rules = len(graph)
    return stats


def domain_triples_only(graph: Graph, baseline: set) -> list:
    """Derived triples that are actually about OUR domain.

    Filters the closure down to triples whose predicate lives in the scs:
    namespace, or which type something into an scs: class. This is what turns
    "611 new triples" into the ~50 a human would call findings. Used by the
    /reasoning/derived endpoint in Stage 4, and for debugging.
    """
    from rdflib import RDF

    scs_prefix = str(SCS)
    return [
        (s, p, o)
        for s, p, o in set(graph) - baseline
        if str(p).startswith(scs_prefix)
        or (p == RDF.type and str(o).startswith(scs_prefix))
    ]