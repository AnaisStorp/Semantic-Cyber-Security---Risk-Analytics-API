"""Read-only SPARQL console over the materialised graph."""

from __future__ import annotations

import pandas as pd
import streamlit as st
from rdflib.plugins.sparql import prepareQuery

from app.config import settings
from app.dashboard.data import get_graph
from app.graph.namespaces import PREFIX_MAP

st.title("SPARQL console")
st.caption(
    "Queries run against the **materialised** graph, so derived triples "
    "(`hasVulnerability`, `canReach`, `EntryPoint`, `attackStepTo`) are visible "
    "exactly as if they had been asserted. Read-only: `rdflib`'s query grammar "
    "does not contain `INSERT` or `DELETE`, so writes are impossible by "
    "construction rather than by a filter."
)

EXAMPLES = {
    "Attack steps": "SELECT ?source ?target WHERE { ?source scs:attackStepTo ?target }",
    "Entry points": "SELECT ?host WHERE { ?host a scs:EntryPoint }",
    "Derived reachability": """SELECT ?a ?b WHERE {
  ?a scs:canReach ?b .
  FILTER NOT EXISTS { ?a scs:connectsTo ?b }
}""",
    "Highest-scoring remote flaws": """SELECT ?cve ?score WHERE {
  ?v a scs:RemotelyExploitable ; scs:cveId ?cve ; scs:cvssScore ?score .
} ORDER BY DESC(?score)""",
}

choice = st.selectbox("Example", list(EXAMPLES))
query = st.text_area("Query", EXAMPLES[choice], height=180)

if st.button("Run", type="primary"):
    try:
        prepared = prepareQuery(query, initNs=PREFIX_MAP)
    except Exception as exc:
        st.error(f"Invalid SPARQL: {exc}")
        st.stop()

    result = get_graph().graph.query(prepared)
    if result.type == "ASK":
        st.metric("Result", str(bool(result.askAnswer)))
    else:
        cols = [str(v) for v in result.vars or []]
        rows = [
            {
                c: (str(r[i]).rsplit("#", 1)[-1] if r[i] is not None else None)
                for i, c in enumerate(cols)
            }
            for r in list(result)[: settings.sparql_max_rows]
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        st.caption(f"{len(rows)} rows (capped at {settings.sparql_max_rows}).")
