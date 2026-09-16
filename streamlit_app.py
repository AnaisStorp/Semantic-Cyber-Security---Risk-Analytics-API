from __future__ import annotations

import pandas as pd
import streamlit as st

from app.graph import queries as q
from app.graph.store import KnowledgeGraph

st.set_page_config(
    page_title="semantic cyber-security analytics",
    layout="wide",
)


@st.cache_resource(show_spinner="Loading knowledge graph and running reasoner...")
def load_graph() -> KnowledgeGraph:
    """Build the reasoned graph once per server process.

    THE MOST IMPORTANT LINE IN THIS FILE.
    """
    kg = KnowledgeGraph()
    kg.load()
    return kg


kg = load_graph()

st.title("Semantic cyber-security and risk analytics")
st.caption(
    "Attack-path discovery over an RDF/OWL knowledge graph. "
    "Findings below are inferred, not asserted"
)

stats = kg.stats
hosts = q.list_hosts(kg.graph)
entry_points = q.list_entry_points(kg.graph)
paths = q.rank_attack_paths(kg.graph, q.find_attack_paths(kg.graph))

c1, c2, c3, c4 = st.columns(4)

c1.metric("Hosts", len(hosts))
c2.metric("Vulnerable hosts", sum(h["vulnerable"] for h in hosts))
c3.metric("Entry points", len({e["host"] for e in entry_points}))
c4.metric("Attack paths", len(paths))

st.divider()

st.subheader("Inference")
i1, i2, i3 = st.columns(3)
i1.metric("Asserted triples", stats.asserted)
i2.metric("After OWL 2 RL closure", stats.after_owl, delta=stats.after_owl - stats.asserted)
i3.metric("After SPARQL rules", stats.after_rules, delta=stats.after_rules - stats.after_owl)

st.divider()

st.subheader("Asset inventory")
st.dataframe(pd.DataFrame(hosts), use_container_width=True, hide_index=True)

st.subheader("Attack paths")
if paths:
    df = pd.DataFrame(paths)
    df["route"] = df["path"].apply(" → ".join)
    st.dataframe(
        df[["route", "hops", "risk_score", "max_cvss", "target_criticality"]],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No attack paths found.")

st.caption(
    "`risk_score` is a heuristic ordering aid (max CVSS on path × target "
    "criticality ÷ 5), not a validated metric. CVSS scores vulnerabilities in "
    "isolation and has no notion of chained exploitation."
)
