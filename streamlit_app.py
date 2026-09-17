"""Overview page : the entry point Streamlit runs first."""

from __future__ import annotations

import streamlit as st

from app.dashboard import charts
from app.dashboard.data import (
    attack_paths,
    entry_points_df,
    findings_df,
    get_graph,
    vulnerabilities_df,
)

st.set_page_config(
    page_title="Semantic Cyber-Security Analytics",
    page_icon="🛡️",
    layout="wide",
)

kg = get_graph()
vulns = vulnerabilities_df()
paths = attack_paths()
entries = entry_points_df()

st.title("Semantic Cyber-Security & Risk Analytics")
st.caption("Attack-path discovery over an RDF/OWL knowledge graph. Everything below is inferred .")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Hosts", len(findings_df()["host"].unique()) if not findings_df().empty else 0)
c2.metric("Known vulnerabilities", len(vulns))
c3.metric("Entry points", entries["host"].nunique() if not entries.empty else 0)
c4.metric("Attack paths", len(paths))

st.divider()

if paths:
    worst = paths[0]
    st.subheader("Highest-risk path")
    st.markdown(
        f"### {'  ->  '.join(worst['path'])}"
        f"\n\n**{worst['hops']} hops** · peak CVSS **{worst['max_cvss']}** · "
        f"target criticality **{worst['target_criticality']}** · "
        f"risk score **{worst['risk_score']}**"
    )
    st.caption(
        "Not one of these hops was written down. Each is the composition of a "
        "firewall rule someone approved and a CVE someone triaged — separately, "
        "and both reasonably."
    )

st.divider()

left, right = st.columns([3, 2])

with left:
    st.subheader("Vulnerabilities by severity")
    st.altair_chart(charts.severity_chart(vulns), use_container_width=True)

with right:
    st.subheader("Findings per host")
    st.altair_chart(charts.findings_per_host_chart(findings_df()), use_container_width=True)

with st.expander("Table view"):
    st.dataframe(
        vulns.sort_values("cvss", ascending=False), use_container_width=True, hide_index=True
    )

st.divider()

st.subheader("What the reasoner added")
s = kg.stats
i1, i2, i3 = st.columns(3)
i1.metric("Asserted triples", s.asserted)
i2.metric("After OWL 2 RL closure", s.after_owl, delta=s.after_owl - s.asserted)
i3.metric("After SPARQL rules", s.after_rules, delta=s.after_rules - s.after_owl)

with st.expander("How this works"):
    st.markdown(
        """
**Two inference engines, because one is not enough.**

*OWL 2 RL* composes relationships: a host runs a service that uses software
affected by a CVE, therefore the host has that vulnerability (a property chain);
A connects to B, B connects to C, therefore A can reach C (transitivity).

It cannot compare values `CVSS ≥ 7.0`, `internetFacing = true`,
`vector IS AV_Network` are all outside the profile by design, because allowing
them is what makes description logics slow or non-terminating.

So *SPARQL `CONSTRUCT` rules* run on top, forward-chained to a fixpoint, adding
the value-conditional facts. A bounded breadth-first search then reconstructs the
routes, because SPARQL property paths tell you a path **exists** without telling
you what it **is**.

**On `risk_score`:** it is `peak CVSS × target criticality ÷ 5` — a heuristic
ordering aid of our own, not a standard. CVSS deliberately scores a vulnerability
in isolation and has no notion of chained exploitation.
        """
    )
