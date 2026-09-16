"""Asset inventory with filters."""

from __future__ import annotations

import pandas as pd
import streamlit as st
from rdflib import URIRef

from app.dashboard.data import get_graph, hosts_df
from app.graph import queries as q

st.title("Assets")

kg = get_graph()
hosts = hosts_df()


f1, f2, f3 = st.columns([2, 2, 1])
zones = sorted(hosts["zone"].dropna().unique())
chosen_zones = f1.multiselect("Zone", zones, default=zones)
min_crit = f2.slider("Minimum criticality", 1, 5, 1)
only_vuln = f3.toggle("Vulnerable only", value=False)

view = hosts[hosts["zone"].isin(chosen_zones) & (hosts["criticality"].fillna(0) >= min_crit)]
if only_vuln:
    view = view[view["vulnerable"]]

st.caption(f"{len(view)} of {len(hosts)} hosts")
st.dataframe(
    view[["id", "label", "ip_address", "zone", "criticality", "vulnerable"]],
    use_container_width=True,
    hide_index=True,
)

st.divider()

if not view.empty:
    selected = st.selectbox("Inspect a host", view["id"].tolist())
    row = view[view["id"] == selected].iloc[0]
    iri = URIRef(row["iri"])

    d1, d2, d3 = st.columns(3)
    d1.metric("Zone", row["zone"] or "—")
    d2.metric("Criticality", int(row["criticality"]) if pd.notna(row["criticality"]) else "—")
    d3.metric("IP", row["ip_address"] or "—")

    st.subheader("Inferred vulnerabilities")
    vulns = q.host_vulnerabilities(kg.graph, iri)
    if vulns:
        st.dataframe(pd.DataFrame(vulns), use_container_width=True, hide_index=True)
        st.caption(
            "Derived by the OWL property chain `runs ∘ usesSoftware ∘ affectedBy` — "
            "no triple links this host directly to any CVE."
        )
    else:
        st.success("No known vulnerabilities.")

    st.subheader("Blast radius")
    blast = q.blast_radius(kg.graph, iri)
    if blast:
        st.dataframe(pd.DataFrame(blast), use_container_width=True, hide_index=True)
        st.caption(
            "Transitive closure of `dependsOn`: everything that degrades if this asset fails."
        )
    else:
        st.info("Nothing depends on this asset.")
