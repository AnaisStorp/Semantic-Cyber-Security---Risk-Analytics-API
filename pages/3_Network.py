"""The estate as a picture."""

from __future__ import annotations

import streamlit as st

from app.dashboard.data import entry_points_df, get_graph, hosts_df
from app.dashboard.diagram import build_network_dot
from app.dashboard.theme import GRID, STATUS_CRITICAL, STATUS_SERIOUS
from app.graph import queries as q

st.title("Network")

kg = get_graph()
hosts = hosts_df().to_dict("records")
entries = set(entry_points_df()["host"]) if not entry_points_df().empty else set()

show_attack_only = st.toggle("Show only edges an attacker can walk", value=False)

net = q.network_edges(kg.graph)
atk = q.attack_edges(kg.graph)
edges = atk if show_attack_only else net

dot = build_network_dot(hosts, q.zone_map(kg.graph), edges, atk, entries)
st.graphviz_chart(dot, use_container_width=True)


l1, l2, l3 = st.columns(3)
l1.markdown(
    f"<span style='color:{STATUS_CRITICAL}'>.</span> Entry point : internet-facing and remotely exploitable",
    unsafe_allow_html=True,
)
l2.markdown(
    f"<span style='color:{STATUS_SERIOUS}'>.</span> Vulnerable : carries a known CVE",
    unsafe_allow_html=True,
)
l3.markdown(
    f"<span style='color:{GRID}'>.</span> Clean : no known vulnerability", unsafe_allow_html=True
)
st.caption(
    "Grey arrows are asserted firewall rules. Red arrows are derived attack steps, "
    "a subset an attacker can actually traverse. The legend repeats every colour as "
    "text, and every node carries its status as a written label, so nothing here "
    "depends on distinguishing the two reds."
)

with st.expander("DOT source"):
    st.code(dot, language="dot")
