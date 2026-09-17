"""Attack paths, with the evidence for every hop."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from app.config import settings
from app.dashboard.data import attack_paths, get_graph
from app.graph import queries as q

st.title("Attack paths")
st.caption(
    "A network path says a corridor exists. An attack path additionally "
    "requires, at every single hop, a vulnerability whose attack vector permits "
    "that move from where the attacker is standing."
)

kg = get_graph()
paths = attack_paths()
zones = q.host_zone_map(kg.graph)

f1, f2 = st.columns(2)
min_risk = f1.slider("Minimum risk score", 0.0, 10.0, 0.0, step=0.5)
max_hops = f2.slider("Maximum hops", 1, 8, 6)

view = [p for p in paths if p["risk_score"] >= min_risk and p["hops"] <= max_hops]
st.caption(f"{len(view)} of {len(paths)} paths")

if not view:
    st.info("No paths match these filters.")

for path in view:
    route = "  ->  ".join(path["path"])
    header = f"{route}   , risk {path['risk_score']}   ,  {path['hops']} hops"
    with st.expander(header, expanded=(path is view[0])):
        st.markdown(
            f"Entry point {path['entry_point']} , target {path['target']} "
            f"(criticality {path['target_criticality']}) · peak CVSS {path['max_cvss']}"
        )
        for i in range(len(path["path"]) - 1):
            src, dst = path["path"][i], path["path"][i + 1]
            st.markdown(f"Hop {i + 1}: `{src}` ->`{dst}`")
            evidence = q.attack_step_evidence(kg.graph, src, dst, zones, settings.cvss_threshold)
            usable = [e for e in evidence if e["usable"]]
            unusable = [e for e in evidence if not e["usable"]]

            if usable:
                st.dataframe(
                    pd.DataFrame(usable)[["cve", "cvss", "attack_vector", "justification"]],
                    use_container_width=True,
                    hide_index=True,
                )
            if unusable:
                with st.popover(f"{len(unusable)} present but not usable here"):
                    st.dataframe(
                        pd.DataFrame(unusable)[["cve", "cvss", "attack_vector", "justification"]],
                        use_container_width=True,
                        hide_index=True,
                    )
                    st.caption(
                        "These flaws exist on the target and may score highly, but "
                        "their attack vector does not permit exploitation from the "
                        "previous hop. This is exactly the distinction a CVSS-ordered "
                        "list cannot make."
                    )
