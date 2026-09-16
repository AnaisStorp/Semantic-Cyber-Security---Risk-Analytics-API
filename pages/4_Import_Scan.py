"""Upload a scanner CSV and watch the cleaning pipeline work."""

from __future__ import annotations

import streamlit as st

from app.ingest.loader import read_scan_csv
from app.ingest.pipeline import clean_scan_dataframe
from app.ingest.schema import IngestError
from app.ingest.to_rdf import dataframe_to_graph

st.title("Import a scan")
st.caption(
    "Drop a vulnerability-scanner CSV export here to see it validated, cleaned and "
    "converted to RDF. The import is previewed in an **isolated graph** and does not "
    "modify the running one, so this page can never leave the dashboard in a state "
    "that depends on what someone uploaded."
)

uploaded = st.file_uploader("Scanner CSV export", type=["csv"])
if uploaded is None:
    st.info("No file yet. `data/samples/scan_2026_09_15.csv` in the repo is a valid example.")
    st.stop()

try:
    raw = read_scan_csv(uploaded)
    clean = clean_scan_dataframe(raw)
except IngestError as exc:
    st.error(f"**Rejected:** {exc}")
    st.stop()

c1, c2, c3 = st.columns(3)
c1.metric("Rows read", len(raw))
c2.metric("Rows kept", len(clean), delta=len(clean) - len(raw))
c3.metric("Findings", int(clean["cve_id"].notna().sum()))

tab_raw, tab_clean, tab_rdf = st.tabs(["As uploaded", "After cleaning", "As RDF"])

with tab_raw:
    st.dataframe(raw, use_container_width=True, hide_index=True)
    st.caption("Read with `dtype=str` — every value is still text at this point.")

with tab_clean:
    st.dataframe(clean, use_container_width=True, hide_index=True)
    st.caption(
        "Headers normalised, whitespace stripped, types coerced, attack vectors "
        "mapped to canonical terms, out-of-range findings blanked while keeping the "
        "asset, criticality clipped to 1–5, duplicates collapsed to the worst score."
    )

with tab_rdf:
    graph = dataframe_to_graph(clean)
    st.metric("Triples generated", len(graph))
    turtle = graph.serialize(format="turtle")
    st.code(turtle[:6000], language="turtle")
    st.download_button("Download as Turtle", turtle, file_name="scan.ttl", mime="text/turtle")
