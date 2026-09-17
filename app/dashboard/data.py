from __future__ import annotations

import pandas as pd
import streamlit as st
from rdflib import URIRef

from app.config import settings
from app.dashboard.theme import severity_band
from app.graph import queries as q
from app.graph.store import KnowledgeGraph


@st.cache_resource(show_spinner="Loading knowledge graph and running the reasoner…")
def get_graph() -> KnowledgeGraph:
    kg = KnowledgeGraph()
    kg.load()
    return kg


@st.cache_data(show_spinner=False)
def hosts_df() -> pd.DataFrame:
    return pd.DataFrame(q.list_hosts(get_graph().graph))


@st.cache_data(show_spinner=False)
def vulnerabilities_df() -> pd.DataFrame:
    df = pd.DataFrame(q.list_vulnerabilities(get_graph().graph))
    df["severity"] = df["cvss"].map(severity_band)
    return df


@st.cache_data(show_spinner=False)
def findings_df() -> pd.DataFrame:
    """One row per (host, CVE) - the long form the stacked chart needs."""
    g = get_graph().graph
    rows = []
    for host in q.list_hosts(g):
        for v in q.host_vulnerabilities(g, URIRef(host["iri"])):
            rows.append({"host": host["id"], "zone": host["zone"], **v})
    return pd.DataFrame(rows)


@st.cache_data(show_spinner=False)
def entry_points_df() -> pd.DataFrame:
    return pd.DataFrame(q.list_entry_points(get_graph().graph))


@st.cache_data(show_spinner=False)
def attack_paths() -> list[dict]:
    g = get_graph().graph
    return q.rank_attack_paths(g, q.find_attack_paths(g, max_depth=settings.max_attack_depth))
