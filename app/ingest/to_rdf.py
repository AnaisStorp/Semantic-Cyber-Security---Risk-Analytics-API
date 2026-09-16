"""Dataframe -> RDF triples, using the vocabulary from cybersec.ttl."""

from __future__ import annotations

import re
from decimal import Decimal

import pandas as pd
from rdflib import XSD, Graph, Literal
from rdflib.namespace import RDF, RDFS

from app.graph.namespaces import CORP, PREFIX_MAP, SCS

_SLUG_STRIP = re.compile(r"[^A-Za-z0-9]+")


def slugify(value: str) -> str:
    """Turn arbitrary text into a safe IRI fragment: 'Apache Tomcat' -> 'apache_tomcat'."""
    return _SLUG_STRIP.sub("_", str(value).strip()).strip("_").lower()


def short_hostname(fqdn: str) -> str:
    """'web01.corp.example' -> 'web01'."""
    return slugify(str(fqdn).split(".")[0])


def _decimal(value: float) -> Literal:
    """A CVSS score as xsd:decimal, matching the Turtle files exactly."""
    return Literal(Decimal(str(value)), datatype=XSD.decimal)


def dataframe_to_graph(df: pd.DataFrame) -> Graph:
    """Convert a cleaned scan dataframe into an rdflib Graph."""
    g = Graph()
    for prefix, ns in PREFIX_MAP.items():
        g.bind(prefix, ns)

    for row in df.itertuples(index=False):
        host = CORP[short_hostname(row.hostname)]
        g.add((host, RDF.type, SCS.Host))
        g.add((host, RDFS.label, Literal(short_hostname(row.hostname), lang="en")))
        g.add((host, SCS.hostname, Literal(str(row.hostname))))

        if pd.notna(row.ip_address):
            g.add((host, SCS.ipAddress, Literal(str(row.ip_address))))
        if pd.notna(row.zone):
            zone = CORP[slugify(row.zone)]
            g.add((host, SCS.locatedIn, zone))
            g.add((zone, RDF.type, SCS.NetworkZone))
        if pd.notna(row.criticality):
            g.add((host, SCS.criticality, Literal(int(row.criticality), datatype=XSD.integer)))

        service = CORP[f"svc_{slugify(row.service)}_{short_hostname(row.hostname)}"]
        software = CORP[f"sw_{slugify(row.product)}_{slugify(row.version)}"]

        g.add((service, RDF.type, SCS.Service))
        g.add((host, SCS.runs, service))
        g.add((service, SCS.usesSoftware, software))
        if pd.notna(row.port):
            g.add((service, SCS.port, Literal(int(row.port), datatype=XSD.integer)))

        g.add((software, RDF.type, SCS.SoftwareComponent))
        g.add((software, SCS.productName, Literal(str(row.product))))
        g.add((software, SCS.version, Literal(str(row.version))))
        if pd.isna(row.cve_id):
            continue

        vuln = CORP[str(row.cve_id)]
        g.add((software, SCS.affectedBy, vuln))
        g.add((vuln, RDF.type, SCS.Vulnerability))
        g.add((vuln, SCS.cveId, Literal(str(row.cve_id))))
        g.add((vuln, RDFS.label, Literal(str(row.cve_id), lang="en")))
        g.add((vuln, SCS.cvssScore, _decimal(row.cvss_score)))
        g.add((vuln, SCS.hasAttackVector, SCS[str(row.attack_vector)]))
    return g


def graph_from_scan_csv(source) -> Graph:
    """Convenience: path or upload straight to a graph."""
    from app.ingest.pipeline import ingest_scan_csv

    return dataframe_to_graph(ingest_scan_csv(source))
