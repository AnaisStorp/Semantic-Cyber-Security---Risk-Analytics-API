"""Tests for the data importing and filtering layer."""

from __future__ import annotations

import io

import pandas as pd
import pytest

from app.ingest import filters as f
from app.ingest.loader import read_scan_csv, validate_columns
from app.ingest.pipeline import clean_scan_dataframe, ingest_scan_csv
from app.ingest.schema import EmptyScanError, MissingColumnsError
from app.ingest.to_rdf import dataframe_to_graph, short_hostname, slugify

GOOD_CSV = """Hostname,IP Address,Zone,Criticality,Service,Port,Product,Version,CVE ID,CVSS Score,Attack Vector
web01.corp.example,203.0.113.10,zone_dmz,3,nginx,443,nginx,1.18.0,CVE-2021-23017,7.7,AV:N
app01.corp.example,10.20.0.15,zone_internal,4,ssh,22,OpenSSH,8.2p1,CVE-2020-15778,7.4,Adjacent
"""


@pytest.fixture
def raw() -> pd.DataFrame:
    """A small raw frame with deliberately messy headers and values."""
    return pd.DataFrame(
        {
            " Hostname ": ["web01.corp.example", "  db01.corp.example  "],
            "IP Address": ["203.0.113.10", "10.30.0.5"],
            "Zone": ["zone_dmz", "zone_data"],
            "Criticality": ["3", "9"],
            "Service": ["nginx", "postgres"],
            "Port": ["443", "5432"],
            "Product": ["nginx", "PostgreSQL"],
            "Version": ["1.18.0", "13.3"],
            "CVE ID": ["CVE-2021-23017", "CVE-2022-1552"],
            "CVSS Score": ["7.7", "8.8"],
            "Attack Vector": ["AV:N", "NETWORK"],
        }
    )


def test_read_scan_csv_parses_a_valid_export():
    df = read_scan_csv(io.StringIO(GOOD_CSV))
    assert len(df) == 2
    assert "CVE ID" in df.columns


def test_read_scan_csv_reads_everything_as_text():
    """Guards the dtype=str decision against a well-meaning future edit."""
    df = read_scan_csv(io.StringIO(GOOD_CSV))
    assert isinstance(df["CVSS Score"].iloc[0], str)
    assert df["CVSS Score"].iloc[0] == "7.7"
    assert df["Version"].iloc[0] == "1.18.0"


def test_read_scan_csv_rejects_an_empty_file():
    with pytest.raises(EmptyScanError):
        read_scan_csv(io.StringIO(""))


def test_read_scan_csv_rejects_a_header_with_no_rows():
    with pytest.raises(EmptyScanError):
        read_scan_csv(io.StringIO("Hostname,Product\n"))


def test_validate_columns_reports_every_missing_column():
    df = pd.DataFrame({"hostname": ["web01"], "product": ["nginx"]})
    with pytest.raises(MissingColumnsError) as exc:
        validate_columns(df)
    message = str(exc.value)
    assert "ip_address" in message and "zone" in message


def test_validate_columns_passes_a_complete_frame_through(raw):
    cleaned = f.normalise_column_names(raw)
    assert validate_columns(cleaned) is cleaned


def test_ingest_from_a_real_file(tmp_path):
    """End to end from disk, using pytest's temporary directory fixture."""
    path = tmp_path / "scan.csv"
    path.write_text(GOOD_CSV)
    df = ingest_scan_csv(path)
    assert len(df) == 2


def test_normalise_column_names(raw):
    out = f.normalise_column_names(raw)
    assert set(out.columns) >= {"hostname", "ip_address", "cve_id", "cvss_score"}


def test_normalise_column_names_does_not_mutate_the_input(raw):
    """The no-mutation rule, asserted rather than assumed."""
    before = list(raw.columns)
    f.normalise_column_names(raw)
    assert list(raw.columns) == before


def test_strip_string_columns_removes_padding(raw):
    out = f.strip_string_columns(f.normalise_column_names(raw))
    assert out["hostname"].iloc[1] == "db01.corp.example"


def test_coerce_types_produces_numbers(raw):
    out = f.coerce_types(f.normalise_column_names(raw))
    assert out["cvss_score"].iloc[0] == 7.7
    assert out["port"].dtype == "Int64"


def test_coerce_types_turns_garbage_into_nan(raw):
    df = f.normalise_column_names(raw)
    df.loc[0, "cvss_score"] = "not a number"
    out = f.coerce_types(df)
    assert pd.isna(out["cvss_score"].iloc[0])


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        ("AV:N", "AV_Network"),
        ("NETWORK", "AV_Network"),
        ("n", "AV_Network"),
        (" Remote ", "AV_Network"),
        ("AV:A", "AV_Adjacent"),
        ("Adjacent", "AV_Adjacent"),
        ("local", "AV_Local"),
        ("P", "AV_Physical"),
    ],
)
def test_attack_vector_normalisation(raw_value, expected):
    """One test, eight cases. This is what @parametrize is for."""
    df = pd.DataFrame({"attack_vector": [raw_value]})
    assert f.normalise_attack_vector(df)["attack_vector"].iloc[0] == expected


def test_unknown_attack_vector_becomes_nan():
    df = pd.DataFrame({"attack_vector": ["via carrier pigeon"]})
    assert pd.isna(f.normalise_attack_vector(df)["attack_vector"].iloc[0])


def test_drop_unusable_rows_keeps_assets_without_findings():
    df = pd.DataFrame(
        {
            "hostname": ["web01", None, "ws07"],
            "product": ["nginx", "nginx", "Firefox"],
            "cve_id": ["CVE-1", "CVE-2", None],
        }
    )
    out = f.drop_unusable_rows(df)
    assert list(out["hostname"]) == ["web01", "ws07"]


def test_nullify_invalid_findings_keeps_the_host():
    """The central policy: a corrupt finding must not delete the asset."""
    df = pd.DataFrame(
        {
            "hostname": ["web01"],
            "cve_id": ["CVE-2021-23017"],
            "cvss_score": [99.0],  # impossible
            "attack_vector": ["AV_Network"],
        }
    )
    out = f.nullify_invalid_findings(df)
    assert out["hostname"].iloc[0] == "web01"
    assert pd.isna(out["cve_id"].iloc[0])
    assert pd.isna(out["cvss_score"].iloc[0])


@pytest.mark.parametrize("score", [0.0, 10.0])
def test_boundary_cvss_scores_are_valid(score):
    """0.0 and 10.0 are legal. Off-by-one at the boundary is the classic bug."""
    df = pd.DataFrame(
        {
            "hostname": ["h"],
            "cve_id": ["CVE-X"],
            "cvss_score": [score],
            "attack_vector": ["AV_Network"],
        }
    )
    assert f.nullify_invalid_findings(df)["cve_id"].iloc[0] == "CVE-X"


@pytest.mark.parametrize("score", [-0.1, 10.1])
def test_out_of_range_cvss_scores_are_rejected(score):
    df = pd.DataFrame(
        {
            "hostname": ["h"],
            "cve_id": ["CVE-X"],
            "cvss_score": [score],
            "attack_vector": ["AV_Network"],
        }
    )
    assert pd.isna(f.nullify_invalid_findings(df)["cve_id"].iloc[0])


def test_clip_criticality_bounds_rather_than_drops(raw):
    out = f.clip_criticality(f.coerce_types(f.normalise_column_names(raw)))
    assert out["criticality"].iloc[1] == 5  # 9 was clipped, row kept


def test_deduplicate_keeps_the_highest_score():
    df = pd.DataFrame(
        {
            "hostname": ["web01", "web01"],
            "product": ["nginx", "nginx"],
            "version": ["1.18.0", "1.18.0"],
            "cve_id": ["CVE-2021-23017", "CVE-2021-23017"],
            "cvss_score": [7.7, 9.1],
        }
    )
    out = f.deduplicate_findings(df)
    assert len(out) == 1
    assert out["cvss_score"].iloc[0] == 9.1


def test_filter_by_severity_is_inclusive_at_the_threshold():
    df = pd.DataFrame({"cvss_score": [6.9, 7.0, 7.1]})
    assert list(f.filter_by_severity(df, 7.0)["cvss_score"]) == [7.0, 7.1]


def test_filter_by_severity_excludes_rows_with_no_score():
    df = pd.DataFrame({"cvss_score": [9.0, None]})
    assert len(f.filter_by_severity(df, 7.0)) == 1
    # Documents that NaN >= 7.0 is False. Implicit behaviour that the pipeline
    # relies on deserves an explicit test.


def test_filter_by_attack_vector():
    df = pd.DataFrame({"attack_vector": ["AV_Network", "AV_Local", "AV_Adjacent"]})
    out = f.filter_by_attack_vector(df, {"AV_Network", "AV_Adjacent"})
    assert list(out["attack_vector"]) == ["AV_Network", "AV_Adjacent"]


def test_filter_by_zone():
    df = pd.DataFrame({"zone": ["zone_dmz", "zone_data", "zone_internal", None]})
    out = f.filter_by_zone(df, {"zone_dmz", "zone_data"})
    assert list(out["zone"]) == ["zone_dmz", "zone_data"]


def test_filter_findings_only_drops_assets_without_a_cve():
    df = ingest_scan_csv("data/samples/scan_2026_09_15.csv")
    out = f.filter_findings_only(df)
    assert len(out) == 5
    assert out["cve_id"].notna().all()
    assert "ws-analyst-07" not in set(out["hostname"].str.split(".").str[0])


def test_pipeline_on_the_committed_sample_file():
    df = ingest_scan_csv("data/samples/scan_2026_09_15.csv")
    assert len(df) == 6  # 7 rows, one duplicate collapsed
    assert set(df["hostname"].str.split(".").str[0]) == {
        "web01",
        "app01",
        "db01",
        "backup01",
        "ws-analyst-07",
    }
    assert (
        df["attack_vector"]
        .dropna()
        .isin({"AV_Network", "AV_Adjacent", "AV_Local", "AV_Physical"})
        .all()
    )


def test_pipeline_is_idempotent():
    """Cleaning already-clean data must change nothing"""
    once = ingest_scan_csv("data/samples/scan_2026_09_15.csv")
    twice = clean_scan_dataframe(once)
    pd.testing.assert_frame_equal(once, twice)


def test_pipeline_rejects_a_file_missing_a_required_column():
    bad = "Hostname,Product\nweb01,nginx\n"
    with pytest.raises(MissingColumnsError):
        ingest_scan_csv(io.StringIO(bad))


@pytest.mark.parametrize(
    ("value", "expected"),
    [("Apache Tomcat", "apache_tomcat"), ("8.2p1", "8_2p1"), ("  nginx ", "nginx")],
)
def test_slugify(value, expected):
    assert slugify(value) == expected


def test_short_hostname_strips_the_domain():
    assert short_hostname("web01.corp.example") == "web01"


def test_graph_conversion_emits_the_expected_triples():
    from rdflib import RDF as RDF_NS

    from app.graph.namespaces import CORP, SCS

    g = dataframe_to_graph(ingest_scan_csv(io.StringIO(GOOD_CSV)))
    assert (CORP.web01, RDF_NS.type, SCS.Host) in g
    assert (CORP.web01, SCS.runs, CORP.svc_nginx_web01) in g
    assert (CORP.sw_nginx_1_18_0, SCS.affectedBy, CORP["CVE-2021-23017"]) in g
    assert (CORP["CVE-2021-23017"], SCS.hasAttackVector, SCS.AV_Network) in g


def test_shared_software_is_a_single_node():
    """Two hosts running the same version must reference ONE software node"""
    from app.graph.namespaces import CORP, SCS

    csv = (
        GOOD_CSV
        + "backup01.corp.example,10.30.0.20,zone_data,5,ssh,22,OpenSSH,8.2p1,CVE-2020-15778,7.4,AV:A\n"
    )
    g = dataframe_to_graph(ingest_scan_csv(io.StringIO(csv)))
    users = set(g.subjects(SCS.usesSoftware, CORP.sw_openssh_8_2p1))
    assert users == {CORP.svc_ssh_app01, CORP.svc_ssh_backup01}


def test_csv_derived_graph_uses_the_same_host_iris_as_the_turtle(graph):
    """Both ingestion paths must describe the SAME individuals."""
    from app.graph.namespaces import SCS

    g = dataframe_to_graph(ingest_scan_csv("data/samples/scan_2026_09_15.csv"))
    csv_hosts = set(g.subjects(SCS.hostname, None))
    ttl_hosts = set(graph.subjects(SCS.hostname, None))
    assert csv_hosts, "expected the CSV to produce hosts"
    assert csv_hosts <= ttl_hosts
