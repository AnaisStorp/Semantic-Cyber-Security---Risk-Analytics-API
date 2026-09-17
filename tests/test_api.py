"""API tests: every endpoint called in-process through httpx, no server needed."""

from __future__ import annotations

import httpx
import pytest
import pytest_asyncio

from app.config import settings
from app.graph.store import knowledge_graph
from app.main import app

pytestmark = pytest.mark.asyncio

API = settings.api_prefix


@pytest.fixture(scope="session", autouse=True)
def loaded_graph():
    """The app loads the graph in its lifespan, which ASGITransport does not run."""
    knowledge_graph.load()
    return knowledge_graph


@pytest_asyncio.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_health_reports_graph_stats(client):
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["graph"]["derived_triples"] > 0


async def test_list_hosts(client):
    r = await client.get(f"{API}/assets/hosts")
    assert r.status_code == 200
    assert {h["id"] for h in r.json()} >= {"web01", "app01", "db01", "backup01"}


async def test_host_detail_includes_inferred_vulnerabilities(client):
    r = await client.get(f"{API}/assets/hosts/web01")
    assert r.status_code == 200
    body = r.json()
    assert body["entry_point"] is True
    assert [v["cve"] for v in body["vulnerabilities"]] == ["CVE-2021-23017"]


async def test_unknown_host_is_a_404(client):
    r = await client.get(f"{API}/assets/hosts/nope")
    assert r.status_code == 404


async def test_malformed_host_id_is_rejected_before_the_handler(client):
    r = await client.get(f"{API}/assets/hosts/bad id")
    assert r.status_code == 422


async def test_vulnerabilities_flag_the_adjacent_cve_as_not_remote(client):
    r = await client.get(f"{API}/assets/vulnerabilities")
    assert r.status_code == 200
    by_cve = {v["cve"]: v for v in r.json()}
    assert by_cve["CVE-2020-15778"]["remotely_exploitable"] is False
    assert by_cve["CVE-2020-1938"]["remotely_exploitable"] is True


async def test_entry_points(client):
    r = await client.get(f"{API}/risk/entry-points")
    assert r.status_code == 200
    assert {e["host"] for e in r.json()} == {"web01"}


async def test_attack_paths_contain_the_full_route_and_are_ranked(client):
    r = await client.get(f"{API}/risk/attack-paths")
    assert r.status_code == 200
    paths = r.json()
    assert ["web01", "app01", "db01", "backup01"] in [p["path"] for p in paths]
    scores = [p["risk_score"] for p in paths]
    assert scores == sorted(scores, reverse=True)


async def test_attack_paths_respect_max_depth_and_min_risk(client):
    shallow = (await client.get(f"{API}/risk/attack-paths", params={"max_depth": 1})).json()
    assert shallow and all(p["hops"] == 1 for p in shallow)

    risky = (await client.get(f"{API}/risk/attack-paths", params={"min_risk": 9})).json()
    assert risky and all(p["risk_score"] >= 9 for p in risky)


async def test_attack_paths_reject_an_unbounded_depth(client):
    r = await client.get(f"{API}/risk/attack-paths", params={"max_depth": 99})
    assert r.status_code == 422


async def test_blast_radius(client):
    r = await client.get(f"{API}/risk/blast-radius/db01")
    assert r.status_code == 200
    assert {a["asset"] for a in r.json()} == {"web01", "app01", "backup01"}


async def test_integrity_is_consistent(client):
    r = await client.get(f"{API}/risk/integrity")
    assert r.json() == {"consistent": True, "violations": [], "shacl_violations": []}


async def test_sparql_select_sees_inferred_facts(client):
    r = await client.post(
        f"{API}/sparql", json={"query": "SELECT ?h WHERE { ?h a scs:EntryPoint }"}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["row_count"] == 1
    assert body["rows"][0]["h"].endswith("#web01")


async def test_sparql_ask(client):
    r = await client.post(f"{API}/sparql", json={"query": "ASK { ?h a scs:Host }"})
    assert r.json()["rows"] == [{"result": True}]


@pytest.mark.parametrize(
    "query",
    ["SELEC nonsense here", "INSERT DATA { <a:b> <a:c> <a:d> }"],
)
async def test_sparql_rejects_invalid_queries_and_updates(client, query):
    r = await client.post(f"{API}/sparql", json={"query": query})
    assert r.status_code == 400


async def test_sparql_truncates_at_the_row_cap(client, monkeypatch):
    monkeypatch.setattr(settings, "sparql_max_rows", 2)
    r = await client.post(f"{API}/sparql", json={"query": "SELECT ?h WHERE { ?h a scs:Host }"})
    body = r.json()
    assert body["row_count"] == 2
    assert body["truncated"] is True


async def test_sparql_can_be_disabled(client, monkeypatch):
    monkeypatch.setattr(settings, "enable_sparql_endpoint", False)
    r = await client.post(f"{API}/sparql", json={"query": "ASK { ?h a scs:Host }"})
    assert r.status_code == 403
