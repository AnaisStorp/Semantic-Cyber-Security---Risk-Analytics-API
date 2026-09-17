# Semantic Cyber-Security & Risk Analytics

[![CI](https://github.com/AnaisStorp/Semantic-Cyber-Security---Risk-Analytics-API/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/AnaisStorp/Semantic-Cyber-Security---Risk-Analytics-API/actions/workflows/ci.yml)
![Python 3.12](https://img.shields.io/badge/python-3.12-blue)
[![uv](https://img.shields.io/badge/deps-uv-de5fe9)](https://docs.astral.sh/uv/)
![Docker](https://img.shields.io/badge/docker-ready-2496ed)

A vulnerability scanner tells you which machines have bad locks.
This tells you which bad lock an attacker on the internet can actually reach, and what is behind it.


## The problem

Take a small company with three servers.

A scanner runs overnight and produces this:

| Host | Software | CVE | CVSS |
|---|---|---|---|
| web01 | nginx 1.18.0 | CVE-2021-23017 | 7.7 |
| app01 | Apache Tomcat 9.0.30 | CVE-2020-1938 | 9.8 |
| db01 | PostgreSQL 13.3 | CVE-2022-1552 | 8.8 |

Sorted by severity, you patch `app01` first. That looks sensible and it is the wrong answer.

`db01` sits in the data tier where nobody outside can touch it. `web01` is the only machine exposed to the internet. And the firewall, entirely reasonably, lets web01 talk to app01, app01 talk to db01, and db01 push backups to backup01.

Three separate people approved those three rules on three different days. Nobody approved the thing they add up to:

```
internet → web01 → app01 → db01 → backup01
```

**The risk is not in any single finding. It is in the composition, and composition is exactly what a table cannot show you.**

So I modelled the estate as a graph, wrote down the rules of the domain in OWL, and let a reasoner derive the paths.



## What it does

- Ingests a **vulnerability scanner CSV export** with pandas, validates it, cleans it, converts it to RDF
- Fuses it with **network topology** (zones, firewall rules, service dependencies) held as configuration
- Runs an **OWL 2 RL reasoner** to derive structural facts nobody wrote down
- Applies **SPARQL rules** for the value-conditional logic OWL cannot express
- Reconstructs **attack paths** where every single hop is justified by a named CVE whose attack vector permits that specific move
- Serves the result as a **Streamlit dashboard** and an **async FastAPI** REST API
- Ships as a single **Docker image**

On the five-host sample estate: **304 hand-written facts in, 644 derived facts out**, including a three-hop path from the DMZ to the backup server that appears in no source file.


## How it works

### Everything is a triple

RDF says every fact is exactly three parts —> *subject, predicate, object*:

```turtle
corp:web01          scs:runs         corp:svc_nginx_web01 .
corp:svc_nginx_web01 scs:usesSoftware corp:sw_nginx_1_18_0 .
corp:sw_nginx_1_18_0 scs:affectedBy   corp:CVE-2021-23017 .
```

A pile of triples *is* a graph: subjects and objects are nodes, predicates are labelled edges.

### Two inference engines, because one is not enough

I never state that `web01` is vulnerable. It follows.

**Layer 1 — OWL 2 RL** composes relationships. A property chain turns the three triples above into one:

```turtle
scs:hasVulnerability owl:propertyChainAxiom ( scs:runs scs:usesSoftware scs:affectedBy ) .
```

-> `web01 hasVulnerability CVE-2021-23017`

And transitivity turns four firewall rules into nine routes:

```turtle
scs:connectsTo rdfs:subPropertyOf scs:canReach .
scs:canReach a owl:TransitiveProperty .
```

-> `web01 canReach backup01`, three hops, never written down.

**Layer 2 — SPARQL rules.** OWL 2 RL deliberately cannot compare values: `CVSS >= 7.0`, `internetFacing = true`, `vector IS AV_Network` are all outside the profile, because allowing them is what makes description logics slow or non-terminating.

So five `CONSTRUCT` rules run on top, forward-chained to a fixpoint:

| Rule | Derives |
|---|---|
| `RemotelyExploitable` | CVSS ≥ threshold **and** `AV:Network` |
| `ExposedService` | service whose host's zone is internet-facing |
| `EntryPoint` | internet-facing host carrying a remotely exploitable flaw |
| `attackStepTo` (remote) | one-hop edge whose target has a remotely exploitable flaw |
| `attackStepTo` (adjacent) | one-hop edge within the same zone whose target has an `AV:Adjacent` flaw |

That last rule is the one I care about most. **CVE-2020-15778 on backup01 scores 7.4, above the threshold, but its attack vector is `Adjacent`.** It can never be an attacker's first move from the internet. It becomes usable only once the attacker is already inside `zone_data`. A CVSS-ordered list cannot express that distinction. The graph can.

**Layer 3 — bounded breadth-first search.** SPARQL 1.1 property paths tell you a path *exists*; the specification deliberately leaves the route unspecified so engines can optimise. For a security report "backup01 is reachable" is close to useless — you need *"via app01 and db01, using these three CVEs"*. So the one-hop `attackStepTo` edges come out of the graph and a BFS reconstructs the routes.

### The pipeline

```
 scanner CSV ──┐
   (pandas)    │
               ├──► rdflib Graph ──► OWL 2 RL ──► SPARQL rules ──► BFS ──┬──► Streamlit
 topology TTL ─┘      317 triples      +635          +9                  └──► FastAPI
  (zones, firewall,
   dependencies)
```

Two sources on purpose: a scanner knows software and CVEs and changes nightly; it has no idea which zone faces the internet. That comes from network configuration and changes rarely.



## Running it

### Docker (nothing to install but Docker)

```bash
docker compose up --build
```

- Dashboard — http://localhost:8501
- API docs — http://localhost:8000/docs

Or pull the published multi-architecture image:

```bash
docker run --rm -p 8501:8501 <anaisstorp>/scsra:latest
```

### Make

```bash
make help     # list every target
make install  # .venv from uv.lock + git hooks
make check    # lint and test, like CI
make run      # the dashboard
make api      # the REST API
make up       # dashboard + API in containers
```

### Locally

Requires [uv](https://docs.astral.sh/uv/getting-started/installation/). It installs Python 3.12 itself if needed.

```bash
git clone https://github.com/AnaisStorp/Semantic-Cyber-Security---Risk-Analytics-API.git
cd Semantic-Cyber-Security---Risk-Analytics-API

uv sync --locked                       # exact versions from uv.lock
uv run streamlit run streamlit_app.py
```

The REST API is a second entry point onto the same graph layer:

```bash
uv run uvicorn app.main:app --reload
```

-> **http://localhost:8000/docs** for interactive OpenAPI documentation.

### Configuration

Copy `.env.example` to `.env`. Everything is optional; the defaults in `app/config.py` apply otherwise.

| Variable | Default | What it does |
|---|---|---|
| `SCSRA_CVSS_THRESHOLD` | `7.0` | Minimum score to treat a flaw as exploitable (the CVSS HIGH boundary) |
| `SCSRA_MAX_ATTACK_DEPTH` | `6` | Hops explored when enumerating paths |
| `SCSRA_ENABLE_SPARQL_ENDPOINT` | `true` | Turn the raw SPARQL endpoint off in any non-demo deployment |
| `SCSRA_SPARQL_MAX_ROWS` | `1000` | Result cap |


## The dashboard

| Page | What it shows |
|---|---|
| **Overview** | Estate KPIs, the highest-risk path, severity chart, and what the reasoner added at each stage |
| **Assets** | Filterable inventory; per host its inferred vulnerabilities and blast radius |
| **Attack Paths** | Every path with **per-hop evidence**, which CVE justifies each move, and which flaws are present but *not usable from that position* |
| **Network** | The estate as a diagram. Grey arrows are asserted firewall rules; red arrows are the subset an attacker can walk |
| **Import a scan** | Upload a scanner CSV and watch validation -> cleaning -> RDF conversion, step by step |
| **SPARQL** | Read-only console over the materialised graph, so derived triples are queryable as if asserted |

The Attack Paths page is the one worth looking at. Everything else is inventory; that page is an argument with citations.


## The API

| Endpoint | Returns |
|---|---|
| `GET /health` | Liveness plus triple counts per inference stage |
| `GET /api/v1/assets/hosts` | Inventory with inferred vulnerability status |
| `GET /api/v1/assets/hosts/{id}` | One host in detail |
| `GET /api/v1/assets/vulnerabilities` | Every CVE and how many hosts it affects |
| `GET /api/v1/risk/entry-points` | Hosts an external attacker can reach first |
| `GET /api/v1/risk/attack-paths` | Ranked paths, filterable by risk and depth |
| `GET /api/v1/risk/blast-radius/{id}` | Everything that degrades if this asset falls |
| `GET /api/v1/risk/integrity` | Semantic consistency check |
| `POST /api/v1/sparql` | Read-only SPARQL |

**On "async":** the HTTP layer is genuinely async. But `rdflib` is synchronous and CPU-bound, so every call into the graph is offloaded with `run_in_threadpool`. That does not make queries faster — the GIL prevents real parallelism for CPU-bound Python. It keeps the event loop free, so one slow query degrades one request instead of the whole service. Wrapping a blocking call in `async def` and calling it asynchronous would be worse than not using async at all.


## The data

Everything in this repository is **fictional**. Hostnames use the `.example` TLD reserved by [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606); public addresses come from the `203.0.113.0/24` documentation block reserved by [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737). None of it can route to a real system.

The **vulnerabilities are real**, with CVSS v3.1 base scores taken from NVD:

| CVE | Score | Vector | Affects |
|---|---|---|---|
| [CVE-2021-23017](https://nvd.nist.gov/vuln/detail/CVE-2021-23017) | 7.7 | Network | nginx 0.6.18–1.20.0 |
| [CVE-2020-1938](https://nvd.nist.gov/vuln/detail/CVE-2020-1938) (Ghostcat) | 9.8 | Network | Tomcat 9.0.0.M1–9.0.30 |
| [CVE-2020-15778](https://nvd.nist.gov/vuln/detail/CVE-2020-15778) | 7.4 | **Adjacent** | OpenSSH ≤ 8.3p1 |
| [CVE-2022-1552](https://nvd.nist.gov/vuln/detail/CVE-2022-1552) | 8.8 | Network | PostgreSQL 13.0–13.6 |

### Scan export format

```csv
Hostname,IP Address,Zone,Criticality,Service,Port,Product,Version,CVE ID,CVSS Score,Attack Vector
web01.corp.example,203.0.113.10,zone_dmz,3,nginx,443,nginx,1.18.0,CVE-2021-23017,7.7,AV:N
```

The ingestion layer is built for real exports, which are messy. It handles inconsistent header casing, whitespace, three notations for attack vector (`AV:N`, `NETWORK`, `n`, `Remote` all mean the same thing), duplicate findings across nightly scans, and out-of-range values.

One policy decision worth stating: **a corrupt finding does not delete the asset.** A row with a CVSS of 99 keeps its host in the inventory and loses only the finding. The obvious alternative — drop the row — silently removes a machine from your estate, and nobody notices.


## Project structure

```
app/
├── config.py           settings (env vars, .env)
├── models.py           Pydantic response schemas
├── main.py             FastAPI app and lifespan
├── ingest/             CSV → validated dataframe → RDF
│   ├── schema.py       expected columns, vocabulary, typed errors
│   ├── loader.py       reading and column validation
│   ├── filters.py      pure cleaning and filtering functions
│   ├── pipeline.py     the composed pipeline
│   └── to_rdf.py       dataframe → triples
├── graph/              the knowledge graph
│   ├── namespaces.py   the two IRI namespaces, defined exactly once
│   ├── store.py        loading, materialisation, thread-safe access
│   ├── reasoner.py     OWL 2 RL closure + SPARQL rules
│   └── queries.py      SPARQL queries and attack-path search
├── api/routes/         assets, risk, sparql
└── dashboard/          theme tokens, Altair charts, Graphviz diagram
ontology/
├── cybersec.ttl                 T-Box: classes, properties, inference axioms
└── sample_infrastructure.ttl    A-Box: the fictional estate
data/samples/                    example scanner export
pages/                           Streamlit pages
tests/                           67 tests
pyproject.toml                   dependencies and tool config
uv.lock                          exact versions of every package
```

Dependencies point one way only: `routes → deps → graph → config`. Nothing in `app/graph/` knows a web server exists, which is why swapping the in-memory store for a remote triple store touches one file.


## Tests

```bash
uv run pytest -v               # 67 tests
uv run ruff check .            # lint
uv run ruff format --check .   # formatting
```

### Why these are the tests

**Inference tests exist because a broken rule produces an empty report, not an error.** Nothing crashes. The dashboard just quietly shows nothing, and you have no reason to look. So every rule has an assertion on its output count:

```python
assert len(set(graph.subjects(RDF.type, SCS.RemotelyExploitable))) == 3
assert len(set(graph.subject_objects(SCS.attackStepTo))) == 4
```

This is not hypothetical, during development a single missing argument disabled three of the five rules and the app looked completely fine. These three lines find it in 0.26 seconds.

**Negative assertions are always paired with a positive one.** `assert CVE_X not in remotely_exploitable` passes trivially when the whole feature is dead, so it means nothing on its own.

**The ingestion tests are mostly failure paths** — missing columns, malformed CSV, out-of-range scores, boundary values at exactly 0.0 and 10.0, unknown attack vectors. Real input is broken far more often than it is valid.

**Idempotence is tested explicitly:**

```python
pd.testing.assert_frame_equal(clean(df), clean(clean(df)))
```

This caught a genuine bug: the attack-vector normaliser mapped `AV:N → AV_Network` but did not accept `AV_Network` as input, so cleaning already-clean data deleted every finding. A normalisation function has to be a projection — `f(f(x)) == f(x)` — and that is not obvious until a test says so.

**Warnings are errors** (`filterwarnings = ["error"]`). A pandas deprecation had been printing for an entire evening; turning it into a failure surfaced that a cleaning function was about to become a silent no-op on the next major version.

---

## CI

[GitHub Actions](.github/workflows/ci.yml) runs on every push and pull request:

1. install dependencies (`uv sync --locked`)
2. lint (`ruff check`)
3. formatting (`ruff format --check`)
4. tests with coverage (`pytest`)
5. build the Docker image
6. **start the container and probe its health endpoint**

Step 1 fails if `uv.lock` is out of date with `pyproject.toml`, so the tested environment is always the locked one.

Step 6 is the one that matters. `docker build` succeeding only proves the image assembles. Starting it and getting a 200 back proves the application inside actually serves traffic — which is where the `--server.address=0.0.0.0` class of bug gets caught.

CI running on a clean machine is also the only real proof that the dependencies are complete. Tests passing locally prove nothing: your laptop has your venv, your Python, your leftover packages.

Pushing a `v*` tag runs [release.yml](.github/workflows/release.yml), which publishes a multi-architecture image to Docker Hub.


## Reproducibility

- **One lockfile for everything.** `uv.lock` pins every package, including indirect ones, with hashes. Local, CI and Docker all install from it with `--locked`
- Python version pinned (`.python-version`), uv version pinned in CI and Docker
- Base image pinned by digest (`python:3.12-slim`)
- Dependencies installed in their own Docker layer before the source is copied, so editing a page rebuilds in seconds
- Dev tools (pytest, ruff) stay out of the image (`--no-dev`)
- Pre-commit hooks run ruff, keep `uv.lock` in sync, and run the tests before each push
- No dataset downloads, no network access needed at runtime — the sample estate ships with the repository
- The container runs as a non-root user
- Configuration through environment variables, never code changes


## Honest limitations

I would rather you read these here than find them yourself.

**`risk_score` is a heuristic, not a metric.** It is `peak CVSS on the path × target criticality ÷ 5`. CVSS deliberately scores a vulnerability in isolation and has no notion of chained exploitation; the research field that does — attack-graph analysis — uses probabilistic models well beyond this project. Treat it as an ordering aid.

**This is logic, not machine learning.** The reasoner derives what necessarily follows from the stated facts. It does not predict. That is a feature here — every finding has a traceable derivation, which no ML model can offer — but it should not be described as AI in the predictive sense.

**No authentication.** Anyone who can reach the port sees the full attack surface of the modelled estate. Fine for a fictional network; the first thing I would add for real data.

**The SPARQL endpoint has no query timeout.** rdflib does not support one. The row cap limits output, not work, so a deliberately expensive query can consume CPU. The proper fix is executing against Apache Jena Fuseki, which has real per-query timeouts. Until then, set `SCSRA_ENABLE_SPARQL_ENDPOINT=false` outside a controlled demo.

**No pagination.** Five hosts fit in one response. Five thousand would not.

**The ontology is not aligned to an existing standard.** A serious version would map onto [UCO](https://unifiedcyberontology.org/) or [STIX 2.1](https://oasis-open.github.io/cti-documentation/) rather than inventing its own vocabulary, so it could exchange data with other tools.



## References

**Standards**
[RDF 1.1 Primer](https://www.w3.org/TR/rdf11-primer/) ·
[RDF 1.1 Turtle](https://www.w3.org/TR/turtle/) ·
[OWL 2 Primer](https://www.w3.org/TR/owl2-primer/) ·
[OWL 2 Profiles §4 (RL)](https://www.w3.org/TR/owl2-profiles/#OWL_2_RL) ·
[SPARQL 1.1 Query](https://www.w3.org/TR/sparql11-query/) ·
[SHACL](https://www.w3.org/TR/shacl/) ·
[CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document)

**Data**
CVSS scores from the [NIST National Vulnerability Database](https://nvd.nist.gov/).
