# Semantic Cyber Security & Risk Analytics

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

Three separate people approved those three rules on three different days. Nobody approved the thing they add up to: an attacker on the internet gets into web01, moves to app01, then db01, and ends up on backup01.

**The risk is not in any single finding. It is in the composition, and composition is exactly what a table cannot show you.**

So I modelled the estate as a graph, wrote down the rules of the domain in OWL, and let a reasoner derive the paths.


## What it does

* Models a small **fictional company network** in RDF: hosts, software, CVEs, zones, firewall rules and service dependencies
* Runs an **OWL 2 RL reasoner** to derive structural facts nobody wrote down
* Applies **SPARQL rules** for the logic OWL cannot express, anything that depends on a value like a CVSS score
* Reconstructs **attack paths** where every single hop is justified by a named CVE whose attack vector allows that exact move
* Reads a **vulnerability scanner CSV export** with pandas, validates it, cleans it and converts it to RDF
* Serves all of it as a **Streamlit dashboard** and an **async FastAPI** REST API
* Ships as a single **Docker image**

On the five host sample estate: **317 hand written triples in, 644 derived triples out**, including a three hop path from the DMZ to the backup server that appears in no source file.

A note on the CSV, so nobody is surprised: the dashboard and the API run on the sample estate in `ontology/`. The scanner pipeline is shown on the Import page, where you can upload an export and watch each step. The same export can be merged into the analysis with `KnowledgeGraph(csv_sources=[...])`, and a test checks that the CSV and the Turtle files describe the exact same hosts.


## How it works

### Everything is a triple

RDF says every fact has exactly three parts: *subject, predicate, object*.

```turtle
corp:web01          scs:runs         corp:svc_nginx_web01 .
corp:svc_nginx_web01 scs:usesSoftware corp:sw_nginx_1_18_0 .
corp:sw_nginx_1_18_0 scs:affectedBy   corp:CVE-2021-23017 .
```

A pile of triples *is* a graph: subjects and objects are nodes, predicates are labelled edges.

### Two inference engines, because one is not enough

I never state that `web01` is vulnerable. It follows.

**Layer 1: OWL 2 RL** composes relationships. A property chain turns the three triples above into one:

```turtle
scs:hasVulnerability owl:propertyChainAxiom ( scs:runs scs:usesSoftware scs:affectedBy ) .
```

The reasoner concludes `web01 hasVulnerability CVE-2021-23017`.

And transitivity turns four firewall rules into nine routes:

```turtle
scs:connectsTo rdfs:subPropertyOf scs:canReach .
scs:canReach a owl:TransitiveProperty .
```

So `web01 canReach backup01`, three hops away, even though nobody ever wrote it down.

**Layer 2: SPARQL rules.** OWL 2 RL deliberately cannot compare values. `CVSS >= 7.0`, `internetFacing = true` and `vector IS AV_Network` are all outside the profile, because allowing them is what makes description logics slow or even non terminating.

So five `CONSTRUCT` rules run on top, again and again, until a full pass adds nothing new:

| Rule | Derives |
|---|---|
| `RemotelyExploitable` | CVSS ≥ threshold **and** `AV:Network` |
| `ExposedService` | a service whose host sits in a zone facing the internet |
| `EntryPoint` | a host facing the internet with a remotely exploitable flaw |
| `attackStepTo` (remote) | a single hop whose target has a remotely exploitable flaw |
| `attackStepTo` (adjacent) | a single hop inside one zone whose target has an `AV:Adjacent` flaw |

That last rule is the one I care about most. **CVE-2020-15778 on backup01 scores 7.4, above the threshold, but its attack vector is `Adjacent`.** It can never be an attacker's first move from the internet. It only becomes usable once the attacker is already inside `zone_data`. A list sorted by CVSS cannot express that. The graph can.

**Layer 3: bounded breadth first search.** SPARQL 1.1 property paths tell you a path *exists*. The specification deliberately leaves the route itself unspecified so engines can optimise. For a security report, "backup01 is reachable" is close to useless. You need *"via app01 and db01, using these three CVEs"*. So I pull the single hop `attackStepTo` edges out of the graph and a BFS rebuilds the routes.

### The pipeline

1. The Turtle files (and optionally a cleaned scanner CSV) are loaded into one rdflib graph: 317 triples
2. OWL 2 RL closure adds 635 triples
3. The SPARQL rules add 9 more, the ones that actually matter
4. BFS turns the attack steps into full paths
5. Streamlit and FastAPI both read from that same graph

There are two kinds of input on purpose. A scanner knows software and CVEs and changes every night, but it has no idea which zone faces the internet. That comes from the network configuration, which rarely changes.


## Running it

### Docker (nothing to install but Docker)

```bash
docker compose up --build
```

Then open the dashboard at http://localhost:8501 and the API docs at http://localhost:8000/docs.

### Make

```bash
make help     # list every target
make install  # create .venv from uv.lock and install git hooks
make check    # lint and test, like CI
make run      # the dashboard
make api      # the REST API
make up       # dashboard and API in containers
```

### Locally

You need [uv](https://docs.astral.sh/uv/getting-started/installation/). It installs Python 3.12 by itself if you don't have it.

```bash
git clone https://github.com/AnaisStorp/Semantic-Cyber-Security---Risk-Analytics-API.git
cd Semantic-Cyber-Security---Risk-Analytics-API

uv sync --locked                       # exact versions from uv.lock
uv run streamlit run streamlit_app.py
```

The REST API is a second way into the same graph:

```bash
uv run uvicorn app.main:app --reload
```

Interactive OpenAPI docs are at **http://localhost:8000/docs**.

### Configuration

Copy `app/.env.example` to `.env`. Everything is optional, the defaults in `app/config.py` apply otherwise.

| Variable | Default | What it does |
|---|---|---|
| `SCSRA_CVSS_THRESHOLD` | `7.0` | Minimum score for a flaw to count as exploitable (the CVSS HIGH boundary) |
| `SCSRA_MAX_ATTACK_DEPTH` | `6` | How many hops the path search explores |
| `SCSRA_ENABLE_SPARQL_ENDPOINT` | `true` | Turn the raw SPARQL endpoint off for anything that is not a demo |
| `SCSRA_SPARQL_MAX_ROWS` | `1000` | Maximum rows a SPARQL query returns |


## The dashboard

| Page | What it shows |
|---|---|
| **Overview** | Key numbers for the estate, the riskiest path, a severity chart, and what the reasoner added at each stage |
| **Assets** | Filterable inventory, with each host's inferred vulnerabilities and blast radius |
| **Attack Paths** | Every path with **evidence for each hop**: which CVE justifies each move, and which flaws are present but *not usable from that position* |
| **Network** | The estate as a diagram. Grey edges are the firewall rules, red edges are the ones an attacker can actually walk |
| **Import a scan** | Upload a scanner CSV and watch it get validated, cleaned and converted to RDF, step by step |
| **SPARQL** | A read only console over the full graph, so derived triples can be queried as if someone had written them |

The Attack Paths page is the one worth looking at. Everything else is inventory. That page is an argument with citations.


## The API

| Endpoint | Returns |
|---|---|
| `GET /health` | Liveness plus triple counts for each inference stage |
| `GET /api/v1/assets/hosts` | Inventory with inferred vulnerability status |
| `GET /api/v1/assets/hosts/{id}` | One host in detail |
| `GET /api/v1/assets/vulnerabilities` | Every CVE and how many hosts it affects |
| `GET /api/v1/risk/entry-points` | Hosts an external attacker can reach first |
| `GET /api/v1/risk/attack-paths` | Ranked paths, filterable by risk and depth |
| `GET /api/v1/risk/blast-radius/{id}` | Everything that suffers if this asset falls |
| `GET /api/v1/risk/integrity` | Semantic consistency check |
| `POST /api/v1/sparql` | Read only SPARQL |

**On "async":** the HTTP layer really is async. But `rdflib` is synchronous and CPU bound, so every call into the graph goes through `run_in_threadpool`. That does not make queries faster, because the GIL prevents real parallelism for CPU bound Python. What it does is keep the event loop free, so one slow query slows down one request instead of the whole service. Putting a blocking call inside `async def` and calling it asynchronous would be worse than not using async at all.


## The data

Everything in this repository is **fictional**. Hostnames use the `.example` TLD reserved by [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606), and public addresses come from the `203.0.113.0/24` documentation block reserved by [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737). None of it can route to a real system.

The **vulnerabilities are real**, with CVSS v3.1 base scores taken from NVD:

| CVE | Score | Vector | Affects |
|---|---|---|---|
| [CVE-2021-23017](https://nvd.nist.gov/vuln/detail/CVE-2021-23017) | 7.7 | Network | nginx 0.6.18 to 1.20.0 |
| [CVE-2020-1938](https://nvd.nist.gov/vuln/detail/CVE-2020-1938) (Ghostcat) | 9.8 | Network | Tomcat 9.0.0.M1 to 9.0.30 |
| [CVE-2020-15778](https://nvd.nist.gov/vuln/detail/CVE-2020-15778) | 7.4 | **Adjacent** | OpenSSH up to 8.3p1 |
| [CVE-2022-1552](https://nvd.nist.gov/vuln/detail/CVE-2022-1552) | 8.8 | Network | PostgreSQL 13.0 to 13.6 |

### Scan export format

```csv
Hostname,IP Address,Zone,Criticality,Service,Port,Product,Version,CVE ID,CVSS Score,Attack Vector
web01.corp.example,203.0.113.10,zone_dmz,3,nginx,443,nginx,1.18.0,CVE-2021-23017,7.7,AV:N
```

The ingestion code is built for real exports, which are messy. It handles inconsistent header casing, extra whitespace, several ways of writing the attack vector (`AV:N`, `NETWORK`, `n` and `Remote` all mean the same thing), duplicate findings across nightly scans, and values out of range.

One policy decision worth stating: **a corrupt finding does not delete the asset.** A row with a CVSS of 99 keeps its host in the inventory and only loses the finding. The obvious alternative, dropping the row, silently removes a machine from your estate and nobody notices.


## Project structure

| Path | What's inside |
|---|---|
| `app/config.py` | settings from environment variables and `.env` |
| `app/models.py` | Pydantic response schemas |
| `app/main.py` | FastAPI app and its lifespan |
| `app/ingest/` | CSV to validated dataframe to RDF |
| `app/ingest/schema.py` | expected columns, vocabulary, typed errors |
| `app/ingest/loader.py` | reading the file and checking its columns |
| `app/ingest/filters.py` | pure cleaning and filtering functions |
| `app/ingest/pipeline.py` | the full cleaning pipeline |
| `app/ingest/to_rdf.py` | dataframe to triples |
| `app/graph/namespaces.py` | the two IRI namespaces, defined exactly once |
| `app/graph/store.py` | loading, materialisation, thread safe access |
| `app/graph/reasoner.py` | OWL 2 RL closure and SPARQL rules |
| `app/graph/queries.py` | SPARQL queries and the attack path search |
| `app/api/routes/` | assets, risk, sparql |
| `app/dashboard/` | theme, Altair charts, Graphviz diagram |
| `ontology/cybersec.ttl` | TBox: classes, properties, inference axioms |
| `ontology/sample_infrastructure.ttl` | ABox: the fictional estate |
| `data/samples/` | example scanner export |
| `pages/` | Streamlit pages |
| `tests/` | 87 tests |
| `pyproject.toml` | dependencies and tool config |
| `uv.lock` | exact versions of every package |

Dependencies only go one way: routes use deps, deps use the graph, the graph uses config. Nothing in `app/graph/` knows a web server exists, which is why swapping the in memory store for a remote triple store touches one file.


## Tests

```bash
uv run pytest -v               # 87 tests
uv run ruff check .            # lint
uv run ruff format --check .   # formatting
```

Coverage is around 94%.

### Why these are the tests

**Inference tests exist because a broken rule produces an empty report, not an error.** Nothing crashes. The dashboard just quietly shows nothing, and you have no reason to look. So every rule has an assertion on its output count:

```python
assert len(set(graph.subjects(RDF.type, SCS.RemotelyExploitable))) == 3
assert len(set(graph.subject_objects(SCS.attackStepTo))) == 4
```

This is not hypothetical. During development a single missing argument disabled three of the five rules and the app looked completely fine. These lines catch it in well under a second.

**Negative assertions always come with a positive one.** `assert CVE_X not in remotely_exploitable` passes trivially when the whole feature is dead, so on its own it means nothing.

**The ingestion tests are mostly about failure**: missing columns, malformed CSV, scores out of range, boundary values at exactly 0.0 and 10.0, unknown attack vectors. Real input is broken far more often than it is valid. Every filter in `filters.py` has its own test.

**Idempotence is tested explicitly:**

```python
pd.testing.assert_frame_equal(clean(df), clean(clean(df)))
```

This caught a real bug. The attack vector normaliser turned `AV:N` into `AV_Network`, but did not accept `AV_Network` as input, so cleaning data that was already clean deleted every finding. A normalisation function has to satisfy `f(f(x)) == f(x)`, and that is not obvious until a test says so.

**The API tests call every endpoint in process** through `httpx`, without starting a server. They check the happy paths, but also that an unknown host gives a 404, a malformed id or a huge `max_depth` gets rejected with a 422, a SPARQL `INSERT` is refused, the row cap actually truncates, and the endpoint can be switched off.

**Warnings are errors** (`filterwarnings = ["error"]`). A pandas deprecation had been printing for an entire evening. Turning it into a failure showed me that a cleaning function was about to silently stop doing anything in the next major version.


## CI

[GitHub Actions](.github/workflows/ci.yml) runs on every push and pull request:

1. install dependencies (`uv sync --locked`)
2. lint (`ruff check`)
3. formatting (`ruff format --check`)
4. tests with coverage (`pytest`)
5. build the Docker image
6. **start the container and check its health endpoint**

Step 1 fails if `uv.lock` no longer matches `pyproject.toml`, so what gets tested is always the locked environment.

Step 6 is the one that matters. A successful `docker build` only proves the image assembles. Starting it and getting a 200 back proves the app inside actually answers, which is exactly where a mistake like Streamlit not listening on `0.0.0.0` gets caught.

Running on a clean machine is also the only real proof that the dependencies are complete. Tests passing on my laptop prove nothing, because my laptop has my venv, my Python and my leftover packages.

Pushing a version tag (like `v0.1.0`) runs [release.yml](.github/workflows/release.yml), which builds the image for amd64 and arm64 and publishes it to Docker Hub.


## Reproducibility

* **One lockfile for everything.** `uv.lock` pins every package, indirect ones included, with hashes. My machine, CI and Docker all install from it with `--locked`
* The Python version is pinned in `.python-version`, and the uv version is pinned in CI and Docker
* The base image is pinned by digest (`python:3.12-slim`)
* Dependencies are installed in their own Docker layer before the code is copied, so editing a page rebuilds in seconds
* Dev tools like pytest and ruff stay out of the image
* Pre commit hooks run ruff, keep `uv.lock` in sync and run the tests before each push
* No dataset downloads and no network access needed at runtime, the sample estate ships with the repository
* The container runs as an unprivileged user
* Configuration goes through environment variables, never code changes


## Honest limitations

I would rather you read these here than find them yourself.

**`risk_score` is a heuristic, not a metric.** It is `peak CVSS on the path × target criticality ÷ 5`. CVSS deliberately scores a vulnerability in isolation and has no notion of chained exploitation. The research field that does, attack graph analysis, uses probabilistic models well beyond this project. Treat it as a way to sort, nothing more.

**This is logic, not machine learning.** The reasoner derives what necessarily follows from the stated facts. It does not predict anything. That is a feature here, since every finding can be traced back to where it came from, which no ML model can offer. But it should not be described as AI in the predictive sense.

**No authentication.** Anyone who can reach the port sees the full attack surface of the modelled estate. Fine for a fictional network, and the first thing I would add for real data.

**The SPARQL endpoint has no query timeout.** rdflib does not support one. The row cap limits output, not work, so a deliberately expensive query can eat CPU. The proper fix is running queries on Apache Jena Fuseki, which has real timeouts. Until then, set `SCSRA_ENABLE_SPARQL_ENDPOINT=false` outside a controlled demo.

**No pagination.** Five hosts fit in one response. Five thousand would not.

**The ontology is not aligned to an existing standard.** A serious version would map onto [UCO](https://unifiedcyberontology.org/) or [STIX 2.1](https://oasis-open.github.io/cti-documentation/) instead of inventing its own vocabulary, so it could exchange data with other tools.


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
