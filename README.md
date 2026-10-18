# SYNTHSHIELD

### Coalition-Aware Security Gateway for Autonomous AI Agents

**Research prototype · Python / FastAPI / PostgreSQL / Docker / Ollama**

> **Security and research scope:** SYNTHSHIELD is a local proof of concept built with **synthetic organizational data**. It demonstrates selected security properties of an AI-agent tool-use gateway; it is **not** a production-ready authorization system, a comprehensive penetration test, or a statistically validated sensitive-inference classifier.

## Why this project?

An AI agent can collect individually permissible facts from different systems and combine them into information that an organization considers sensitive. This is a **sensitive aggregation-inference** problem: the risk may emerge from the *combination*, not from any single tool result.

SYNTHSHIELD explores a defense-in-depth approach to this problem. The language model selects a tool action; a separate trusted gateway checks the agent's credentials, allowed sources, workflow context, purpose, and the inferred risk of the resulting data-source coalition **before** executing the protected tool.

## Dashboard preview — retro security console

![SYNTHSHIELD retro security dashboard showing recorded security evidence](docs/images/synthshield-retro-dashboard.png)

*Actual screenshot of the local, read-only research-evidence dashboard. It visualizes saved experiment results (106 passing tests, control-isolation scenarios, risk scores, and authorized/denied tool requests); it is **not** live telemetry. The numbers are from synthetic research fixtures.*

**Launch locally:**

```bash
python -m scripts.synthshield_dashboard_retro
```

Open [`http://127.0.0.1:8766`](http://127.0.0.1:8766) on the same computer while the script runs. This `localhost` link is **not** an internet-hosted public demo. The screenshot above is what GitHub visitors can view without running the application.

## Architecture

```mermaid
flowchart TD
  U[Trusted task / host coordinator] --> C[Context and scoped credential provisioning]
  U --> L[Local Ollama Llama 3.2 1B]
  L --> R[Agent runner / selected tool request]
  C --> P[(PostgreSQL scopes and credentials)]
  R --> A[Isolated agent-lab container]
  A -->|Bearer token + source| T[Trusted Tool API / FastAPI]
  T -->|Verify member / lock coalition state| P
  T -->|Evaluate proposed source coalition| E[Policy API / FastAPI]
  E --> I[Rule-based inference engine]
  E --> PL[Purpose Lock]
  E --> AU[Audit and recovery journal]
  E -->|ALLOW / BLOCK| T
  T -->|ALLOW only| D[Synthetic finance / travel / calendar tools]
  T -->|Result or denial| R
  R -->|Sanitized tool feedback| L
```

### Key capabilities

- **Sensitive coalition detection:** detects three specific strategic signals from synthetic calendar, travel, and finance records; the full three-signal coalition is blocked by the current rule set.
- **Purpose Lock:** checks the requested task, authorized data sources, and forbidden derived-output terms independently from inference detection.
- **Credential-mediated tool access:** the trusted tool API verifies scoped Bearer credentials and agent/source membership; untrusted code does not choose the policy decision.
- **Shared coalition history:** a trusted coordinator assigns context IDs; PostgreSQL transactions track prior authorized source access within a scope.
- **Isolation and least privilege:** Docker separates agent and backend networks; runtime PostgreSQL roles have restricted privileges.
- **Auditing:** policy decisions are written to audit/recovery records and PostgreSQL in the tested configuration.
- **Prompt-injection experiments:** attacker-controlled text in model feedback can affect action selection, while the tested tool-execution boundary still denies unauthorized actions.
- **Local evidence dashboard:** browser interface reads saved experimental logs; **not live telemetry**.

## Tested results (19 October 2026)

Results below are from the committed synthetic fixtures and local evaluation environment. They are **observations, not general security guarantees**.

| Evaluation | Observed outcome |
|---|---|
| Automated test suite | **106 passed** in the configured test environment |
| Independent security-control experiment | **4/4** expected inference / Purpose Lock combinations |
| Deployed boundary checks | **5/5** checks passed in the tested Docker deployment |
| Final grounded-agent demonstration | Finance **HTTP 200**, travel **HTTP 200**, calendar **HTTP 403** |
| Final prompt-injection demonstration | Calendar requested after attacker text; **no unauthorized calendar HTTP 200** observed |
| Grounded verified summary | Rejected fabricated meeting count; denied calendar meeting count reported as **unknown** |
| Exploratory paired attack trials | Immediate calendar requests: **3/3** with malicious note, **0/3** with neutral note; not a generalizable success rate |

### Why was calendar denied?

The default `data/purpose_policy.json` authorizes the *monthly expense report* agent to use **finance** and **travel**, but **not calendar**. A calendar-only expense-report request is blocked by **Purpose Lock** even though its inference risk is low. The deployed credential/source checks also independently mediate tool access; the HTTP status alone does not identify which sub-check was decisive in every run.

When all three synthetic sources contain their configured strategic signals, the **inference engine** returns a rule-based risk score of **95/100** and `BLOCK`. In the independent control test, this block persists even with a permissive **in-memory test policy**, demonstrating separation between the two controls.

| Source coalition | Inference score | Inference decision | Purpose decision (default expense policy) | Final decision |
|---|---:|---|---|---|
| Finance + travel | 45/100 | ALLOW | ALLOW | **ALLOW** |
| Calendar alone | 20/100 | ALLOW | BLOCK | **BLOCK** |
| All three | 95/100 | BLOCK | BLOCK | **BLOCK** |
| All three, temporary permissive test policy | 95/100 | BLOCK | ALLOW | **BLOCK** |

These are **rule-based scores**, not probabilities of compromise.

## Quick start: standalone evidence and policy experiments

You can explore the inference/Purpose Lock experiment and the recorded dashboard **without** configuring Docker, Ollama, PostgreSQL, or privileged secrets.

Prerequisites: Git and a compatible Python 3 environment (development was performed with Python 3.13).

```bash
git clone https://github.com/Nikhilbal/synthshield.git
cd synthshield
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

# Run local deterministic source-coalition / policy experiment
python -m scripts.phase11f_control_isolation

# View saved research evidence in your browser (read-only)
python scripts/synthshield_dashboard.py
```

Open **http://127.0.0.1:8765** on the same computer. Press **Ctrl+C** to stop the dashboard. It reads recorded evidence in `reports/phase12/`; it does **not** monitor running containers or access the database.

The standalone control-isolation experiment reads synthetic records from `data/` and uses an **in-memory** permissive test policy for one case. It does not modify `data/purpose_policy.json`.

### Optional retro-style evidence dashboard

Run `python -m scripts.synthshield_dashboard_retro` and open `http://127.0.0.1:8766`. This launcher imports the existing dashboard's evidence parser and changes only the visual theme. **Both versions read recorded evidence; neither is a live monitoring service.** The original dashboard remains at `http://127.0.0.1:8765` when run using `python scripts/synthshield_dashboard.py`.

## Full local AI-agent / Docker demonstration (advanced)

The deployed demonstration requires **additional secure setup** beyond the quick start:

- Docker Desktop / Docker Compose and a local Ollama server with `llama3.2:1b` installed.
- An **untracked** `.env` containing the required PostgreSQL, runtime-role, and audit credentials. **Do not commit or publish secrets.**
- Initialized PostgreSQL schema, migrations under `db/migrations/`, and correctly provisioned least-privilege runtime/coordinator roles.
- Both `compose.yaml` and `compose.isolation.yaml`, with healthy `postgres`, `policy-api`, and `trusted-tool` services.

**This repository does not currently provide a turnkey, audited one-command secure bootstrap.** Do not use development database passwords or copy research credentials to a public environment.

For an *already configured* local lab:

```bash
# Inspect service state
docker compose -f compose.yaml -f compose.isolation.yaml ps

# Confirm the local model is installed
ollama list

# Run the bounded grounded AI-agent demo
python -m scripts.phase11c_grounded_agent

# Run the controlled tool-feedback prompt-injection experiment
python -m scripts.phase11d_prompt_injection_lab

# Database-dependent test suite (requires a correctly configured DB)
SYNTHSHIELD_RUN_DB_TESTS=1 python -m pytest -q --tb=short
```

The live scripts provision and clean up temporary research identities. Do not run against production records or services.

## Repository guide

```text
synthshield/
├── src/
│   ├── engine.py                     # Rule-based inference scoring
│   ├── coalition.py                  # Coalition / counterfactual analysis
│   ├── purpose.py                    # Purpose Lock + decision combination
│   ├── api.py                        # Policy evaluation API
│   ├── authorized_agent_gateway.py   # Scoped agent access and context state
│   └── trusted_tool_service.py       # Protected HTTP tool execution
├── agent_lab/                         # Isolated agent-side client
├── data/                              # Synthetic fixtures and test policy
├── db/migrations/                     # PostgreSQL schema / privilege migrations
├── scripts/
│   ├── synthshield_dashboard.py       # Read-only local evidence browser
│   ├── phase11c_grounded_agent.py     # Bounded, grounded AI-agent demo
│   ├── phase11d_prompt_injection_lab.py
│   ├── phase11e_controlled_evaluation.py
│   └── phase11f_control_isolation.py
├── tests/
├── reports/phase12/                   # Recorded evaluation evidence and reports
├── compose.yaml
└── compose.isolation.yaml
```

## Evidence and technical write-ups

- [Security findings and research limitations](reports/phase12/security_findings.md)
- [Architecture, threat model, and research demonstration](reports/phase12/technical_documentation.md)
- [Independent security-control evidence](reports/phase12/control_isolation.txt)
- [Deployed boundary-test evidence](reports/phase12/deployed_boundary_test.txt)
- [Final grounded-agent demonstration](reports/phase12/final_grounded_agent_demo.txt)
- [Final prompt-injection demonstration](reports/phase12/final_prompt_injection_demo.txt)
- [Paired prompt-injection results](reports/phase11e_results.json)
- [Evidence checksum manifest](reports/phase12/evidence_sha256.txt)

The checksum manifest covers its specified evidence artifacts at the time it was generated; the manifest must itself be stored in a trusted location for meaningful tamper detection. Later demonstration logs are not automatically covered by the earlier manifest.

## Threat model and limitations

**Trust boundaries:** model-selected tool calls are lower trust; the trusted host coordinator and protected tool gateway are intended to control context assignment, credential issuance, and execution. These assumptions have **not** been verified under every possible deployment or attack path.

Outstanding work before any production-security claim includes:

1. **Authoritative context assignment:** unrelated context IDs might fragment shared coalition history if orchestration assigns them incorrectly.
2. **Legacy and alternate execution paths:** not every gateway, script, or direct-tool entry point has been exhaustively audited for bypass opportunities.
3. **Credential lifecycle and races:** more coverage is needed for token revocation, concurrent requests, workflow membership, and end-to-end enforcement.
4. **Detector generalization:** the current three-signal inference rules have not been benchmarked for false-positive/false-negative behavior on diverse unseen cases.
5. **Prompt injection:** the AI model can still select manipulated actions; tested authorization guards prevented unauthorized execution in the observed scenarios, not in all attacks.
6. **Operational hardening:** secrets, audit provenance, safe initial configuration, dependency supply-chain security, and broader threat modeling remain open.

The project's **95/100 critical score** measures a hand-designed rule condition, **not** a calibrated real-world risk probability. The `106 passed` count describes the tested revision and environment; it is not a permanent guarantee after future code changes.

## Technology stack

**Python 3.13 (development), FastAPI, PostgreSQL 18, Docker Compose, Ollama (`llama3.2:1b`), pytest**, and the Python standard library for the local evidence dashboard.

## Project status

**Completed research prototype / bounded local demonstration.** Source code, experiments, and evidence are provided for learning, evaluation, and iteration. Review the security findings before adapting any part of this design to a real organization.
