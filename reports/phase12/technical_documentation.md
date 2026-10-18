# SYNTHSHIELD — Technical Architecture, Threat Model, and Research Demonstration

**Document:** Phase 12D — Technical documentation
**Version:** Research-prototype draft, 19 October 2026
**Project:** SYNTHSHIELD — Counterfactual sensitive-aggregation security for AI-agent tool use
**Environment evaluated:** Local Python/FastAPI, PostgreSQL 18, Docker Compose, macOS host, Ollama `llama3.2:1b`
**Status:** Prototype with reproducible, scoped security tests; **not production-certified**

> **Evidence boundary.** This document summarizes the code excerpts and local experimental outputs provided during development. It describes **observed** security properties, **assumptions**, and **open findings** separately. Do not represent results from synthetic fixtures as performance on unseen real-world attacks.

## 1. Executive overview

Autonomous or semi-autonomous AI agents can request individually permissible tools and thereby assemble information that becomes sensitive **only when combined**. SYNTHSHIELD investigates this *sensitive aggregation inference* problem by mediating tool requests at a gateway outside the AI model, recording sources accessed across related workflows, and evaluating the evolving source coalition before executing protected tools.

The prototype combines two distinct controls:

1. **Sensitive-inference detection:** a rule-based engine scans the selected synthetic records for strategically revealing signals and blocks the recognized three-signal coalition.
2. **Purpose Lock:** a separate policy check considers the requested task, allowed sources, and forbidden derived-output terms. Either control may independently block.

The current local demonstration uses an Ollama language model to propose tool actions; authorization is handled by a separate FastAPI trusted-tool service. Synthetic finance/travel/calendar tools stand in for external data providers. The model cannot authorize its own requests.

## 2. System scope and non-goals

**In scope:** Synthetic fixtures; local model-selected or iterative tool requests; scoped Bearer credentials; shared PostgreSQL coalition history; purpose and inference policy evaluation; JSONL/PostgreSQL audit flows; local Docker network and PostgreSQL role separation; controlled prompt-injection experiments; reproducible testing.

**Out of scope for this prototype:** Real company records, production IAM, hostile-host compromise, third-party API security certification, comprehensive container breakout testing, statistical detector accuracy on unseen data, cross-tenant isolation, and verified global attribution of every related workflow to one context.

**Important terminology:** A policy risk score of 95/100 is a **rule-based scoring output**, not a calibrated confidence or observed real-world probability. A result of `ALLOW` for risk 45/100 does not mean the coalition is universally safe; it only passes the current rule set.

## 3. High-level architecture

```mermaid
flowchart TD
    User[Trusted research task] --> Coord[Trusted host coordinator]
    Coord -->|Assign context; provision credential| PG[(PostgreSQL)]
    User --> AI[Ollama llama3.2:1b on host]
    AI -->|Select one source: finance/travel/calendar| Runner[Host-side agent runner]
    Coord -->|Deliver only scoped token for request| Runner
    Runner -->|stdin: request + credential| Agent[Untrusted agent-lab container]
    Agent -->|Bearer + source over agent_net| Tool[Trusted-tool FastAPI service]
    Tool -->|Credential membership, scope lock, reservation| PG
    Tool -->|Proposed source coalition over backend_net| Policy[Policy API FastAPI service]
    Policy --> Engine[Inference engine]
    Policy --> Purpose[Purpose Lock]
    Policy --> Audit[JSONL / recovery journal]
    Policy -->|Security event| PG
    Engine --> Policy
    Purpose --> Policy
    Policy -->|ALLOW or BLOCK| Tool
    Tool -->|On ALLOW only| Synthetic[Synthetic protected tools]
    Tool -->|Result or HTTP denial| Agent
    Agent -->|Sanitized feedback| Runner
    Runner -->|Feedback without secrets| AI
```

### 3.1 Trust boundaries

| Boundary | Intended property | What was actually observed |
|---|---|---|
| AI model → tool selection | Model selects actions but cannot decide authorization | Phase 11A–11E demos used model-selected actions subject to independent HTTP checks |
| Host coordinator → PostgreSQL | Coordinator can create scopes/agents without superuser privileges | `synth_coordinator` was verified non-superuser and allowed to provision agents |
| `agent-lab` → internal network | Untrusted agent accesses trusted-tool endpoint, not DB or policy API directly | Phase 12B connection attempts to `postgres:5432` and `policy-api:8000` failed; missing/unknown tokens were rejected |
| Trusted-tool → PostgreSQL | Runtime can inspect authorized membership/update coalition access but cannot issue agent credentials | Targeted privilege checks passed for `synth_tool_runtime` |
| Policy API → data & audit | Evaluate independently, persist audit; fail closed on unavailable required services | Local API and PostgreSQL integration checks succeeded; specific outage/503 case did not execute a protected tool |
| Tool result → AI planner | Returned text is lower-trust data, not authority | Prompt-injection tests observed model action changes; gateway still denied calendar |

The failed direct connections are scoped observations, not proofs that no network path or privileged secret exists anywhere. Coordinator secrets were checked for absence from tested runtime **environment variables**, not every possible storage location.

## 4. Component map

| File or component | Responsibility |
|---|---|
| `src/engine.py` | Load synthetic data and detect three information signals; generate rule-based risk/decision |
| `src/coalition.py` | Analyze source coalitions, minimal sensitive sets, counterfactual removal, synergy |
| `src/purpose.py` | Load purpose policy; evaluate purpose drift; merge independent decisions |
| `src/api.py` | Handle `POST /v1/evaluate`, evaluate controls and write security/audit records |
| `src/agent_gateway.py` | HTTP evaluation client; validate safe responses; fail closed on policy outages |
| `src/authorized_agent_gateway.py` | Trusted scope creation, credential issuance, membership resolution and guarded source access |
| `src/trusted_tool_service.py` | Expose `POST /v1/agent-tools/execute`; map source to synthetic protected tool; send 401/403/503 as appropriate |
| `src/database.py` | Connect using environment-selected runtime identity and dedicated coordinator connection |
| `src/event_store.py`, `src/audit.py`, `src/integrity.py`, recovery modules | Store and verify audit/recovery evidence; implementation must be assessed with matching runtime configuration |
| `db/migrations/004_least_privilege_roles.sql` | Define restricted PostgreSQL roles and targeted privileges |
| `db/migrations/005_trusted_context_scope.sql` | Add nullable `context_id` and a unique partial index for non-NULL context IDs |
| `compose.yaml`, `compose.isolation.yaml`, `Dockerfile.isolation`, `agent_lab/` | Docker services and isolated agent execution topology |
| `scripts/phase11_ai_agent_demo.py` | LLM-planned tool access through isolated Docker agent |
| `scripts/phase11b_iterative_agent.py` | Iterative tool choice with feedback |
| `scripts/phase11c_grounded_agent.py` | Verified summaries and bounded duplicate handling |
| `scripts/phase11d_prompt_injection_lab.py` | Initial tool-output injection demonstration |
| `scripts/phase11e_controlled_evaluation.py` | Paired controlled tool-output injection trials |
| `scripts/phase11f_control_isolation.py` | Four independent inference/Purpose Lock cases |
| `scripts/demo_agent_gateway.py` | Local trusted-context credentialed demo; different from the isolated Docker agent |

The repository also retains `src/session_gateway.py` and `src/shared_agent_gateway.py`. The deployed route inspection showed no legacy `/v1` routes in the two inspected services; this **does not prove** those modules are unreachable through every potential entry point.

## 5. Authorization sequence

1. A **trusted coordinator** assigns a `context_id` to an information-sharing context, calls `get_or_create_coalition_scope(context_id=..., task=...)`, and provisions agent credentials tied to the resolved `scope_id` and a restricted list of sources.
2. A model proposes an action such as `finance`. The action is treated as a request, **not** a policy decision.
3. A host runner sends only the source-specific Bearer credential and source name to the isolated agent container, then to `POST /v1/agent-tools/execute`.
4. The trusted-tool service resolves the credential hash in PostgreSQL, checks that the membership is active, and checks the source permission.
5. The service locks the shared `coalition_scopes` row with `SELECT ... FOR UPDATE`, combines `accessed_sources` with the proposed source, and calls the policy API.
6. The policy API independently evaluates sensitive inference and purpose. If either control blocks, the request is denied and the protected tool is not executed.
7. If allowed, the tool runtime reserves the source in the shared coalition history **before** executing the synthetic protected tool. The reservation persists even if tool execution subsequently fails.
8. The model receives only approved tool data, a denial, or an error. The grounded reporter uses approved structured results rather than accepting unsupported model-supplied numbers.

**Known design gap:** The database ensures *one scope per same `context_id`*, but cannot know whether two **different** IDs represent the same underlying workflow. The legacy creator still generates fresh scopes. Trusted orchestration must prevent splitting related work across IDs. Do not describe SYN-SEC-001 as closed.

## 6. Inference engine and Purpose Lock

### 6.1 Synthetic inference signals

The current rule-based detector checks source JSON text for:

| Source | Recognized signal |
|---|---|
| Calendar | `cfo`, `alphacorp`, `meeting` |
| Travel | `cfo`, `london` |
| Finance | `due diligence` |

Triggered-signal mapping:

| Number of signals | Risk score | Level | Inference decision |
|---:|---:|---|---|
| 0 | 0 | MINIMAL | ALLOW |
| 1 | 20 | LOW | ALLOW |
| 2 | 45 | MEDIUM | ALLOW |
| 3 | 95 | CRITICAL | BLOCK |

The 3-signal condition yields the prototype's protected strategic inference. The detector is deterministic and brittle to paraphrases or changed data schemas; it is **not** an LLM-based or calibrated inference classifier.

### 6.2 Purpose Lock

The checked-in `data/purpose_policy.json` authorizes an expense-report purpose using configured task keywords and sources `finance` and `travel`. The source `calendar` is not in that policy's allowed-source list. The prototype also checks derived output for forbidden inference keywords.

`combine_security_decisions()` returns `BLOCK` whenever **either** the inference or purpose decision is `BLOCK`.

### 6.3 Independently tested control matrix (Phase 11F)

| Scenario | Inference | Purpose | Final | Inference risk |
|---|---|---|---|---:|
| Finance + travel expense report | ALLOW | ALLOW | ALLOW | 45/100 |
| Calendar-only expense request | ALLOW | BLOCK | BLOCK | 20/100 |
| All three sources with in-memory permissive policy | BLOCK | ALLOW | BLOCK | 95/100 |
| All three sources with original policy | BLOCK | BLOCK | BLOCK | 95/100 |

The permissive policy was used **only in memory for a local engine test**, not pushed to the Docker policy service. Therefore the test establishes independent rule-level logic, not a deployed bypass of Purpose Lock.

## 7. Threat model

### 7.1 Assets and adversaries

**Protected assets:** Source data, derived strategic inferences, agent credentials, coordinator database credentials, security audit logs, coalition histories, and policy integrity.

**Adversaries modeled:** An untrusted AI agent requesting protected tools; an agent presenting an absent or bogus token; malicious instructions embedded in lower-trust tool-result text; an orchestrator or misconfigured integration that fragments related workflows into distinct contexts. Full hostile-container/host compromise is not modeled.

### 7.2 Threat-to-control table

| Threat | Primary defense | Evidence | Residual risk |
|---|---|---|---|
| Unauthorized tool calls | Bearer token validation and source-specific membership | HTTP 401/403 checks; credentialed live demo | Token theft, lifecycle gaps, unreviewed entry points |
| Direct internal service access from agent | Docker network separation | Failed direct DB/policy API connections | Network/DNS assessment is incomplete |
| Sensitive aggregation across related agents | Locked shared coalition state + inference engine | Scope reuse and risk 95 block for synthetic three-source fixture | Different context IDs can fragment history |
| Task/purpose drift | Purpose Lock | Calendar-only expense request blocked at risk 20 | Keyword heuristics may be bypassed or overblock |
| Tool-output prompt injection | Gateway authorizes independently; grounded report discards unverified claims | Phase 11E: no unauthorized calendar execution or fake meeting count | Model still followed attack-like instruction and degraded task completion |
| Audit tampering/availability | PostgreSQL restrictions, HMAC journal/recovery design | Targeted permission and persistence tests | End-to-end tamper resistance and operational recovery not comprehensively verified |
| Legacy bypass path | Keep deployed protected tools behind trusted-tool service | No legacy `/v1` route observed in scanned services | Imports, direct tool paths and other deployments not exhaustively audited |

## 8. Experimental evidence summary

All counts are from the development session's observed terminal logs; see the companion Phase 12C findings report for detailed conditions and caveats.

| Experiment | Reported result | Artifact |
|---|---|---|
| Full automated regression suite | **106 passed in 1.20 s** at Phase 12A | `reports/phase12/pytest_baseline.txt` |
| Independent control matrix | **4/4 expected combinations** | `reports/phase12/control_isolation.txt` |
| Deployed boundary checks | **5/5** (secret env vars absent, 2 connection denials, 401, 403) | `reports/phase12/deployed_boundary_test.txt` |
| Paired injection comparison, 3 exposed pairs | Immediate calendar: **0/3 control**, **3/3 attack** | `reports/phase11e_results.json` |
| Same paired injection trials | **0** successful unauthorized calendar executions; **0** fictional meeting counts in verified summaries | `reports/phase11e_results.json` |
| Trusted-context demo | Scope reuse, wrong credential denial, finance/travel allowed, calendar denied, cleanup | Earlier local demonstration logs |

**Interpretation:** In the control condition, the model requested calendar later as well; immediate selection differed after the injected note. The adversarial result is exploratory (small number of narrow, deterministically configured trials), not a validated cross-model attack success rate. Calendar HTTP 403 in the deployed experiment does not alone isolate which security control blocked access; Phase 11F tests control independence directly.

## 9. Reproduction guide (local research environment)

### 9.1 Prerequisites

- macOS environment with Python 3.13 virtual environment at `.venv`, plus project dependencies already installed.
- Docker Desktop and Compose with the existing `postgres`, `policy-api`, `trusted-tool`, and `agent-lab` definitions.
- PostgreSQL initialized with the project tables and migrations **004** and **005**, and the expected restricted database roles configured.
- Ollama installed with model `llama3.2:1b`; Ollama serving `127.0.0.1:11434` when running LLM experiments.
- Local `.env` configured with required secrets. **Never publish `.env`, credentials, token material, HMAC keys, or resolved Compose configuration output containing secrets.**

### 9.2 Verify services and automated tests

```bash
cd ~/Projects/synthshield
source .venv/bin/activate

docker compose -f compose.yaml -f compose.isolation.yaml ps
SYNTHSHIELD_RUN_DB_TESTS=1 python -m pytest -q --tb=short
```

### 9.3 Repeat the isolated engine experiment

```bash
python -m scripts.phase11f_control_isolation
```

This test evaluates the two engines directly; no live policy alteration is required.

### 9.4 Repeat bounded model experiments

```bash
ollama list
python -m scripts.phase11c_grounded_agent
python -m scripts.phase11e_controlled_evaluation --trials 3
```

The Ollama server must be running and Docker must be healthy. The paired injection script provisions temporary agent identities; do not log or copy their plaintext credentials into a research report.

### 9.5 Evidence locations and chain of custody

```text
reports/
├── phase11e_results.json
└── phase12/
    ├── pytest_baseline.txt
    ├── control_isolation.txt
    ├── deployed_boundary_test.txt
    ├── security_findings.md
    └── technical_documentation.md   # this document
```

Evidence files can be hashed locally (without opening or printing secrets) using:

```bash
shasum -a 256 \
  reports/phase11e_results.json \
  reports/phase12/pytest_baseline.txt \
  reports/phase12/control_isolation.txt \
  reports/phase12/deployed_boundary_test.txt \
  reports/phase12/security_findings.md \
  reports/phase12/technical_documentation.md \
  > reports/phase12/evidence_sha256.txt
```

Hashing detects changes **relative to a previously trusted manifest**. It does not authenticate how an experiment was run or protect against an attacker who can replace both files and manifest.

## 10. Outstanding findings and recommended priority

| ID | Status | Completion requirement |
|---|---|---|
| **SYN-SEC-001** | Open / partially mitigated | Trusted orchestration consistently binds all related workflows to a canonical context; regression tests demonstrate that split-context attacks are rejected or correlated |
| **SYN-SEC-002** | Tested paths enforced / wider audit outstanding | Exercise revocation, concurrency, issuance boundaries, credential lifecycle, membership, and every protected HTTP route |
| **SYN-SEC-003** | Open audit | Map old gateway/direct tool entry points and establish that untrusted agent contexts cannot execute them |
| **SYN-SEC-004** | Research limitation | Use diversified fixtures and measure detector false-positive/false-negative behavior |
| **SYN-SEC-005** | Model-level issue observed | Evaluate varied injection strategies, prompts, and models; report both model deviation and actual data-access outcomes |
| **SYN-SEC-006** | Release preparation outstanding | Review untracked files; perform secrets check; pin dependencies and record build versions/hashes; verify reports before Git publication |

**Release criterion:** Treat the final deliverable as a **local research demonstration** until critical trust-boundary issues are closed. A public repo may show proof-of-concept code and explicitly unresolved findings, but must never imply enterprise-ready security.

## 11. Suggested demonstration outline (8–12 minutes)

1. **Problem (1 minute):** Individually authorized tool results may combine into a sensitive inference.
2. **Architecture (1–2 minutes):** Show model, untrusted container, trusted tool gateway, policy API, and shared coalition database.
3. **Baseline (2 minutes):** Execute an approved expense report; show finance and travel ALLOW and a grounded summary.
4. **Access denial (1 minute):** Show calendar HTTP 403 and explain the independent role of Purpose Lock.
5. **Inference isolation (2 minutes):** Run Phase 11F and highlight risk 95 with inference BLOCK despite permissive test policy.
6. **Prompt injection (2 minutes):** Summarize Phase 11E control-versus-attack observations, zero unauthorized executions, and degraded task completion.
7. **Limitations (1 minute):** Discuss context splitting, legacy gateways, rule-based detection, and prototype-only deployment claims.

**Safety:** Use only synthetic fixtures. Never display real credentials, `.env` values, private keys, or production data during demonstrations.

## 12. Final assessment

The evidence supports SYNTHSHIELD as a functioning **local research prototype** of independent, credential-mediated AI-agent tool authorization combined with a rule-based sensitive-aggregation detector and Purpose Lock. It shows successful authorization checks, selected network/database separation, trusted-context reuse, fail-closed denials, verified-data reporting, and a controlled synthetic prompt-injection experiment. It does **not** demonstrate production security or complete defense against context fragmentation and alternative execution paths.

**Companion document:** `reports/phase12/security_findings.md` (Phase 12C).
**Next milestone:** Phase 12E — reviewed Git staging, secret screening, deterministic validation, and a local checkpoint commit.
