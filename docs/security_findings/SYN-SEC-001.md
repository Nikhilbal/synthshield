# SYN-SEC-001 — Workflow Identity Fragmentation

**Project:** SYNTHSHIELD  
**Test phase:** 10.1 — Authorization Bypass Simulation  
**Status:** Confirmed in controlled synthetic environment  
**Severity:** Undetermined

## Vulnerability Description

SYNTHSHIELD maintains coalition-access history using a PostgreSQL record identified by `workflow_id`.

When collaborating agents operate under separate workflow IDs, their data-source access histories are not combined.

## Attack Simulation

Three agents requested access to finance, travel, and calendar data using three distinct workflow IDs.

Each individual access was authorized by the synthetic policy evaluator.

The three-source sensitive coalition was not detected.

## Control Experiment

The same agents used a single shared workflow ID.

SYNTHSHIELD allowed finance and travel access but blocked calendar access before tool execution.

## Root Cause

Coalition history is partitioned by workflow identity, and the tested gateway permits workflow IDs to be provided externally.

## Security Impact

An attacker who can split related accesses across workflow identities may evade coalition-based inference protection.

## Limitations

This result was demonstrated with synthetic tools and a synthetic security policy. The current finance-agent Purpose Lock independently restricts calendar access. Production exploitability has not been established.

## Recommended Remediation

Implement trusted workflow assignment, authenticated agent identities, authorized membership, and coalition tracking based on the actual information-sharing boundary.

## Retest Criteria

Related accesses using different externally supplied workflow IDs must not bypass the protected coalition boundary.