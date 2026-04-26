# Akashic — Study Guide

A textbook-style walkthrough of the Akashic codebase as of the
end of Phase 7 (OAuth 2.1 + OIDC implementation). Written for someone
who knows nothing about the code flow and wants to build a working
mental model from the ground up.

The guide assumes you've used the project a bit — you've run the
docker stack, you know it has a thing called "the akashic server"
and a thing called "the admin BFF" — but you don't yet have a
clear picture of *why* the code is shaped the way it is.

## Reading order

The chapters are designed to be read in sequence. Each one builds on
concepts from the previous chapter, so jumping ahead is possible but
will leave you reaching for the glossary in chapter 09.

| Chapter | Topic | Why it matters |
|---|---|---|
| [00 — Architecture Map](./00-architecture-map.md) | The 30,000-foot view: every container, every process, every network boundary | Without this you'll get lost in details |
| [01 — PKI and TLS](./01-pki-and-tls.md) | Vault, Vault Agent, certs, the trust chain, "TLS everywhere" | Everything else depends on this |
| [02 — Data and Dependencies](./02-data-and-deps.md) | Postgres, Redis, LDAP — what each one stores and how it's wired | The runtime services Akashic needs |
| [03 — The Akashic Server](./03-akashic-server.md) | Config system, logging, dual-server pattern, lifecycle | The Go code itself |
| [04 — Bootstrap Flow](./04-bootstrap.md) | How a fresh install becomes a usable IdP | The first-run path |
| [05 — The Admin BFF](./05-admin-bff.md) | Embedded React FE, mTLS to control plane, lazy init | The browser-facing surface |
| [06 — OAuth / OIDC](./06-oauth-oidc.md) | The protocol concepts, what we implemented, why each piece exists | Phase 7's core work |
| [07 — Login Flow Walkthrough](./07-login-flow-walkthrough.md) | A single browser request traced end-to-end through every component | Concrete grounding for chapter 06 |
| [08 — Deployment & Runtime](./08-deployment-and-runtime.md) | Container mode, host-akashic mode, the unified compose | How to run the project today |
| [09 — Reference & Glossary](./09-reference-glossary.md) | Terms, hostnames, ports, file paths, env vars | Lookup, not learning |

## How to use this guide

**If you're trying to understand the architecture top-down**: read 00,
then 01, 03, 06 in that order. You'll have the skeleton.

**If you're debugging a specific failure**: jump to chapter 07
(login-flow walkthrough) — it traces every step a request makes,
which is usually enough to identify which component is failing.

**If you're trying to set up the project on a new machine**: read 00,
08, then chapter 09's reference section.

**If you're going to extend the OAuth work in Phase 8**: read 06 and
07 thoroughly; they document the protocol decisions and the
implementation seams.

## Scope of this guide

This study guide covers the period from the end of **Phase 5** (TLS
everywhere — every dependency speaks TLS, all certs issued by Vault)
through the end of **Phase 7** (OAuth 2.1 + OIDC working end-to-end).
It does not cover:

- Phases 1–4 (basic server + config + logging + initial PKI). Some
  of that infrastructure is referenced because it's still in use, but
  a "from scratch" history is out of scope. See `doc/phase-{3,4}-plan.md`
  for that ground.
- Phase 8+ (tenant client registration, full admin dashboard,
  refresh tokens, etc.) — those are future work.

## A note on style

These chapters are deliberately written as if explaining the code to
a thoughtful colleague rather than as exhaustive reference docs. There
will be opinions about *why* the code is shaped a particular way, not
just descriptions of *what* it does. When the existing implementation
makes a non-obvious tradeoff, the chapter will name it.

Where a chapter says **"see the source"**, that's a hint to actually
open the file and read along — the prose explains the model, the
source confirms it.
