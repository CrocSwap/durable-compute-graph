# Security policy

DCG (Durable Compute Graph) is alpha software. It runs on Fogo testnet only,
and its formats may change before beta. Do not use it to hold value on
mainnet.

## Reporting a vulnerability

Report vulnerabilities privately to **security@crocodilelabs.io**, or through
a GitHub private security advisory on this repository. Please don't open a
public issue, pull request or discussion for a suspected vulnerability.

Include:
- the affected component: the program and instruction or tag, the Python
  client or sequencer, the commit or deployed image hash, and the program
  address;
- what an attacker can do: take or lock funds or bonds, win or block a
  dispute they should not, corrupt or skip session state, or deny service;
- steps to reproduce, ideally a test against `solana-program-test` or a
  testnet transaction signature;
- whether you have shared it with anyone else.

## What happens next

- **Within 3 business days:** we acknowledge your report.
- **Within 10 business days:** we tell you whether we confirm it, how severe
  we judge it to be, and our plan.
- **We keep you informed** as the fix progresses, and credit you in the
  advisory unless you ask us not to.

## Disclosure window

We ask for a **90-day disclosure window**, starting from your report.
- We publish an advisory once a fix is deployed to the shared testnet
  program and released, or when 90 days pass, whichever comes first.
- If a fix needs longer, we will ask you before the window ends and explain
  why.
- If a vulnerability is being actively exploited, we may disclose sooner,
  and we will tell you first.

## Scope

**In scope:**
- the DCG on-chain program in this repository: consensus-mode sessions,
  optimistic disputes (tag 227), admission and templates, bonds, settlement
  and closes;
- the Python packages (tracing, client, sequencer);
- the image deployed on the shared Fogo testnet program.

**Out of scope:**
- features documented as testnet-only or experimental: the v2.0 trace path
  (tags 208–226) and features marked "TEST IMAGES ONLY";
- the Fogo chain, validators and RPC infrastructure;
- denial of service that only costs the attacker their own fees or rent;
- applications built on DCG, unless the flaw is in DCG itself.

**Known limits:** the release notes and the design documents list the alpha's
known limits. For example, the optimistic mode needs an honest watcher, and
templates are trusted from whoever sealed them. These are not
vulnerabilities, but a way to exploit one beyond its documented effect is.

## Breaking changes and upgrades

Separately from security fixes:
- every release records its changes in the changelog and in GitHub
  releases;
- the shared testnet program is upgraded only with at least one week's
  notice, except for security fixes;
- every format change comes with a migration note.
