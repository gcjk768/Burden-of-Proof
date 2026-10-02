# Burden of Proof

**Security scanners bury teams in findings, and most are noise. Burden of Proof makes every finding prove itself before anyone spends time on it.**

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![NVIDIA Nemotron](https://img.shields.io/badge/NVIDIA-Nemotron-76B900?logo=nvidia&logoColor=white)](https://github.com/nebius/token-factory-cookbook/tree/main/models/nemotron)
[![Nebius Token Factory](https://img.shields.io/badge/Nebius-Token%20Factory-052B42)](https://tokenfactory.nebius.com/)
[![Status: design](https://img.shields.io/badge/status-design%20stage-F59E0B)](#status)

An agent for application security and DevSecOps engineers in regulated organizations. It takes the findings from Semgrep and OWASP Dependency-Check on a Java repository, and for each one it:

1. decides whether it is real, citing file paths and line numbers as evidence,
2. writes a JUnit test that fails while the weakness is present,
3. writes the smallest patch that makes that test pass without breaking the build,
4. opens a merge request with the evidence, or records an auditable suppression for a false positive.

Every model call goes to open NVIDIA Nemotron models on Nebius Token Factory, and every build and test runs in a Token Factory Sandbox with no network access.

> [!NOTE]
> **Status: design stage.** Nothing is built yet. The diagram below is the proposed architecture, and it will change as the work lands.

## Architecture

<p align="center">
  <a href="docs/architecture.drawio.svg">
    <img src="docs/architecture.drawio.svg" width="100%" alt="Burden of Proof architecture. Inputs on the left: an AppSec engineer running the CLI, a GitLab CI job, and the target Java repository. In the middle, the agent runs eight numbered stages: ingest, normalize and group, triage, analyze, prove, fix, upgrade dependencies, and report. Each stage connects to what it uses on the right: Token Factory Sandboxes for running code, Nemotron 3.5 Lightning for triage, Nemotron 3 Ultra for cross-file analysis, Nemotron 3 Super for proof tests and patches, Tavily and OSV for advisories, and GitLab for merge requests. Along the bottom: a dashboard, an LLM gateway, and SQLite storage.">
  </a>
</p>

How to read it:

- **Each numbered stage points at exactly what it uses.** Green means an NVIDIA Nemotron model on Token Factory. Amber means code runs in a Token Factory Sandbox. Grey means plain Python or a public API.
- **The models are chosen per stage.** The cheap, fast model handles volume, the 1M-token model reads whole modules, and the strongest coder writes tests and patches.
- **Proof is decided by code, not by a model.** A finding counts as proven only when its test fails before the fix and passes after it. A fix counts only when the full test suite and a rescan also pass.

The diagram is a draw.io file. Open [`docs/architecture.drawio.svg`](docs/architecture.drawio.svg) in [diagrams.net](https://app.diagrams.net/) or the VS Code Draw.io Integration extension to edit it. The SVG carries its own source, so saving it updates the image this page shows.

## How Nemotron and Token Factory are used

| Stage | Model on Token Factory | Why this model | Thinking |
|---|---|---|---|
| Triage | `nvidia/Nemotron-3_5-Lightning` | Fast and inexpensive for the bulk of findings, with a 1M-token context | Off, schema-constrained JSON |
| Cross-file analysis | `nvidia/Nemotron-3-Ultra-550b-a55b` | Reads whole modules in its 1M-token context to trace input to sink | On while investigating, then off to emit the verdict |
| Proof tests, patches, upgrades | `nvidia/nemotron-3-super-120b-a12b` | Strong code generation at moderate cost; takes over when Ultra is unavailable | Low |
| Triage comparison | `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` | Side-by-side baseline against Lightning | Off |

- **Inference.** Calls go through the OpenAI Python SDK to `https://api.tokenfactory.nebius.com/v1/` with `NEBIUS_API_KEY`. Model IDs come from environment variables and are checked against the public Token Factory catalog at startup.
- **Sandboxes.** Each run resolves Maven dependencies once into a sandbox checkpoint. Every proof test and patch attempt then runs in a disposable branch of that checkpoint, with no network interface.
- **Cost.** Every call is recorded with its model, tokens and cost. The dashboard shows spend per model and stage, and runs stop at a budget cap.
- **Licences.** Nemotron 3 Nano and Super are released under the NVIDIA Open Model License. Nemotron 3.5 Lightning and Nemotron 3 Ultra are released under OpenMDW-1.1.

## Status

| Week | Goal |
|---|---|
| 1 (to 11 Oct) | Skeleton, Token Factory client with routing and cost tracking, scanner ingest, first finding through the whole loop |
| 2 (to 18 Oct) | Sandboxes runner, deep analysis on Ultra, full loop on a deliberately vulnerable Java app, first triage benchmark numbers |
| 3 (to 25 Oct) | Dependency upgrades with Tavily and OSV, GitLab merge requests, dashboard, final benchmark numbers |
| 4 (to 29 Oct) | Hosted demo with sample mode, documentation, demo video |

Setup and run instructions will be added with the first working slice.

## Credits

Brand logos are trademarks of their owners and are used only to identify the products. Brand icons come from [Simple Icons](https://simpleicons.org/) (CC0-1.0) and from the Semgrep, OSV, Tavily and Nebius repositories. Generic icons come from [Material Design Icons](https://pictogrammers.com/library/mdi/) (Apache-2.0).

## Licence

Apache-2.0. The licence file will be added with the project skeleton.
