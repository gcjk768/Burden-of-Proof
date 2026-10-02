# Decisions

Choices made while building Burden of Proof, and why. Newest first within each section.

## Architecture

**Sandbox: Linux namespaces now, Token Factory Sandboxes next; Serverless jobs dropped.** (2 Oct 2026)
Every build, test and scan runs through one `Runner` interface. The first implementation runs each
command in fresh user, PID and network namespaces (`unshare`), so it works without a Docker daemon,
including inside CI containers. With the network off, the command has no route anywhere. Token
Factory Sandboxes are the next implementation (milestone 5), because the Coding and Agentic
Engineering track names them and their checkpoint-and-branch model fits the proof and fix loop. The
low-level `contree-client` exposes `networking.enabled = false`, which starts the microVM with no
network interface. Nebius Serverless AI jobs were dropped from the plan. They are in preview, take
minutes to provision per job, have no way to disable networking, do not report exit codes, and need
a separately funded AI Cloud account.

**Each sandboxed command sees only what it needs.** (review, 2 Oct 2026) A multi-lens review found that
the first namespace runner cut the network but left the whole host filesystem readable, including the
project's `.env`. Commands now also get a mount namespace in which `bop.runner.jail` builds a fresh
root: system directories and the toolchain read-only, the snapshot and declared outputs read-write,
and empty tmpfs mounts for `/tmp` and `$HOME`. The runner refuses to start unless a probe confirms that
a host file outside the snapshot is invisible. The shared Maven repository is writable only during
the online prepare step and read-only for every offline build of untrusted code.

**Network only for dependency resolution.** The `prepare` step resolves every Maven dependency and
plugin with network on and records the baseline test results. Every later build runs Maven offline
(`-o`) with no network. Only an allowlist of environment variables reaches the sandbox, so no API key
or token is ever visible to code under test. Proxy variables are passed only when the network is on.

**SQLite through the standard library, not SQLAlchemy.** Fourteen small tables and simple queries do
not need an ORM, and one fewer dependency is one fewer thing to break during a hackathon.

**argparse, not Typer.** Same reason: four subcommands do not justify a dependency.

**IDs are scoped to the run.** Finding and group IDs come from the code, so they now carry a token
derived from the run ID. Without it, scanning the same repository twice collided on primary keys.

**The baseline is recorded offline.** Dependencies are resolved online, then the suite runs again in
the same offline sandbox that later judges patches. Tests that pass only with network access drop
out of the baseline instead of turning into false regressions. Loopback works inside the sandbox.
Projects with no tests get a throwaway test during prepare, so the JUnit provider is cached for
offline proof runs.

**Prepare runs the real lifecycle, not `dependency:go-offline`.** `go-offline` fails on projects with
artifacts outside Maven Central (hdiv/insecure-bank has one) and still misses plugins resolved during
the real build.

**One finding's failure stays with that finding.** Tool errors go back to the model as text. A failed
investigation marks its finding undetermined. Any unexpected exception marks the run failed, with a
traceback in `error.log`. Triage decisions are applied before any deep work, so a budget stop cannot
lose them, and the finding in flight is marked `stopped`.

**Every stage commits to SQLite before the next starts.** The run ledger (`llm_calls`, `runner_jobs`)
records every model call and sandbox job, so the dashboard and the cost panel are queries, not logs.

## Models

**Nemotron 3.5 Lightning is the main triage model; Nemotron 3 Nano is the comparison.** Same price,
four times the context, newer, and the model Nebius itself migrated to after the August 2026
retirements. Nano stays configurable for a side-by-side measurement.

**Thinking is off wherever the reply must be JSON.** All Nemotron 3 and 3.5 models reason by default
and the hidden reasoning counts against `max_tokens`, which truncates structured replies. Thinking is
switched per request with `chat_template_kwargs.enable_thinking`. It is off for triage and for the
verdict call, and on for Ultra's investigation and for Super writing tests and patches. `bop doctor
--live` reports reasoning tokens per model so the switch can be verified on the real endpoint.

**Ultra investigates in two steps.** First a tool-using investigation with thinking on, in plain text.
Then a short thinking-off call turns the notes into the verdict schema. This keeps JSON reliable
without giving up reasoning where it matters.

**Ultra falls back to Super.** On 404, 409, 5xx or a connection failure after the SDK's own retries,
the deep stage reruns on Super and the ledger records `fallback_from`. The catalog listed Ultra with
status "error" twice in September 2026.

**Per-role base URL overrides.** The global endpoint serves every model, but Nebius's own examples for
Super and Ultra use the us-central1 host, so each role can point at its own base URL.

**Unknown models are priced like Ultra.** A model missing from the price table must never count as
free in the budget.

## Scanning

**Our own Semgrep rules, under Apache-2.0.** The Semgrep engine is LGPL and fine to use, but the
registry rules are under the Semgrep Rules License, which forbids redistribution and offering them as
a service. The project ships `src/bop/rules/java-security.yaml` instead.

**Taint mode with method parameters as sources.** A first version matched string concatenation into
JDBC calls. It flagged the correct fix (a `PreparedStatement` whose SQL concatenates a constant table
name), so a correct patch would have been rejected as "introducing a new finding". Taint mode does not
flag constants or bound parameters, still flags values that are merely converted (a realistic false
positive for triage), and does not flag the normalise-then-check fix for path traversal. Semgrep CE
only sees one method at a time. Following values across files is the deep-analysis model's job.

**Our own fingerprints.** Semgrep CE's SARIF fingerprint is the literal string "requires login". A
finding's fingerprint is a hash of tool, rule, file and the normalised matched code, so it disappears
when the code is fixed and survives unrelated line shifts.

## Trust: what counts as proven, fixed or suppressed

**Proof is decided by code, never by a model.** A proof test counts only if Surefire reports an
assertion failure whose message contains `[BOP-PROOF]`. Compile errors, other exceptions, timeouts
and assertions without the marker do not count. The test must later pass on the patched code.

**A fix counts only if all three checks pass.** The proof test passes, every test that passed in the
baseline still passes, and a rescan no longer reports the finding and reports no new in-scope finding
in the files the patch touched. The recorded demo includes a patch that only adds `.normalize()`. That
silences the scanner, but the proof test still fails, so the patch is rejected.

**Rescans count duplicates.** Identical matches are told apart only by order, so fixing the first of two
identical lines used to shift the second into its fingerprint. A finding counts as gone when the
number of matches with its code drops by the number of group members.

**Patch policy.** The allowed-folder check runs on the resolved path, so `src/main/../test/...` is
refused, and the proof test is rewritten from its source before it judges each patch. Edits are exact
search-and-replace blocks that must match once. They may only touch
`src/main/`, may not add suppression comments or annotations, and may not change more than 80 lines.
A patch is applied all or nothing and rolled back byte for byte after each attempt.

**Proof test policy.** A test must live under `src/test/java` in the package it declares, contain the
marker, and avoid processes, sockets, URLs, `System.exit`, reflection tricks and sleeps.

**Evidence is checked against the checkout.** Every cited excerpt must appear in code (not comments) at
the cited lines, allowing three lines of slack and ignoring a copied line-number column. Unverifiable
evidence earns one retry. If it still fails, the verdict is kept but recorded as unverified, which
blocks any suppression. One bad excerpt no longer discards a whole triage batch.

**Suppression thresholds.** Triage may suppress a finding only as `likely_false_positive` with
confidence of at least 0.8 and verified evidence. Deep analysis may suppress only as `unreachable`
with confidence of at least 0.7 and verified evidence. Everything else goes deeper or is marked
undetermined for a human.

## Cost

**Estimate first, then ask.** After the scan and before any model call, `bop run` estimates the cost
of the run. Above `BOP_WARN_USD` (default 2 dollars) it stops and asks for `--yes`. `BOP_BUDGET_USD`
(default 5 dollars) is a hard cap checked before every uncached call.

**Responses are cached on disk by exact request, but only usable ones.** Truncated or empty replies are
not cached, and a reply that fails validation is removed. `bop doctor --live` never uses the cache.
If Ultra fails, the rest of the run stays on Super. Persistent 429s stop the run with a clear error. In development the cache is read-write. `BOP_CACHE=read`
replays only and refuses to spend.

## Testing

**Recorded model replies.** The end-to-end test and the offline demo use a scripted client that replays
realistic Nemotron-style replies. The replies include deliberate mistakes (a missing import, a search
string that does not match, a patch that only silences the scanner) so the feedback loops are
exercised against the real sandbox, Maven, Surefire and Semgrep.

**The sample app is small on purpose.** `tests/fixtures/tiny-java-app` has one SQL injection reachable
from an HTTP-style handler across three files, one path traversal, one false positive (an integer
parsed before it reaches SQL), constant SQL that must not be flagged, and one outdated library for the
dependency stage.

## Environment quirks

**Semgrep's version check is disabled.** Behind a proxy that blocks semgrep.dev, `semgrep --version`
took 98 seconds while it waited for the version check. Scans run offline, so they are unaffected.
