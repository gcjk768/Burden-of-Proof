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
a host file outside the snapshot is invisible.

**The jail uses `pivot_root` and drops every capability.** (verification, 2 Oct 2026) The verification
pass broke the first jail. It used `chroot`, and the command ran as root of its user namespace with
`CAP_SYS_CHROOT`, so a test that chrooted twice climbed back to the host root and could read and write
host files. The jail now moves the namespace onto the new root with `pivot_root` and detaches the old
one, so the host tree is no longer mounted anywhere the command can reach. Before `exec` it empties the
bounding, ambient, effective, permitted and inheritable capability sets. It sets and locks the
securebits that would hand root its capabilities back. It sets `no_new_privs` and closes stray file
descriptors. It confirms all of this through `/proc/self/status` and refuses to run the command if
anything differs. IPC and UTS namespaces are new too. Tests cover the double-chroot escape, the same
escape from a nested user namespace with full capabilities, and remounting a read-only path as
writable. Configuration files that `/etc` links elsewhere, such as `/etc/resolv.conf` pointing into
`/run` on systemd-resolved hosts, have their real file bound read-only too, or DNS fails on GitHub's
Ubuntu runners. The command's environment no longer travels in the jail's argument list, which any local
user can read, because a proxy URL can carry a password. The third verification pass noted that a read-only remount changes only the top mount, so a writable
mount nested under a bound toolchain path would stay writable. Read-only binds are now made read-only
recursively with `mount_setattr`, or mount by mount on kernels older than 5.12, and a test builds such a
nested mount to check both. Bubblewrap would do the same job. We kept our own short jail so the sandbox has no extra
system dependency and every step is tested here.

**Host-side code never follows links a build planted.** (2 Oct 2026) Builds run with the snapshot
writable, so the target's code can replace a file or directory with a symlink to a host path. Code
outside the sandbox that touches the snapshot afterwards treats it as hostile. Restoring a patched file
replaces a planted file link with a regular file instead of writing through it, and stops the run if a
parent directory now leads outside the snapshot. Surefire reports that are links are skipped. Proof
tests are written with `O_NOFOLLOW`. Reading tools and evidence checks already resolve every path and
refuse anything outside the snapshot. The third verification pass found four more places that followed
planted links: proof-test cleanup, the warm-up cleanup, clearing Surefire reports through a linked
`target/`, and the code window sent to the model. Every host-side delete under the snapshot now first
removes the first link on the way down (only the link itself), report parsing refuses any link between
the snapshot root and the report, and the code window and pom read are confined like every other read.
No build is running while this happens, because the jail kills all of its processes when its command
exits, so a link cannot be put back between the check and the delete.

**Network only for dependency resolution, and the project's tests never run online.** (verification,
2 Oct 2026) The `prepare` step compiles main and test code with network on, but runs only a throwaway
empty test class. Selecting it makes Surefire download the provider that matches the project's test
classpath, whatever the pom says. JUnit often arrives transitively through spring-boot-starter-test or a
parent pom, and the previous text check missed that. The project's own tests first run in the offline
baseline. Every later build runs Maven offline (`-o`) with no network. Only an allowlist of environment
variables reaches the sandbox, so no API key or token is ever visible to code under test. Proxy
variables are passed only when the network is on. One limit remains: build plugins that the project's
pom binds to the `test` lifecycle still run during the online step, in the host network namespace. The
hosted demo therefore runs only the curated sample repositories. A proxy that allows only Maven
repository hosts is the planned fix.

**Each target repository gets its own Maven repository.** (verification, 2 Oct 2026) The first design
shared one writable repository across runs, and the verification pass showed that a test running
during the online step could plant a file next to a JUnit jar that every later build of every
repository would load. Each target now resolves into `$BOP_HOME/m2/<name>-<hash of its path>`, which
is writable only during its own online step. A shared cache (`BOP_MAVEN_REPO`) is optional. When set,
it is mounted read-only and given to Maven 3.9 as the chained "tail" repository
(`maven.repo.local.tail`), so builds read from it and never write to it. The integration tests seed
their shared cache by building our own fixture directly, outside the sandbox.

**The warm-up reaches every module, and source checks are skipped for it.** (verification, 2 Oct
2026) Multi-module projects and projects with a licence-header check failed in prepare after the change
above. The modules that run Surefire are now read from the `<modules>` lists before any build, and each
gets the empty warm-up class. The online step skips licence-header, style and formatting checks (RAT,
license, Checkstyle, Spotless, PMD, SpotBugs and similar), which would reject the warm-up file. Their
plugins still resolve, and the offline baseline runs them on the project's own files. Baselines of
multi-module projects now include every module's tests. Proof tests are still written under the root
module, so proofs in multi-module projects are not supported yet.

**Surefire's detected provider decides the JUnit flavour.** The proof prompt now names JUnit 4 or 5 from
the provider Surefire reports ("Using auto detected provider ..."), with the pom text only as a fallback.

**SQLite through the standard library, not SQLAlchemy.** Fourteen small tables and simple queries do
not need an ORM, and one fewer dependency is one fewer thing to break during a hackathon.

**argparse, not Typer.** Same reason: four subcommands do not justify a dependency.

**IDs are scoped to the run, but models never see the scoped form.** Finding and group IDs come from
the code, so in the database they carry a token derived from the run ID. Without it, scanning the same
repository twice collided on primary keys. The verification pass found that putting the scoped ID in
prompts made every run's requests different, so the response cache never hit across runs and
`BOP_CACHE=read` replays failed. Prompts now carry the unscoped ID, and build output fed back to a model
has the run's work path removed. A test checks that two runs send identical requests.

**The baseline is recorded offline.** Dependencies are resolved online, then the suite runs for the
first time in the same offline sandbox that later judges patches. Tests that need network access fail
there and are left out of the baseline instead of turning into false regressions. Loopback works inside
the sandbox.

**Prepare runs the real lifecycle, not `dependency:go-offline`.** `go-offline` fails on projects with
artifacts outside Maven Central (hdiv/insecure-bank has one) and still misses plugins resolved during
the real build.

**One finding's failure stays with that finding.** Tool errors go back to the model as text. A failed
investigation marks its finding undetermined. Any unexpected exception marks the run failed, with a
traceback in `error.log`. Triage decisions are applied before any deep work, so a budget stop cannot
lose them, and the finding in flight is marked `stopped`. A stop during triage itself keeps the
batches that finished and marks the rest `stopped`. The forced conclusion after the last tool turn is
checked for truncation like any other turn, gets one retry, and otherwise leaves the finding
undetermined instead of passing half a sentence to the verdict step.

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

**Thinking-off requests also send `reasoning_effort: "none"`.** (2 Oct 2026) Other Token Factory users
report that `enable_thinking=false` alone has not always stopped Nemotron from reasoning, and that the
extra field did. We have not seen this first-hand yet. If the server ever rejects the field, the client
drops it for the rest of the run and retries the call. Every call's reasoning tokens are in the ledger,
and the report counts thinking-off calls that still reasoned. Reasoning text, whether the server returns
it in its own field or it leaks into the content as `<think>` tags, is kept in the analysis transcript
for audit and never shown to the next stage.

**A reply cut off at the token limit gets one retry with twice the tokens and thinking off.** Reasoning
that eats the token budget is the usual cause, so the retry turns thinking off as well. The cap is 32,768
tokens. If the retry is cut off too, the stage's own feedback loop handles it.

**Ultra investigates in two steps.** First a tool-using investigation with thinking on, in plain text.
Then a short thinking-off call turns the notes into the verdict schema. This keeps JSON reliable
without giving up reasoning where it matters.

**Ultra falls back to Super.** On 404, 409, 5xx or a connection failure after the SDK's own retries,
the deep stage reruns on Super and the ledger records `fallback_from`. Only 404 and 409 keep it on Super
for the rest of the run (see Cost). The catalog listed Ultra with
status "error" twice in September 2026.

**Per-role base URL overrides.** The global endpoint serves every model, but Nebius's own examples for
Super and Ultra use the us-central1 host, so each role can point at its own base URL.

**Unknown models are priced like Ultra.** A model missing from the price table must never count as
free in the budget.

## Scanning

**Benchmark numbers are measured, kept and labelled.** (2 Oct 2026) `bop bench owasp` scores the rules
on the OWASP Benchmark with our own scorer, and `--triage` scores them again after the real triage stage
with the real suppression rule. The first measurement is kept even though the rules changed afterwards.
The standard file and JDBC sinks added after looking at Benchmark misses are labelled as tuned on the
data they are scored on (`docs/benchmark.md`). The scoring SARIF drops suppressed results because the
Benchmark's own reader ignores SARIF suppressions.

**Any mention of `nosem` in a patch is refused.** (verification, 2 Oct 2026) Semgrep honours `nosem`
anywhere in a comment, so `// nosemgrep_ok`, `// NOSEMGREPPED`, `// nosemantic` and
`// reviewed: nosemgrep` all hide a match (checked with Semgrep 1.179). The patch policy now refuses any
`nosem`, case-insensitive. Markers are counted, so a search that already holds one cannot carry a new
one in. Fingerprints ignore any comment that mentions `nosem`. The rescan also counts a newly suppressed
match in an edited file, so a patch that slipped past the policy would still fail there.

**Findings the team already suppressed are recorded, not re-examined.** Semgrep keeps a match on a line
marked `nosemgrep` in its SARIF, with an in-source suppression (checked with Semgrep 1.179). Such
findings are stored with the state `suppressed_in_source` and skipped. A `nosemgrep` comment is removed
from the snippet before fingerprinting, so adding one does not change a finding's identity. Patches may
not add `nosemgrep` or its short form `nosem`.

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

**Rescans count duplicates, and check the finding's own line.** Identical matches are told apart only
by order, so fixing the first of two identical lines used to shift the second into its fingerprint. A
finding counts as gone when the number of matches with its code drops by the number of group members,
and no match with the same rule and code remains at the member's own line, followed through the patch.
The second rule catches a patch that removes a different identical line and leaves the reported one.

**Patch policy.** The allowed-folder check runs on the resolved path, so `src/main/../test/...` is
refused, and the proof test is rewritten from its source before it judges each patch. Edits are exact
search-and-replace blocks that must match once. A search text is tried as written first and with the
file's Windows line endings only if that finds nothing, so files with mixed endings can be patched. In a
file with only Windows line endings, the replacement gets them too. They may only touch
`src/main/`, may not add suppression comments or annotations, and may not change more than 80 lines.
A patch is applied all or nothing and rolled back byte for byte after each attempt.

**Proof test policy.** A test must live under `src/test/java` in the package it declares, contain the
marker, and avoid processes, sockets, URLs, `System.exit`, reflection tricks and sleeps. The location is
judged on the resolved path, and the file is written without following symlinks. Builds of the target's
code run between writes and could otherwise redirect the proof test into production code.

**Evidence is checked against the checkout.** Every cited excerpt must appear at the cited lines,
allowing three lines of slack and ignoring a copied line-number column when every line has one. Only
code counts. An excerpt copied exactly from a line that ends in a comment is accepted on its code part,
and the stored excerpt is that code part, so comments never become evidence. An excerpt with no real
code left once comments are removed is rejected. Comments are recognised in Java (text blocks
included), Kotlin, Groovy and JavaScript, in XML-like files, in SQL, and in properties, YAML and shell
files. Unverifiable evidence earns one retry. If it still fails, the
verdict is kept but recorded as unverified, which blocks any suppression. One bad excerpt never discards
a whole triage batch: if the retry comes back cut off, malformed, not at all, or stops at the budget
cap, the first reply is used. That reply passed every hard check and failed only the evidence check,
so it stays cached. After a budget stop the run still stops at its next model call. An excerpt counts
as code if any name or keyword is left once comments are removed, so `a = b;` is code. JavaScript,
TypeScript and Groovy files are not stripped of comments, because their template, regex and slashy
literals can contain `/*`. A copied line-number column is removed when every line after the first has
one, since copies often start partway through a line.

**Suppression thresholds.** Triage may suppress a finding only as `likely_false_positive` with
confidence of at least 0.8 and verified evidence. Deep analysis may suppress only as `unreachable`
with confidence of at least 0.7 and verified evidence. Everything else goes deeper or is marked
undetermined for a human.

## Cost

**Estimate first, then ask.** After the scan and before any model call, `bop run` estimates the cost
of the run. Above `BOP_WARN_USD` (default 2 dollars) it stops and asks for `--yes`. `BOP_BUDGET_USD`
(default 5 dollars) is a hard cap checked before every uncached call.

**Responses are cached on disk by exact request, every one of them.** (verification, 2 Oct 2026) The
first review asked us to skip truncated, empty and invalid replies. The verification pass showed why
that was wrong. A retry request embeds the rejected reply, so a replay needs that reply too, and a
`BOP_CACHE=read` replay even deleted recorded files. Now every parsed reply is cached and nothing is
removed in read mode. A bad reply cannot get stuck, because callers always answer it with a different
request (the reply plus feedback), and a replay walks the same conversation turn by turn. To draw fresh
replies, run with `BOP_CACHE=off` or clear the cache. `bop doctor --live` never uses the cache. In
development the cache is read-write. `BOP_CACHE=read` replays only and refuses to spend. Failures are
recorded too: when a model is unavailable, a marker is cached under the request, so a replay takes the
same fallback the recorded run took. `reasoning_effort` is left out of the cache key, because whether it
is sent depends on what the server accepted earlier in the run. Both were found by the third
verification pass, which also showed a reply that cannot be parsed skipped the ledger and the budget.
It is now recorded and charged for whatever usage it reports.

**Only a permanent failure moves a stage to its fallback model for the rest of the run.** A 404 (model
not found) or 409 (model stopped) after the SDK's retries keeps the deep stage on Super for the rest of
the run. A timeout (including an HTTP 408), connection error or 5xx sends only that one call to Super,
and the next call tries Ultra again. A persistent 429 stops the run with a clear error instead of switching models, because both
models draw on the same account limits.

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
