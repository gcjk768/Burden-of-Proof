# Benchmark results

Every number here was measured with the command shown, on the commit shown. Nothing is estimated or
rounded up. Weak results stay in.

## OWASP Benchmark for Java, raw scanner (no triage)

Measured on 2 Oct 2026 with:

```bash
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git
bop bench owasp BenchmarkJava
```

- Benchmark: BenchmarkJava commit `8b67a88d73b2594570fc21150705283de884620b`, `expectedresults-1.2.csv`.
- Scanner: Semgrep 1.179.0 with this project's `java-security.yaml`, 819 results across 2,740 test files.
- Scoring: per test case and category, by our own scorer (`src/bop/bench/owasp.py`). A case counts as
  flagged when any result in its file maps to that category. The Benchmark score is the true positive
  rate minus the false positive rate.

| Category | Cases | TP | FP | TN | FN | Precision | Recall | FPR | Benchmark score |
|---|---|---|---|---|---|---|---|---|---|
| SQL injection (CWE-89) | 504 | 240 | 194 | 38 | 32 | 0.553 | 0.882 | 0.836 | +0.046 |
| Path traversal (CWE-22) | 268 | 91 | 84 | 51 | 42 | 0.520 | 0.684 | 0.622 | +0.062 |

What this says:

- **The raw rules are close to guessing.** They flag most real cases and most safe ones too, so the
  Benchmark score is barely above zero. That is by design. The rules are deliberately broad taint rules,
  and triage is the step meant to remove the false positives. The table after triage will be the same
  scan, scored the same way.

## The same, after adding standard sinks found through Benchmark misses

The first table showed recall gaps from sinks the rules did not list. Of the 42 missed path traversal
cases, 19 wrote through `FileOutputStream`, 11 put the untrusted value in the directory part of
`new File(dir, name)`, and 5 used the one-argument `Paths.get`. Of the 32 missed SQL injection cases, 11
used Spring's `queryForRowSet`. These are standard JDK and Spring APIs that real applications use, so
the rules now cover them: `FileOutputStream`, `FileReader`, `FileWriter`, `RandomAccessFile`, either part
of `new File` and `Paths.get` and `Path.of`, and `queryForRowSet`, `queryForStream`, `queryForInt`,
`queryForLong` and `createSQLQuery`. This change was made after looking at Benchmark misses, so it is
tuned on the same data it is scored on. Both tables stay on this page for that reason.

Measured on 2 Oct 2026 with the same command, Benchmark commit and Semgrep version: 902 results.

| Category | Cases | TP | FP | TN | FN | Precision | Recall | FPR | Benchmark score |
|---|---|---|---|---|---|---|---|---|---|
| SQL injection (CWE-89) | 504 | 251 | 198 | 34 | 21 | 0.559 | 0.923 | 0.853 | +0.069 |
| Path traversal (CWE-22) | 268 | 125 | 118 | 17 | 8 | 0.514 | 0.940 | 0.874 | +0.066 |

Recall went up, mostly for path traversal (0.684 to 0.940). The false positive rate went up as well, so
the Benchmark score barely moved. The remaining misses come from taint the engine loses between methods
and through collections, which Semgrep CE does not follow. The rules are now broader still, and triage
has more to remove.

Not done yet:

- **The triage run**, which needs a Token Factory key. It is ready to go:

  ```bash
  bop bench owasp BenchmarkJava --triage --estimate-only   # prints the estimate, calls no model
  bop bench owasp BenchmarkJava --triage                   # triages every finding, scores before and after
  ```

  The estimate for the first scan's 819 results was about $0.30 with Nemotron 3.5 Lightning, at the fallback prices
  in the code, because the catalog was unreachable from the build environment. A finding is dropped from
  the "after" score exactly when a normal run would suppress it at triage: verdict
  `likely_false_positive`, confidence of at least 0.8, and evidence that verified against the code. The
  command also writes `scoring.sarif` without the suppressed results, for BenchmarkUtils.
- **A cross-check** of these numbers with the Benchmark's own BenchmarkUtils scorecard.
