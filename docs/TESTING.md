# TESTING.md — the standard for this project

This is the definition of testing for the WINDOWS-SERVER security stack. It is enforced by
`agent-ops/bin/docs-check.sh`, by every role contract in `agent-ops/roles/`, and by the
definition of done in `AGENTS.md` §5.

---

## 1. Definition

> **A test consists of validated input, monitored and verified output, and independent confirmation.**
> Anything missing one of those three is not a test.

| Component | Required form here | How it is satisfied in this project |
|---|---|---|
| **Validated input** | Real artefacts whose correct answer is established *before* the run — plus deliberately invalid inputs | `C:\srv\rdp-guard\bans.json` (live state), synthetic boundary cases for the tier maths, the stale model id that actually broke a dispatch |
| **Monitored & verified output** | The actual output is captured and compared **field-by-field** with the expectation; mismatch = FAIL + diff | Exit codes, the `# model:` provenance stamp, JSON answers compared key-by-key to an independently computed ground truth, live artifacts re-read after a change |
| **Independent confirmation** | A second producer or method, independent of the author's assumptions | Different model family, a different harness (grok vs agy vs Codex), or an independent computation (python/node vs the JavaScript under test) |

## 2. Banned — and what it looks like when it happens

| Banned | Why | Real instance in this project |
|---|---|---|
| **Smoke test** | Proves a process exited, not that it is correct | Asking a model to "reply READY"; treating `HTTP 200` on the dashboard as proof the data was right; a permaban log line as proof the ban was *enforced* |
| **Stub functionality** | Ships a lie: success reported for work not done | A function returning `[]`/`0`/`""` on an error path so callers cannot tell "nothing found" from "I failed"; `# TODO` bodies; placeholder values in a data file |
| **Unverified assertion** | Claiming an outcome that was not observed | Writing "fixed" after editing without re-reading the live artifact; describing intent in the Verification field |
| **Self-confirmation** | The author agreeing with the author | Re-running the same check with the same wrong assumption; verifying your own code in your own session and calling that independent |

Two examples where the absence of this standard already cost us, both found by the review panel:

* The collector's own `bans.json` **state loader** silently degraded to "no bans" — which, in that
  code path, **deleted the firewall rule and released every banned attacker**. There was no test
  asserting the invariant "enforcement never shrinks on a bad read", so it shipped.
* The tier-blend logic **double-counted one hour and dropped ~22,000 attempts**, while the dashboard
  displayed 5,426 and looked entirely plausible. A smoke test ("does the dashboard load?") passes
  that bug happily. It took an independent reproduction (running the real functions with synthetic
  boundary data) to expose it.

**A security tool that renders confidently wrong numbers is worse than one that visibly fails.**

## 3. Required shape of a test in this project

```
TEST: <what invariant or behaviour is under test>
INPUT (validated): <the artefact / synthetic case, and how its correct answer was established>
EXPECTATION: <exact expected values>
PROCEDURE: <the command(s), captured verbatim>
OBSERVED: <the raw output, not a summary>
VERDICT: PASS | FAIL   <field-by-field comparison, diff on failure>
INDEPENDENT CONFIRMATION: <who/what else agrees and by what method>
NOT CONFIRMED: <what this test does not establish — never omit>
```

The **`NOT CONFIRMED`** line is mandatory. Declaring the limits of evidence is part of the test, not
an admission of weakness.

## 4. Choosing the verifying model — measured, not guessed

Verification must be performed by a *strong* model, and strength is taken from published benchmarks,
never from model names or vibes:

| Source | Role |
|---|---|
| **Artificial Analysis Intelligence Index v4.3.2** (`artificialanalysis.ai`) — Terminal-Bench 4.0, HLE, AA-Briefcase, GDPval-AA, SciCode, CritPt, AA-LCR | primary score |
| **BenchLM BenchAlign v5.8** (`benchlm.ai`) | independent cross-check; interpolation where AA has no reading |

The live table is `~/.agents/skills/agy-delegate/model-scores.tsv`, and
`~/.agents/skills/agy-delegate/scripts/deploy-agy.sh models` prints the catalogue ordered by it with
the basis for each entry (`measured` / `interpolated` / `unscored`).

**Current reading (2026-10-02): `claude-opus-5-5-high` 54 is the strongest model available to the
verifier role**, so `-m auto` resolves to it. If it is quota-exhausted, the dispatcher falls back and
**records the substitution in the report** — an unwritten substitution would silently downgrade the
evidence.

## 5. Minimum testing per change

| Change | Minimum required |
|---|---|
| Any edit to `rdp-guard.ps1` | A saved before/after of the affected invariant + a live run + independent review |
| Any edit to `collect.ps1` | Re-read `data.json` and compare computed aggregates to an independent calculation |
| Any edit to `index.html` | The page's functions executed against real data with synthetic boundary cases (not a browser "it loaded") |
| Any edit to `server.py` | A request matrix: what must be served, and what must be **404** |
| Firewall / exposure change | Verified from **outside** the host (port probe), not only from the local config |
| Documentation-only change | `docs-check.sh` must exit 0; no behavioural claim may be made |

## 6. Enforcement

```bash
bash agent-ops/bin/docs-check.sh      # exit 0 = the turn may be declared done
```

It checks the artifacts a compliant turn must leave behind: the doc set exists, the journal has an
entry for today carrying the three testing components, every review report carries a verdict, every
ADR carries its four sections, no stub markers exist in shipped files, and no documentation has been
placed in the HTTP-served directory.
