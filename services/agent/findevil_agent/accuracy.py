"""Pure ground-truth accuracy-scoring core — the single source of truth.

This module holds the *domain logic* for grading a finished Case against a curated
ground-truth golden: recall, precision/F1, hallucination rate, verdict consistency,
planted-bait detection, and negative-assertion coverage. It is offline and
read-only — it reads a case directory's ``verdict.json`` and a matching
``goldens/<id>/expected-findings.json`` and returns a plain report dict. It never
touches the sealed audit chain and is never part of the investigation pipeline.

Two callers share this one core (no logic fork):

  * ``scripts/score-recall.py`` — the hyphenated maintainer/grading CLI, which
    imports :func:`score` (and the resolver helpers) and adds only the CLI/printing
    layer; and
  * the ``accuracy_compare`` MCP shim — a read-only, audit-chained *diagnostic*
    tool. It is NOT a Finding: per CLAUDE.md, optional automation/scoring sidecars
    are never evidence and never create Findings, so the shim appends only a
    non-Finding ``accuracy_diagnostic`` audit record.

Matching: an expected finding is RECALLED when some run finding covers enough of
its distinctive description/artifact-hint tokens (coverage over the expected token
set, not symmetric Jaccard, so a verbose-but-correct run finding still matches a
concise ground-truth claim). MITRE technique is deliberately not a match shortcut.

Precision: a run finding matched to no expected claim is ``extra``. On an
``exhaustive`` (closed-world) key every extra is a false positive; on an open-world
key an extra is only PROVABLY wrong when it asserts a planted ``anti_fact``, a
``known_negative`` (benign IOC-lookalike), or a ``named_claim_denylist`` term.

Negative-assertion coverage: of the negative assertions a correct run must AVOID
(every ``anti_fact`` / ``known_negative`` / denylisted name in the key), how many
did the run correctly stay away from. 100% coverage means zero planted-bait
hallucinations.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# A run finding matches an expected one when it COVERS this fraction of the
# expected finding's distinctive tokens. Recall asks "did the run surface this
# ground-truth claim?" — so we normalize the overlap by the expected token set,
# not by the union (symmetric Jaccard unfairly penalizes verbose run findings
# that fully state the claim and then add caveats). Set at 0.5 so a match needs the
# *distinctive* tokens of the claim, not just shared generic DFIR vocabulary
# (email/host/http) that a semantically-unrelated finding can accumulate to ~0.4.
MATCH_COVERAGE = 0.5
# Floor on absolute shared tokens so a tiny expected set can't match on one or
# two generic words that survived stopword removal.
MATCH_MIN_SHARED = 3

# Tokens with no discriminating power for DFIR finding descriptions.
_STOPWORDS = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "has",
        "have",
        "in",
        "into",
        "is",
        "it",
        "its",
        "of",
        "on",
        "or",
        "that",
        "the",
        "to",
        "via",
        "with",
        "within",
        "shows",
        "show",
        "indicates",
        "indicating",
        "evidence",
        "artifact",
        "artifacts",
        "file",
        "files",
        "entry",
        "entries",
        "consistent",
        "suspicious",
        "recent",
        "recently",
    ]
)

# Verdict words the product emits, grouped by polarity. NEUTRAL is handled
# separately: a neutral run matches only a neutral golden (see
# _verdict_consistent). Goldens use the same vocabulary as verdict.json.
_EVIL_WORDS = frozenset({"CONFIRMED_EVIL", "SUSPICIOUS", "SUSPICION", "EVIL"})
_BENIGN_WORDS = frozenset({"NO_EVIL", "BENIGN"})
_NEUTRAL_WORDS = frozenset({"UNKNOWN", "INDETERMINATE"})


def _tokens(*parts: str | None) -> set[str]:
    text = " ".join(p for p in parts if p).lower()
    return {t for t in re.findall(r"[a-z0-9]+", text) if t not in _STOPWORDS and len(t) > 2}


def _coverage(expected: set[str], candidate: set[str]) -> tuple[float, int]:
    """How much of the expected token set the candidate covers.

    Returns (coverage_fraction, shared_count). Normalizing by the expected set
    (not the union) makes a verbose-but-correct run finding match a concise
    ground-truth claim.
    """
    if not expected or not candidate:
        return 0.0, 0
    shared = len(expected & candidate)
    return shared / len(expected), shared


def newest_case_dir() -> Path | None:
    root = Path("tmp/auto-runs")
    if not root.is_dir():
        return None
    cases = [d for d in root.iterdir() if d.is_dir() and (d / "verdict.json").is_file()]
    return max(cases, key=lambda d: d.stat().st_mtime) if cases else None


def resolve_golden(case_dir: Path, override: str | None) -> Path | None:
    """Find the expected-findings.json for this case.

    Order: explicit override, then goldens/<verdict.case_id>, then a goldens dir
    whose name is a substring of the case dir name (handles auto-<uuid> dirs that
    record their logical case_id inside verdict.json).
    """
    if override:
        p = Path(override)
        cand = p if p.is_file() else p / "expected-findings.json"
        return cand if cand.is_file() else None

    goldens = Path("goldens")
    verdict = case_dir / "verdict.json"
    if verdict.is_file():
        try:
            cid = json.loads(verdict.read_text(encoding="utf-8")).get("case_id")
        except json.JSONDecodeError:
            cid = None
        if cid:
            cand = goldens / str(cid) / "expected-findings.json"
            if cand.is_file():
                return cand
    if goldens.is_dir():
        name = case_dir.name
        for sub in sorted(goldens.iterdir()):
            cand = sub / "expected-findings.json"
            if cand.is_file() and (sub.name in name or name in sub.name):
                return cand
    return None


def _verdict_consistent(run_verdict: str | None, golden_verdict: str | None) -> bool:
    """Honest verdict consistency — deliberately ASYMMETRIC.

    The product's three verdict words carry an epistemic polarity: EVIL
    (CONFIRMED_EVIL/SUSPICIOUS), BENIGN (NO_EVIL), NEUTRAL (INDETERMINATE/UNKNOWN).

    Rules, in order:
      1. A NEUTRAL *run* verdict matches only a NEUTRAL *golden*. INDETERMINATE
         used to be accepted against any key, on the grounds that we never punish
         honest uncertainty — but INDETERMINATE is also exactly what a tool
         failure emits, which made this check a near no-op: in the 2026-07-28
         aggregate three of the four "passing" goldens ended INDETERMINATE,
         nitroba included, against a CONFIRMED_EVIL key. A key that asserts a
         definite answer is not satisfied by a run that never reached one.
      2. Once the run makes a *definite* call (EVIL or BENIGN), a NEUTRAL *golden*
         means the case was authored to expect uncertainty — so the definite call
         is over/under-confident and FAILS. This is what makes a false-positive
         control (e.g. alihadi-09 "Encrypt Them All", golden INDETERMINATE) bite:
         a run that escalates to CONFIRMED_EVIL/SUSPICIOUS is wrong.
      3. Otherwise the polarity must agree.
    """
    rv = (run_verdict or "").upper()
    gv = (golden_verdict or "").upper()
    if rv in _NEUTRAL_WORDS:
        return gv in _NEUTRAL_WORDS
    if gv in _NEUTRAL_WORDS:
        return False
    if rv in _EVIL_WORDS and gv in _EVIL_WORDS:
        return True
    if rv in _BENIGN_WORDS and gv in _BENIGN_WORDS:
        return True
    return rv == gv


def _run_completed(verdict_doc: dict[str, Any]) -> tuple[bool, list[str]]:
    """Did the run finish its work, or fall over on the way?

    Deliberately mirrors the ENGINE's own model of failure rather than inventing a
    stricter one, because "any tool call that errored" is not what the engine means
    by a failed run:

      * ``heartbeat.terminated_partial`` is the HEARTBEAT terminator saying it gave
        up mid-case. That is the engine's own "I stopped".
      * A guardrail rejection is recorded as ``{"error": ..., "rejected": True}``
        (find_evil_auto.py:9361) — the bridge refusing an out-of-scope tool request.
        That is the guardrail WORKING, not the run breaking, so ``rejected`` calls
        are excluded.
      * ``_record_tool`` (find_evil_auto.py:9234) resets the consecutive-failure
        streak on ANY successful call: "a single transient error never trips the
        HEARTBEAT escalation". So a failure with a later success after it is one the
        engine recovered from; only a TRAILING unrecovered failure means the run
        stopped on it. We mirror that streak here rather than re-deriving it.

    This gates ONLY the zero-expected recall shortcut in :func:`score`. A
    true-negative golden must be scored on the run having actually established the
    negative, not on it having crashed before it could assert anything — but those
    same two controls are what catch over-claiming, so a false FAIL here makes them
    unusable rather than merely wrong.
    """
    reasons: list[str] = []
    heartbeat = verdict_doc.get("heartbeat") or {}
    if heartbeat.get("terminated_partial"):
        reasons.append("heartbeat terminated the case partway (terminated_partial)")
    # Walk the calls the way the engine walks its own streak: any success clears
    # what came before it, so what survives to the end is the unrecovered tail.
    unrecovered: list[str] = []
    for tc in verdict_doc.get("tool_calls") or []:
        if not tc.get("error"):
            unrecovered.clear()
        elif not tc.get("rejected"):
            unrecovered.append(str(tc.get("tool") or "unnamed tool"))
    if unrecovered:
        reasons.append(
            "tool call(s) failed with no later success: " + ", ".join(sorted(set(unrecovered)))
        )
    return not reasons, reasons


def _is_eligible(expected: dict[str, Any], rf: dict[str, Any]) -> bool:
    """Can this run finding satisfy this expected finding?

    Eligibility is purely description-content overlap: the run finding must cover
    enough of the expected finding's distinctive tokens. MITRE technique is
    deliberately NOT a shortcut here — in cases where every finding shares one
    technique (e.g. all T1071.001), a MITRE match would make any finding eligible
    for any claim and inflate recall. Content overlap is the honest signal.
    """
    exp_tokens = _tokens(expected.get("description"), expected.get("artifact_hint"))
    cov, shared = _coverage(exp_tokens, _tokens(rf.get("description"), rf.get("artifact_path")))
    return shared >= MATCH_MIN_SHARED and cov >= MATCH_COVERAGE


def _max_matching(
    expected: list[dict[str, Any]], run_findings: list[dict[str, Any]]
) -> dict[int, int]:
    """Maximum bipartite matching (Kuhn's algorithm): expected_idx -> run_idx.

    A run finding may back at most one expected claim (no double-counting), and we
    find the assignment that covers the *most* expected claims — so neither greedy
    order nor a shared MITRE technique can under- or over-count recall.
    """
    adj: list[list[int]] = [
        [j for j, rf in enumerate(run_findings) if _is_eligible(exp, rf)] for exp in expected
    ]
    run_to_exp: dict[int, int] = {}

    def _augment(i: int, seen: set[int]) -> bool:
        for j in adj[i]:
            if j in seen:
                continue
            seen.add(j)
            if j not in run_to_exp or _augment(run_to_exp[j], seen):
                run_to_exp[j] = i
                return True
        return False

    for i in range(len(expected)):
        _augment(i, set())
    return {i: j for j, i in run_to_exp.items()}


def _negative_coverage(
    violations: list[dict[str, Any]],
    denylist_hits: list[dict[str, Any]],
    anti_facts: list[dict[str, Any]],
    known_negatives: list[dict[str, Any]],
    named_denylist: list[str],
) -> dict[str, Any]:
    """Negative-assertion coverage: did the run AVOID every planted-bait claim?

    The golden declares negative assertions a correct run must never make:
    ``anti_fact`` claims (false for this case), ``known_negative`` benign
    IOC-lookalikes, and a ``named_claim_denylist`` of terms (named malware /
    technique phrases) that must not appear in any finding. ``coverage_percent`` is
    the fraction of those negative-assertion controls the run respected; 100% means
    zero planted-bait hallucinations. ``clean`` is True iff the run asserted none.
    """
    anti_fact_violations = sum(1 for v in violations if v.get("violation") == "anti_fact")
    known_negative_violations = sum(1 for v in violations if v.get("violation") == "known_negative")
    denylist_terms_asserted = len(
        {term for hit in denylist_hits for term in (hit.get("terms") or [])}
    )

    anti_fact_total = len(anti_facts)
    known_negative_total = len(known_negatives)
    denylist_total = len(named_denylist)
    controls_total = anti_fact_total + known_negative_total + denylist_total

    # Respected controls: a control is "asserted" (violated) when the run makes the
    # forbidden claim. We cap each violation class at its declared total so a single
    # finding tripping multiple denylist terms can't push coverage negative.
    af_bad = min(anti_fact_violations, anti_fact_total)
    kn_bad = min(known_negative_violations, known_negative_total)
    dl_bad = min(denylist_terms_asserted, denylist_total)
    asserted = af_bad + kn_bad + dl_bad
    respected = controls_total - asserted

    # No declared negative controls -> vacuously full coverage (nothing to avoid).
    coverage_percent = 100 if controls_total == 0 else round(respected * 100 / controls_total)

    return {
        "controls_total": controls_total,
        "controls_respected": respected,
        "coverage_percent": coverage_percent,
        "clean": asserted == 0,
        "anti_fact_total": anti_fact_total,
        "anti_fact_violations": anti_fact_violations,
        "known_negative_total": known_negative_total,
        "known_negative_violations": known_negative_violations,
        "denylist_terms_total": denylist_total,
        "denylist_terms_asserted": denylist_terms_asserted,
    }


def score(case_dir: Path, golden_path: Path) -> dict[str, Any]:
    """Grade a finished Case directory against a ground-truth golden.

    Reads ``case_dir/verdict.json`` and ``golden_path`` and returns a plain report
    dict with recall, precision/F1, hallucination rate, verdict consistency,
    planted-bait findings, negative-assertion coverage, and a ``pass`` flag.
    Offline and read-only; never touches the audit chain.
    """
    verdict_doc = json.loads((case_dir / "verdict.json").read_text(encoding="utf-8"))
    golden = json.loads(golden_path.read_text(encoding="utf-8"))

    run_findings: list[dict[str, Any]] = verdict_doc.get("findings") or []
    expected: list[dict[str, Any]] = golden.get("findings") or []

    assignment = _max_matching(expected, run_findings)  # expected_idx -> run_idx (1:1)
    matched: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    for i, exp in enumerate(expected):
        record = {
            "finding_id": exp.get("finding_id"),
            "description": exp.get("description"),
            "mitre_technique": exp.get("mitre_technique"),
        }
        if i in assignment:
            record["matched_run_finding_id"] = run_findings[assignment[i]].get("finding_id")
            matched.append(record)
        else:
            unmatched.append(record)

    expected_n = len(expected)
    recalled_n = len(matched)

    run_verdict = verdict_doc.get("verdict")
    golden_verdict = golden.get("verdict")
    verdict_match = _verdict_consistent(run_verdict, golden_verdict)
    run_completed, run_incomplete_reasons = _run_completed(verdict_doc)

    # An empty golden (synthetic-benign / -decoy) says "there is nothing to find
    # here" — it does NOT say "nothing went wrong". Scoring recall 100 on
    # expected_n == 0 unconditionally is what let a run that produced nothing at
    # all pass two goldens in the 2026-07-28 aggregate: it errored out, emitted
    # zero findings and INDETERMINATE, and scored a perfect recall for it. So the
    # shortcut now requires the run to have actually established the negative —
    # finished without a tool failure AND reached the verdict the key asked for.
    # Zero-expected is still not an automatic fail: a clean, complete,
    # correctly-verdicted run on a true-negative case scores 100, as it should.
    if expected_n:
        recall_percent = round(recalled_n * 100 / expected_n)
    else:
        recall_percent = 100 if (run_completed and verdict_match) else 0

    # A stub golden (e.g. sans-starter, status pending_manual_walkthrough) carries
    # `min_recall_percent: null`. int(None) is a TypeError with no case name in it;
    # say which key is unscoreable instead. No default threshold is invented — a
    # stub is not a bar the run can clear.
    raw_min_recall = golden.get("min_recall_percent", 0)
    if raw_min_recall is None:
        raise ValueError(
            f"golden '{golden.get('case_id') or golden_path.parent.name}' has "
            f"min_recall_percent: null ({golden_path}) — it is an unpopulated stub, "
            "not a scoreable answer key. Populate min_recall_percent (and findings) "
            "before scoring a run against it."
        )
    min_recall = int(raw_min_recall)

    # --- False-positive / precision side -------------------------------------
    # Recall asks "did the run surface the ground truth?"; precision asks "did it
    # over-claim?". A run finding matched to no expected claim is `extra`. Whether
    # an extra finding is a false positive depends on the key:
    #   - exhaustive (closed-world) key  -> every extra is a false positive;
    #   - open-world key                 -> an extra is only PROVABLY wrong when it
    #     matches a planted `anti_fact` (a claim that is false for this case) or a
    #     `known_negative` (a benign IOC-lookalike a correct run must not assert),
    #     because the key may simply omit a real finding the run legitimately made.
    exhaustive = bool(golden.get("exhaustive", False))
    anti_facts = golden.get("anti_facts") or []
    known_negatives = golden.get("known_negatives") or []

    matched_run_idx = set(assignment.values())
    extra: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    for j, rf in enumerate(run_findings):
        if j in matched_run_idx:
            continue
        entry = {
            "finding_id": rf.get("finding_id"),
            "description": rf.get("description"),
        }
        if any(_is_eligible(spec, rf) for spec in anti_facts):
            entry["violation"] = "anti_fact"
            violations.append(entry)
        elif any(_is_eligible(spec, rf) for spec in known_negatives):
            entry["violation"] = "known_negative"
            violations.append(entry)
        extra.append(entry)

    # Planted-bait: terms a correct run must NEVER assert for this case (benign
    # IOC-lookalikes / named malware like "mimikatz" or "cobalt strike"). Scanned
    # across ALL run findings (a denylisted claim is wrong whether or not the
    # finding also matched an expected claim), substring + case-insensitive.
    named_denylist = [str(t).lower() for t in (golden.get("named_claim_denylist") or [])]
    denylist_hits: list[dict[str, Any]] = []
    for rf in run_findings:
        desc = (rf.get("description") or "").lower()
        terms = sorted({t for t in named_denylist if t and t in desc})
        if terms:
            denylist_hits.append(
                {
                    "finding_id": rf.get("finding_id"),
                    "description": rf.get("description"),
                    "violation": "named_claim_denylist",
                    "terms": terms,
                }
            )

    # Planted-bait failures = anti_fact / known_negative assertions plus any
    # denylisted-term assertion; deduped per finding for the headline count.
    planted_bait = violations + denylist_hits
    fp_planted = len({(e.get("finding_id"), e.get("description")) for e in planted_bait})

    extra_n = len(extra)
    total_run = len(run_findings)
    precision_scored = (
        exhaustive or bool(anti_facts) or bool(known_negatives) or bool(named_denylist)
    )
    false_positives = extra if exhaustive else violations
    fp_n = len(false_positives)

    # Zero denominator means UNMEASURED, not perfect. A run that matched no claim
    # and asserted nothing provably wrong has no precision to report, and a run
    # with no findings at all has no hallucination rate — reporting 1.0 / 0.0 there
    # is what made every failing zero-finding row print `prec=100 halluc=0.0`.
    # None is deliberate: it forces every reader to render "n/a" rather than a
    # number that looks like a perfect score.
    precision_denom = recalled_n + fp_n
    precision_frac = recalled_n / precision_denom if precision_denom else None
    precision_percent = None if precision_frac is None else round(precision_frac * 100)
    # Derived from recall_percent so this function carries ONE definition of
    # recall: on a zero-expected golden that is the completed-and-verdict-matched
    # decision above, not an unconditional 1.0 contradicting it.
    recall_frac = recall_percent / 100 if expected_n == 0 else recalled_n / expected_n
    if precision_frac is None:
        f1 = None
    else:
        pr_sum = precision_frac + recall_frac
        f1 = round(2 * precision_frac * recall_frac / pr_sum, 4) if pr_sum else 0.0
    hallucination_rate = round(fp_n / total_run, 4) if total_run else None

    negative_coverage = _negative_coverage(
        violations, denylist_hits, anti_facts, known_negatives, named_denylist
    )

    # Gate: any planted-bait assertion (anti_fact / known_negative / denylisted
    # named claim) always fails the run. Generic extra findings (closed-world FPs)
    # are reported but do not fail, so a run that surfaces a real claim the key
    # omitted is not punished as a failure.
    passed = recall_percent >= min_recall and verdict_match and not planted_bait

    return {
        "case_id": golden.get("case_id") or verdict_doc.get("case_id"),
        "case_dir": str(case_dir),
        "golden": str(golden_path),
        "expected_n": expected_n,
        "recalled_n": recalled_n,
        "recall_percent": recall_percent,
        "min_recall_percent": min_recall,
        "run_finding_n": total_run,
        "extra_n": extra_n,
        "false_positives_n": fp_n,
        "fp_planted": fp_planted,
        "precision_percent": precision_percent,
        "precision_scored": precision_scored,
        "exhaustive": exhaustive,
        "f1": f1,
        "hallucination_rate": hallucination_rate,
        "negative_coverage": negative_coverage,
        "run_verdict": run_verdict,
        "golden_verdict": golden_verdict,
        "verdict_match": verdict_match,
        "run_completed": run_completed,
        "run_incomplete_reasons": run_incomplete_reasons,
        "pass": passed,
        "matched": matched,
        "unmatched": unmatched,
        "extra": extra,
        "false_positives": false_positives,
        "planted_bait": planted_bait,
    }


__all__ = ["newest_case_dir", "resolve_golden", "score"]
