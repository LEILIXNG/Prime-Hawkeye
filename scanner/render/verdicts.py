"""Verdict bucketing, risk grading and the small item-shaped helpers the
report is sorted and labelled by.

Deterministic, presentation-free, and the half of the renderer other stages
import (render_md.py, rule_stats.py) -- kept apart from the HTML so those
callers do not drag a page template in with them.
"""
import re

from scanner.cvss import band, score_for, vector_for

SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}
REACHABLE_ORDER = {"yes": 0, "uncertain": 1, "no": 2}

# Matches the short quoted name Semgrep tends to put at the end of a CWE
# description, e.g. "CWE-89: Improper Neutralization ... ('SQL Injection')".
_CWE_SHORT_NAME = re.compile(r"\('([^']+)'\)\s*$")


def _sort_key(item: dict):
    finding = item.get("finding") or {}
    return (
        REACHABLE_ORDER.get(finding.get("reachable"), 1),
        SEVERITY_ORDER.get(item.get("severity"), 3),
    )

VERDICT_SUMMARY_KEYS = {
    "yes": "reachable",
    "no": "not_reachable",
    "uncertain": "uncertain",
    "failed": "verifier_failed",
    "unverified": "unverified",
}


def verdict_of(item: dict) -> str:
    """Which bucket one candidate falls into: yes / no / uncertain / failed
    / unverified.

    Four of those are things the verify stage said. `unverified` is the
    absence of it: a candidate with no `finding` at all, because the stage
    never reached it -- the provider rate-limited us past the retries, or
    the run was a raw candidate list that was never verified. It is kept
    apart from the other three deliberately. "The model could not decide"
    and "nobody asked the model" read the same in a report that conflates
    them, and only one of the two is worth a human's time.

    A verifier failure is recorded in `reasoning` rather than in
    `reachable`, so it has to be checked before the verdict itself.
    """
    finding = item.get("finding") or {}
    if not finding:
        return "unverified"
    if "verifier_failed" in str(finding.get("reasoning") or ""):
        return "failed"
    reachable = finding.get("reachable")
    return reachable if reachable in ("yes", "no") else "uncertain"


def build_summary(verified: list[dict]) -> dict:
    summary = {"total": len(verified), "reachable": 0, "uncertain": 0, "not_reachable": 0,
               "verifier_failed": 0, "unverified": 0}
    for item in verified:
        summary[VERDICT_SUMMARY_KEYS[verdict_of(item)]] += 1
    return summary


def _cwe_text(item: dict) -> str | None:
    """A candidate's cwe field is a list of Semgrep's raw CWE strings in
    production (e.g. ["CWE-89: ... ('SQL Injection')"]), but a plain string
    in older fixtures/tests -- normalize both to one string."""
    cwe = item.get("cwe")
    if isinstance(cwe, list):
        return cwe[0] if cwe else None
    return cwe or None


def vuln_type_label(item: dict) -> str:
    """A short, human-readable vulnerability type for grouping/display --
    prefers the quoted short name Semgrep puts at the end of a CWE string
    ("SQL Injection"), falls back to the full CWE text, then to no-CWE."""
    text = _cwe_text(item)
    if not text:
        return "Uncategorized"
    match = _CWE_SHORT_NAME.search(text)
    return match.group(1) if match else text


# Highest first -- the facet lists these in fixed order rather than by
# count, because a severity scale reads wrong shuffled.
RISK_LEVELS = ("critical", "high", "medium", "low")


def risk_level(item: dict) -> str:
    """Four-level risk rating: the CWE's CVSS band, graded by whether the
    verifier actually reached the sink.

    The band comes from scanner/cvss.py rather than from Semgrep's
    ERROR/WARNING/INFO, which cannot separate an unauthenticated SQL
    injection from a weak hash -- both are ERROR. CVSS bands put them four
    points apart.

    Reachability stays as the second axis, and deliberately not as CVSS
    Temporal Report Confidence: RC:U multiplies by 0.92, which moves a 9.8
    to 9.0 and leaves it Critical. "We could not confirm this reaches the
    sink" deserves more than a rounding error, so it drops a whole band.

    The three verdicts are not two things. `no` is the verifier stating the
    sink is unreachable or already sanitized: that is evidence of safety,
    and it bottoms out the scale no matter how high the base score was.
    These are the same findings the summary counts as "safe", so grading
    them as anything else would have the report contradicting its own
    headline. `uncertain` and `verifier_failed` are the absence of a
    verdict, not a negative one -- unproven, so one step down from
    confirmed, never to the floor.
    """
    verdict = verdict_of(item)
    if verdict == "no":
        return "low"
    confirmed = band(score_for(item))
    if verdict == "yes":
        return confirmed
    # unverified lands here with uncertain and verifier_failed: all three are
    # the absence of a verdict rather than a negative one, so all three drop
    # one band instead of bottoming out at the "safe" floor.
    return {"critical": "high", "high": "medium", "medium": "low", "low": "low", "none": "low"}[confirmed]


def _sink_basename(item: dict) -> str:
    return item["sink_file"].replace("\\", "/").rsplit("/", 1)[-1]


def short_location(path: str, keep: int = 2) -> str:
    """The trailing `keep` segments of a path, with a leading ellipsis.

    A real project's sink paths run to 60+ characters of
    src/main/java/org/... that is identical across every finding, which in a
    collapsed card pushes the parts that actually differ off the end of the
    row. The full path stays on the row's title attribute and in the card
    body, so nothing is lost -- only the shared prefix is.
    """
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    if len(parts) <= keep:
        return "/".join(parts)
    return ".../" + "/".join(parts[-keep:])


def with_scores(item: dict) -> dict:
    """A finding plus its CVSS fields, for report.json.

    Stamped here rather than left for each consumer to work out: the web UI,
    the Markdown export and the database all read this file, and a table
    re-implemented three times is three tables that drift.
    """
    return {
        **item,
        "cvss_vector": f"CVSS:3.1/{vector_for(item)}",
        "cvss_score": score_for(item),
        "risk_level": risk_level(item),
    }

