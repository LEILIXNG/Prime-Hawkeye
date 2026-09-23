"""Orchestrates A -> B -> C -> E -> G for the Phase 1 API.

Kept intentionally synchronous (called from a FastAPI BackgroundTasks
worker, one scan at a time) per docs/framework.md's "单用户同一时刻通常只
跑一个扫描" simplification — no distributed queue.
"""
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock
from typing import Callable

from scanner.common import (
    PROMPTS_DIR,
    ensure_data_dir,
    load_default_configs,
    load_excluded_paths,
    load_excluded_rules,
    load_out_of_scope_cwes,
)
from scanner.callgraph import index_workspace
from scanner.core import (
    build_context, build_prompt, dedup, dedup_copies, drop_excluded_paths, drop_out_of_scope,
    normalize, run_semgrep,
)
from scanner.ingest import safe_extract
from scanner.render import render
from scanner.translate import (
    LANGUAGE_NAMES,
    apply_translation,
    build_translate_prompt,
    finding_language,
    needs_translation,
    parse_translation,
    validate_translation,
)
from llm_gateway.rate_limit import ProviderExhausted
from scanner.verify import call_llm, call_llm_cached

DEFAULT_CONFIGS = load_default_configs()
EXCLUDED_RULES = load_excluded_rules()
EXCLUDED_PATHS = load_excluded_paths()
OUT_OF_SCOPE_CWES = load_out_of_scope_cwes()


class PipelineError(Exception):
    pass


class PipelineCancelled(Exception):
    """Raised when the caller asked for the scan to stop. Not a
    PipelineError: a cancelled scan did not fail, and the two end up in
    different states on the scan row."""


# How often a paused scan checks whether it has been resumed (or cancelled
# out of the pause). Not the responsiveness of pause/resume itself, which
# depends on how far apart the checkpoints below already are -- this is
# just the cost of sitting still, and a scan can sit paused for however
# long the user leaves it.
PAUSE_POLL_SECONDS = 0.5


def _wait_while_paused(should_pause: Callable[[], bool], should_cancel: Callable[[], bool],
                       on_pause_change: Callable[[bool], None]) -> None:
    """Blocks the calling thread while `should_pause()` says so, checking
    `should_cancel()` on every tick so a paused scan can still be
    cancelled rather than sitting there until timed out. `on_pause_change`
    is told when the wait starts and ends -- not whether it ended in a
    resume or a cancel, which the caller's own should_cancel() check right
    after this call already distinguishes.

    Not a threading.Event: pause/resume/cancel are all requests recorded in
    an in-memory registry the API layer owns (apps/api/cancel.py's own
    docstring explains why in-memory is enough), and polling that registry
    at the same checkpoints should_cancel() already uses keeps pause on the
    identical footing rather than adding a second signalling mechanism.
    """
    if not should_pause():
        return
    on_pause_change(True)
    try:
        while should_pause() and not should_cancel():
            time.sleep(PAUSE_POLL_SECONDS)
    finally:
        on_pause_change(False)


def verify_all(candidates, workspace_dir, index, template, provider, model, concurrency: int = 1,
               on_progress: Callable[[int, int], None] = lambda done, total: None,
               should_cancel: Callable[[], bool] = lambda: False,
               should_pause: Callable[[], bool] = lambda: False,
               on_pause_change: Callable[[bool], None] = lambda paused: None,
               on_halt: Callable[[str], None] = lambda reason: None):
    """The verify stage, `concurrency` calls in flight at a time.

    Threads rather than asyncio: the work is one blocking HTTP call per
    candidate through a provider SDK this project does not control, and the
    context building around it is file IO. Nothing here is CPU-bound, so the
    GIL is not what limits it.

    executor.map keeps the results in candidate order -- the report sorts by
    verdict later, but a scan that shuffled its findings run to run would
    make two reports of the same code impossible to diff. It also re-raises
    the first exception, which keeps the contract that a hard failure ends
    the stage rather than yielding a report with silent holes in it.

    A rate limit or a transient provider failure (connection error, timeout,
    5xx) is the one failure that does not end it. llm_gateway retries those
    with backoff, and only when they are exhausted does one reach here as
    ProviderExhausted; at that point the endpoint is refusing us for longer than a
    scan can wait, and the answer is to keep what was judged rather than
    throw the whole scan away. Verification stops at that candidate, the
    rest come back as the bare candidate with no `finding` key at all --
    which verdict_of() reports as `unverified`, a state of its own and not
    one of the three verdicts the model can return. on_halt is called once
    with the reason.

    on_progress is called with (done, total) alongside every progress line
    printed here, and in the concurrent branch that call happens on a worker
    thread -- whatever it writes to has to tolerate that.
    """
    halted: list[str] = []

    def verify_one(candidate):
        # Checked per candidate rather than per stage: this is the long one,
        # and a scan the user asked to delete should not keep spending LLM
        # calls for the minutes the rest of it would take. Pause is checked
        # here for the same reason -- candidates in flight finish, but the
        # next one waits.
        _wait_while_paused(should_pause, should_cancel, on_pause_change)
        if should_cancel():
            raise PipelineCancelled()
        # Once the endpoint has stopped answering, the queued candidates are
        # drained without being sent: they would each burn the full retry
        # ladder to arrive at the same place.
        if halted:
            return dict(candidate)
        if candidate.get("verification_mode") == "static":
            confidence = {"HIGH": 95, "MEDIUM": 75, "LOW": 55}.get(
                str(candidate.get("rule_confidence", "")).upper(), 75
            )
            return {
                **candidate,
                "finding": {
                    # Existing consumers require this enum. verdict_kind
                    # distinguishes a deterministic static finding from an
                    # HTTP source-to-sink reachability claim.
                    "reachable": "yes",
                    "verdict_kind": "static",
                    "sanitized": False,
                    "confidence": confidence,
                    "reasoning": f"Static rule confirmed: {candidate.get('message', '')}",
                    "exploit_scenario": "",
                    "remediation": candidate.get("rule_remediation", ""),
                },
            }
        code_context = build_context(workspace_dir, candidate, index)
        prompt = build_prompt(template, candidate, code_context)
        try:
            return {**candidate, "finding": call_llm(provider, model, prompt)}
        except ProviderExhausted as e:
            if not halted:
                halted.append(str(e))
                print(f"[pipeline] {e}; keeping the findings verified so far", file=sys.stderr)
            return dict(candidate)

    total = len(candidates)
    on_progress(0, total)
    if concurrency <= 1:
        verified = []
        for i, candidate in enumerate(candidates, 1):
            print(f"[pipeline] verifying {i}/{total}", file=sys.stderr)
            verified.append(verify_one(candidate))
            on_progress(i, total)
        _report_halt(halted, on_halt)
        return verified

    print(f"[pipeline] verifying {total} candidates, {concurrency} at a time", file=sys.stderr)
    done = 0
    lock = Lock()

    def verify_and_count(candidate):
        result = verify_one(candidate)
        nonlocal done
        with lock:
            done += 1
            print(f"[pipeline] verifying {done}/{total}", file=sys.stderr)
            on_progress(done, total)
        return result

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        verified = list(pool.map(verify_and_count, candidates))
    _report_halt(halted, on_halt)
    return verified


def _report_halt(halted: list[str], on_halt) -> None:
    if halted:
        on_halt(halted[0])


def run_pipeline(
    zip_path: Path,
    workspace_dir: Path,
    report_dir: Path,
    project_name: str,
    provider,
    model: str,
    on_status: Callable[[str], None] = lambda status: None,
    on_progress: Callable[[int, int], None] = lambda done, total: None,
    should_cancel: Callable[[], bool] = lambda: False,
    should_pause: Callable[[], bool] = lambda: False,
    on_pause_change: Callable[[bool], None] = lambda paused: None,
    translate: bool = True,
    concurrency: int = 1,
) -> dict:
    """Runs the full A/B/C/E/G flow for one scan. Returns the same dict
    shape as scanner.render.render(), plus `halted_reason`: None normally,
    or why verification stopped early when the endpoint rate-limited us for
    longer than the retries could absorb. A halted scan still produces a
    report -- the candidates it never reached are counted as `unverified` in
    the summary -- so it is a completed scan carrying a caveat, not a failed
    one. Raises PipelineError on failure; callers are responsible for
    recording Scan.status = "failed".

    `should_pause` is checked at the same checkpoints `should_cancel`
    already is (between stages, and between candidates in the verify
    stage), blocking this thread until it goes back to False or
    `should_cancel` goes True. `on_pause_change` fires True right before
    the wait starts and False right after it ends, so a caller can reflect
    "paused" somewhere (a DB column, say) without this module knowing
    anything about where that state lives -- the same separation
    `on_status`/`on_progress` already keep.
    """
    ensure_data_dir()

    def checkpoint() -> None:
        _wait_while_paused(should_pause, should_cancel, on_pause_change)
        if should_cancel():
            raise PipelineCancelled()

    checkpoint()
    on_status("ingesting")
    try:
        safe_extract(zip_path, workspace_dir)
    except Exception as e:
        raise PipelineError(f"ingest failed: {e}") from e

    checkpoint()
    on_status("scanning")
    try:
        raw = run_semgrep(workspace_dir, DEFAULT_CONFIGS, EXCLUDED_RULES, EXCLUDED_PATHS)
        in_scope = drop_out_of_scope(normalize(raw, workspace_dir), OUT_OF_SCOPE_CWES)
        kept = drop_excluded_paths(in_scope, EXCLUDED_PATHS)
        candidates = dedup_copies(dedup(kept), workspace_dir)
    except (Exception, SystemExit) as e:
        raise PipelineError(f"scan failed: {e}") from e

    # Its own stage rather than the first thing the verify stage does: this
    # is a tree-sitter parse of every .java file in the workspace, and while
    # it runs no LLM call has been made yet. Folded into "verifying" it read
    # as a scan stuck on its first finding -- 2s on a 162-file project, but
    # it scales with the repo, not with the number of findings.
    checkpoint()
    on_status("indexing")
    try:
        # Built once per scan: doing it per candidate would repeat the whole
        # parse for every finding.
        index = index_workspace(workspace_dir)
    except Exception as e:
        raise PipelineError(f"call graph failed: {e}") from e

    checkpoint()
    on_status("verifying")
    template = (PROMPTS_DIR / "verify_taint.md").read_text(encoding="utf-8")
    halted: list[str] = []
    try:
        verified = verify_all(candidates, workspace_dir, index, template, provider, model, concurrency,
                              on_progress=on_progress, should_cancel=should_cancel,
                              should_pause=should_pause, on_pause_change=on_pause_change,
                              on_halt=halted.append)
    except PipelineCancelled:
        # Reaches here from a worker thread through executor.map, and must
        # not be dressed up as a verify failure on the way out.
        raise
    except Exception as e:
        raise PipelineError(f"verify failed: {e}") from e

    # F: fill in the other language for the prose, so the report's zh/en
    # toggle switches what the reader actually reads and not just the
    # labels. Roughly doubles the LLM calls a scan makes, which is why it is
    # a flag: on a rate-limited free endpoint that is the cost that matters.
    # Never fatal -- an untranslated finding shows the same text under both
    # toggles, which is what the report did before this stage existed.
    if translate:
        on_status("translating")
        translate_template = (PROMPTS_DIR / "translate_finding.md").read_text(encoding="utf-8")
        for i, item in enumerate(verified, 1):
            finding = item.get("finding")
            # An unverified candidate has no prose to translate, and asking
            # for more LLM calls is the last thing a halted scan needs.
            if not finding or not needs_translation(finding):
                continue
            source = finding_language(finding)
            target = "en" if source == "zh" else "zh"
            print(f"[pipeline] translating {i}/{len(verified)} {source}->{target}", file=sys.stderr)
            on_progress(i, len(verified))
            name = LANGUAGE_NAMES[target]
            try:
                parsed = call_llm_cached(
                    provider, model,
                    build_translate_prompt(translate_template, finding, target),
                    parse=lambda raw, t=target: parse_translation(raw, t),
                    retry_hint=f"上一次输出没有翻译成{name},或者不是合法 JSON。"
                               f"请重新翻译,三个字段全部输出{name}。",
                )
                item["finding"] = apply_translation(finding, source, validate_translation(parsed, target))
            except Exception as e:
                print(f"[pipeline]   translation failed ({type(e).__name__}), keeping original", file=sys.stderr)
                item["finding"] = apply_translation(finding, source, None)

    checkpoint()
    on_status("reporting")
    try:
        result = render(verified, project_name, report_dir)
    except Exception as e:
        raise PipelineError(f"report rendering failed: {e}") from e

    on_status("done")
    return {**result, "halted_reason": halted[0] if halted else None}
