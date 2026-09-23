"""Unit tests for the deterministic parts of scripts/01_scan.py.

These never call Semgrep or an LLM -- they operate on hand-built dicts
shaped like real Semgrep --dataflow-traces JSON output (captured from an
actual run against VulnerableApp, see MEMORY.md's note on the tagged-tuple
taint_source format).
"""
import os
import subprocess
from pathlib import Path

import pytest

from scanner.core import dedup_copies, drop_out_of_scope, long_paths, run_semgrep


def make_result(check_id="rule.id", path="C:\\repo\\A.java", start_line=51,
                 severity="ERROR", cwe=None, owasp=None, dataflow_trace=None):
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": start_line, "col": 1},
        "end": {"line": start_line, "col": 10},
        "extra": {
            "message": f"finding for {check_id}",
            "severity": severity,
            "metadata": {"cwe": cwe, "owasp": owasp},
            "dataflow_trace": dataflow_trace,
        },
    }


def make_trace(path, line):
    """Shape matches real Semgrep output: a tagged tuple, not {"location": ...}."""
    return {
        "taint_source": ["CliLoc", [{"path": path, "start": {"line": line}, "end": {"line": line}}, "username"]],
        "taint_sink": ["CliLoc", [{"path": path, "start": {"line": line}}, "sql"]],
    }


class TestExtractSourceLocation:
    def test_returns_none_when_no_trace(self, scan_module):
        result = make_result(dataflow_trace=None)
        assert scan_module.extract_source_location(result, Path("C:\\repo")) is None

    def test_returns_none_when_trace_missing_taint_source(self, scan_module):
        result = make_result(dataflow_trace={"taint_sink": ["CliLoc", [{}, "x"]]})
        assert scan_module.extract_source_location(result, Path("C:\\repo")) is None

    def test_parses_tagged_tuple_shape(self, scan_module):
        trace = make_trace("C:\\repo\\A.java", 44)
        result = make_result(dataflow_trace=trace)
        loc = scan_module.extract_source_location(result, Path("C:\\repo"))
        assert loc is not None
        assert loc["line"] == 44
        assert loc["file"] == "A.java"

    def test_defensive_on_malformed_payload(self, scan_module):
        # taint_source present but payload isn't the [location, varname] list
        # shape -- must not raise, must return None.
        result = make_result(dataflow_trace={"taint_source": ["CliLoc", "not-a-list"]})
        assert scan_module.extract_source_location(result, Path("C:\\repo")) is None


class TestNormalize:
    def test_cross_function_candidate_keeps_distinct_source_and_sink(self, scan_module):
        raw = {"results": [make_result(
            check_id="java.spring-sqli", path="C:\\repo\\Auth.java", start_line=51,
            dataflow_trace=make_trace("C:\\repo\\Auth.java", 44),
        )]}
        candidates = scan_module.normalize(raw, Path("C:\\repo"))
        assert len(candidates) == 1
        c = candidates[0]
        assert c["source_line"] == 44
        assert c["sink_line"] == 51
        assert c["is_intraprocedural"] is True  # same file, just different lines

    def test_pattern_rule_without_trace_uses_sink_as_source(self, scan_module):
        raw = {"results": [make_result(dataflow_trace=None)]}
        candidates = scan_module.normalize(raw, Path("C:\\repo"))
        c = candidates[0]
        assert c["source_line"] == c["sink_line"] == 51
        assert c["is_intraprocedural"] is True


class TestDedup:
    def test_merges_findings_at_the_same_source_and_sink(self, scan_module):
        raw = {"results": [
            make_result(check_id="rule.a", path="C:\\repo\\Crypto.java", start_line=88, dataflow_trace=None),
            make_result(check_id="rule.b", path="C:\\repo\\Crypto.java", start_line=88, dataflow_trace=None),
        ]}
        candidates = scan_module.normalize(raw, Path("C:\\repo"))
        deduped = scan_module.dedup(candidates)
        assert len(deduped) == 1
        assert set(deduped[0]["rule_ids"]) == {"rule.a", "rule.b"}

    def test_keeps_distinct_sources_sharing_one_sink_separate(self, scan_module):
        """Regression test for the bug flagged in the framework review: the
        CommandInjection Level1~5 handlers all funnel into the same sink
        line, but each has a different source (a different HTTP entry
        point) and must be reported as separate candidates, not merged."""
        sink_path = "C:\\repo\\CommandInjection.java"
        raw = {"results": [
            make_result(check_id="cmd-inject", path=sink_path, start_line=47,
                        dataflow_trace=make_trace(sink_path, 68)),   # Level 1 entry
            make_result(check_id="cmd-inject", path=sink_path, start_line=47,
                        dataflow_trace=make_trace(sink_path, 83)),   # Level 2 entry
        ]}
        candidates = scan_module.normalize(raw, Path("C:\\repo"))
        deduped = scan_module.dedup(candidates)
        assert len(deduped) == 2
        source_lines = {c["source_line"] for c in deduped}
        assert source_lines == {68, 83}


class TestDedupCopies:
    """dedup_copies() reads the files, so these write real ones. The shape
    under test is the one measured on the vmscode corpus: the same module
    shipped twice, renamed into a different package."""

    COPY = """package {pkg};

import java.io.File;
import java.io.FileOutputStream;

public class TemplateUtil {{
    public static void write(String filePath, String fileName) throws Exception {{
        new FileOutputStream(filePath + File.separator + fileName);
    }}
}}
"""

    def write_copy(self, root, rel, pkg):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.COPY.format(pkg=pkg), encoding="utf-8")
        return rel

    def candidate(self, rel, line=7, rule="rules.custom.java.file-path-with-nonconstant-segment"):
        return {"source_file": rel, "source_line": line, "sink_file": rel, "sink_line": line,
                "rule_ids": [rule], "messages": ["m"]}

    def test_merges_the_same_file_shipped_under_two_packages(self, tmp_path):
        a = self.write_copy(tmp_path, "modA/src/main/java/com/x/asm/TemplateUtil.java", "com.x.asm")
        b = self.write_copy(tmp_path, "modB/src/main/java/com/x/TemplateUtil.java", "com.x")
        merged = dedup_copies([self.candidate(a), self.candidate(b)], tmp_path)
        assert len(merged) == 1
        assert merged[0]["duplicate_locations"] == [b]

    def test_keeps_two_files_that_only_share_a_name(self, tmp_path):
        a = self.write_copy(tmp_path, "modA/src/main/java/com/x/TemplateUtil.java", "com.x")
        b = tmp_path / "modB/src/main/java/com/y/TemplateUtil.java"
        b.parent.mkdir(parents=True, exist_ok=True)
        b.write_text(self.COPY.format(pkg="com.y").replace("filePath", "safeRoot"), encoding="utf-8")
        merged = dedup_copies([self.candidate(a), self.candidate("modB/src/main/java/com/y/TemplateUtil.java")], tmp_path)
        assert len(merged) == 2

    def test_keeps_two_sinks_in_one_file_separate(self, tmp_path):
        a = self.write_copy(tmp_path, "modA/src/main/java/com/x/TemplateUtil.java", "com.x")
        merged = dedup_copies([self.candidate(a, line=7), self.candidate(a, line=8)], tmp_path)
        assert len(merged) == 2

    def test_keeps_copies_that_different_rules_hit(self, tmp_path):
        a = self.write_copy(tmp_path, "modA/src/main/java/com/x/asm/TemplateUtil.java", "com.x.asm")
        b = self.write_copy(tmp_path, "modB/src/main/java/com/x/TemplateUtil.java", "com.x")
        merged = dedup_copies([self.candidate(a, rule="rule.a"), self.candidate(b, rule="rule.b")], tmp_path)
        assert len(merged) == 2

    def test_an_unreadable_file_never_merges(self, tmp_path):
        """Failing to read a file must not be mistaken for two files being
        equal -- that would silently drop a finding nobody looked at."""
        merged = dedup_copies(
            [self.candidate("gone/A.java"), self.candidate("also-gone/A.java")], tmp_path)
        assert len(merged) == 2

    def test_leaves_a_single_candidate_untouched_with_an_empty_list(self, tmp_path):
        a = self.write_copy(tmp_path, "modA/src/main/java/com/x/TemplateUtil.java", "com.x")
        merged = dedup_copies([self.candidate(a)], tmp_path)
        assert merged[0]["duplicate_locations"] == []


class TestRelpath:
    def test_path_inside_target_becomes_relative(self, scan_module):
        rel = scan_module.relpath(Path("C:/repo"), "C:/repo/src/Main.java")
        assert rel in ("src\\Main.java", "src/Main.java")

    def test_path_outside_target_falls_back_to_original(self, scan_module):
        rel = scan_module.relpath(Path("C:/repo"), "D:/elsewhere/Main.java")
        assert rel == "D:/elsewhere/Main.java"


@pytest.mark.skipif(os.name != "nt", reason="the MAX_PATH limit only exists on Windows")
class TestLongPaths:
    """semgrep does not report files it cannot open past Windows' MAX_PATH --
    they show up as neither scanned, skipped nor errored -- so this is the
    only thing standing between a too-deep workspace and a scan that quietly
    covers a third of the code. `limit` is injected here so the cases stay
    readable instead of building 260-character fixtures.
    """

    def plant(self, root: Path, rel: str):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x", encoding="utf-8")
        return target

    def test_flags_a_source_file_past_the_limit(self, tmp_path):
        deep = self.plant(tmp_path, "src/main/java/Deep.java")
        assert long_paths(tmp_path, limit=len(str(deep))) == [deep]

    def test_ignores_files_semgrep_would_not_have_scanned_anyway(self, tmp_path):
        """An uploaded project's build output is over the limit constantly
        and costs nothing -- failing the scan for it would be a false alarm."""
        planted = self.plant(tmp_path, "build/classes/Deep.class")
        assert long_paths(tmp_path, limit=len(str(planted))) == []

    def test_ignores_files_under_a_configured_exclude_path(self, tmp_path):
        planted = self.plant(tmp_path, "target/generated/Deep.java")
        limit = len(str(planted))
        assert long_paths(tmp_path, ["target"], limit=limit) == []
        assert long_paths(tmp_path, [], limit=limit) == [planted]

    def test_honours_an_unanchored_exclude_glob(self, tmp_path):
        planted = self.plant(tmp_path, "moduleA/src/it/Deep.java")
        assert long_paths(tmp_path, ["**/src/it"], limit=len(str(planted))) == []

    def test_honours_a_file_glob(self, tmp_path):
        planted = self.plant(tmp_path, "web/app.min.js")
        assert long_paths(tmp_path, ["*.min.js"], limit=len(str(planted))) == []

    def test_stays_quiet_when_everything_fits(self, tmp_path):
        self.plant(tmp_path, "src/A.java")
        assert long_paths(tmp_path, limit=4096) == []


class TestRunSemgrepRefusesAnIncompleteScan:
    """The guard has to abort *before* semgrep runs. Reporting 29 findings
    where there are 44, with no error anywhere, is the failure mode this
    whole check exists for -- so monkeypatch the detection and assert the
    scan stops rather than trusting that the wiring is still connected.
    """

    def test_raises_instead_of_scanning(self, tmp_path, monkeypatch):
        monkeypatch.setattr("scanner.core.long_paths", lambda *a, **k: [tmp_path / "TooDeep.java"])

        def fail_if_called(*a, **k):
            raise AssertionError("semgrep was launched despite unreadable files")

        monkeypatch.setattr("scanner.core.subprocess.run", fail_if_called)

        with pytest.raises(SystemExit, match="silently incomplete"):
            run_semgrep(tmp_path, ["rules/custom"])

    def test_runs_normally_when_nothing_is_out_of_reach(self, tmp_path, monkeypatch):
        monkeypatch.setattr("scanner.core.long_paths", lambda *a, **k: [])

        class Proc:
            returncode = 0
            stdout = '{"results": []}'
            stderr = ""

        monkeypatch.setattr("scanner.core.subprocess.run", lambda *a, **k: Proc())
        assert run_semgrep(tmp_path, ["rules/custom"]) == {"results": []}


class TestScopeFilter:
    """Scope is dataflow: a weakness only counts when externally controlled
    data reaches a dangerous operation. Filtering by CWE rather than by rule
    id is what makes that a property of the weakness, so a vendor rule this
    project has never seen is classified the first time it fires."""

    OUT_OF_SCOPE = frozenset({"CWE-327", "CWE-328", "CWE-295"})

    def candidate(self, cwe, rule="rules.vendor.x"):
        return {"rule_id": rule, "cwe": cwe, "source_file": "A.java", "source_line": 1,
                "sink_file": "A.java", "sink_line": 1}

    def test_drops_a_weakness_with_no_dataflow(self, tmp_path):
        kept = drop_out_of_scope([self.candidate(["CWE-328: Use of Weak Hash"])], self.OUT_OF_SCOPE)
        assert kept == []

    def test_keeps_a_dataflow_weakness(self, tmp_path):
        cand = self.candidate(["CWE-89: SQL Injection"])
        assert drop_out_of_scope([cand], self.OUT_OF_SCOPE) == [cand]

    def test_keeps_a_candidate_with_no_cwe_at_all(self, tmp_path):
        """Denylist, not allowlist: an unclassified weakness stays in, because
        a false negative costs more than a false positive."""
        cand = self.candidate(None)
        assert drop_out_of_scope([cand], self.OUT_OF_SCOPE) == [cand]

    def test_keeps_a_candidate_that_is_only_partly_out_of_scope(self, tmp_path):
        cand = self.candidate(["CWE-327: Broken Crypto", "CWE-89: SQL Injection"])
        assert drop_out_of_scope([cand], self.OUT_OF_SCOPE) == [cand]

    def test_accepts_a_plain_string_cwe(self, tmp_path):
        """Production sends a list, older fixtures a bare string."""
        assert drop_out_of_scope([self.candidate("CWE-295")], self.OUT_OF_SCOPE) == []

    def test_an_empty_scope_list_drops_nothing(self, tmp_path):
        cands = [self.candidate(["CWE-328"]), self.candidate(["CWE-89"])]
        assert drop_out_of_scope(cands, frozenset()) == cands

    def test_runs_before_dedup_so_a_shared_sink_survives_on_its_other_rule(self, scan_module):
        """The reason the filter sits before dedup(): two rules on one
        (source, sink) merge into a single candidate carrying one cwe, and
        filtering afterwards would judge the pair by whichever rule landed
        first."""
        raw = {"results": [
            make_result(check_id="crypto", path=r"C:\repo\A.java", start_line=88, cwe=["CWE-327: Broken Crypto"]),
            make_result(check_id="sqli", path=r"C:\repo\A.java", start_line=88, cwe=["CWE-89: SQL Injection"]),
        ]}
        candidates = scan_module.normalize(raw, Path(r"C:\repo"))
        deduped = scan_module.dedup(drop_out_of_scope(candidates, self.OUT_OF_SCOPE))
        assert len(deduped) == 1
        assert deduped[0]["rule_ids"] == ["sqli"]


class TestVerifyAll:
    """scanner.pipeline.verify_all -- the concurrency knob. No LLM here:
    call_llm is stubbed, so what is asserted is ordering and fan-out."""

    def _setup(self, monkeypatch, calls, delay=0.0):
        import time
        from scanner import pipeline

        monkeypatch.setattr(pipeline, "build_context", lambda ws, c, idx: "ctx")
        monkeypatch.setattr(pipeline, "build_prompt", lambda tpl, c, ctx: c["sink_file"])

        def fake_call_llm(provider, model, prompt):
            calls.append(prompt)
            if delay:
                time.sleep(delay)
            return {"reachable": "yes", "reasoning": prompt}

        monkeypatch.setattr(pipeline, "call_llm", fake_call_llm)

    def test_results_keep_candidate_order_when_run_concurrently(self, monkeypatch):
        from scanner.pipeline import verify_all

        calls = []
        self._setup(monkeypatch, calls, delay=0.02)
        candidates = [{"sink_file": f"F{n}.java"} for n in range(12)]

        verified = verify_all(candidates, None, None, "tpl", None, "m", concurrency=4)

        # Threads finish out of order; the returned list must not.
        assert [v["sink_file"] for v in verified] == [c["sink_file"] for c in candidates]
        assert len(calls) == 12

    def test_every_candidate_is_verified_exactly_once(self, monkeypatch):
        from scanner.pipeline import verify_all

        calls = []
        self._setup(monkeypatch, calls)
        candidates = [{"sink_file": f"F{n}.java"} for n in range(5)]

        verify_all(candidates, None, None, "tpl", None, "m", concurrency=3)

        assert sorted(calls) == sorted(c["sink_file"] for c in candidates)

    def test_a_failure_still_ends_the_stage(self, monkeypatch):
        # A hard failure must surface, not be swallowed into a report with
        # silent holes in it. An exhausted rate limit is the one exception,
        # covered by TestVerifyAllRateLimited below.
        import pytest

        from scanner import pipeline
        from scanner.pipeline import verify_all

        monkeypatch.setattr(pipeline, "build_context", lambda ws, c, idx: "ctx")
        monkeypatch.setattr(pipeline, "build_prompt", lambda tpl, c, ctx: c["sink_file"])

        def boom(provider, model, prompt):
            if prompt == "F3.java":
                raise RuntimeError("malformed request")
            return {"reachable": "yes"}

        monkeypatch.setattr(pipeline, "call_llm", boom)
        candidates = [{"sink_file": f"F{n}.java"} for n in range(6)]

        with pytest.raises(RuntimeError, match="malformed"):
            verify_all(candidates, None, None, "tpl", None, "m", concurrency=3)


class TestVerifyAllRateLimited:
    """What a scan does when the provider stops answering.

    llm_gateway retries a 429 with backoff; only an exhausted ladder reaches
    verify_all. At that point the endpoint is refusing us for longer than a
    scan can wait, and throwing away the Semgrep work plus every verdict
    already paid for is the worse of the two options.
    """

    def _setup(self, monkeypatch, fail_from: int, unavailable: bool = False):
        from llm_gateway.rate_limit import ProviderUnavailable, RateLimitExhausted
        from scanner import pipeline

        monkeypatch.setattr(pipeline, "build_context", lambda ws, c, idx: "ctx")
        monkeypatch.setattr(pipeline, "build_prompt", lambda tpl, c, ctx: c["sink_file"])
        sent = []

        def call_llm(provider, model, prompt):
            sent.append(prompt)
            if int(prompt[1]) >= fail_from:
                if unavailable:
                    raise ProviderUnavailable(4, RuntimeError("Connection error."))
                raise RateLimitExhausted(4, RuntimeError("429 Too Many Requests"))
            return {"reachable": "yes", "reasoning": "ok"}

        monkeypatch.setattr(pipeline, "call_llm", call_llm)
        return sent

    @pytest.mark.parametrize("unavailable", [False, True], ids=["rate-limited", "connection-lost"])
    def test_the_verdicts_already_paid_for_are_kept(self, monkeypatch, unavailable):
        from scanner.pipeline import verify_all

        self._setup(monkeypatch, fail_from=3, unavailable=unavailable)
        candidates = [{"sink_file": f"F{n}.java"} for n in range(6)]

        verified = verify_all(candidates, None, None, "tpl", None, "m", concurrency=1)

        assert len(verified) == 6
        assert [v["sink_file"] for v in verified] == [c["sink_file"] for c in candidates]
        assert [v.get("finding", {}).get("reachable") for v in verified[:3]] == ["yes"] * 3

    def test_the_ones_never_reached_carry_no_finding_at_all(self, monkeypatch):
        """Not `no`, not `uncertain`, not `verifier_failed` -- the report has
        to be able to say nobody judged these."""
        from scanner.render import build_summary, verdict_of
        from scanner.pipeline import verify_all

        self._setup(monkeypatch, fail_from=3)

        verified = verify_all([{"sink_file": f"F{n}.java"} for n in range(6)],
                              None, None, "tpl", None, "m", concurrency=1)

        assert all("finding" not in v for v in verified[3:])
        assert [verdict_of(v) for v in verified[3:]] == ["unverified"] * 3
        summary = build_summary(verified)
        assert (summary["unverified"], summary["reachable"], summary["uncertain"]) == (3, 3, 0)

    def test_the_remaining_candidates_are_not_sent(self, monkeypatch):
        """Each would burn the full retry ladder to arrive in the same place,
        which on a 20-candidate scan is minutes of waiting for nothing."""
        from scanner.pipeline import verify_all

        sent = self._setup(monkeypatch, fail_from=3)

        verify_all([{"sink_file": f"F{n}.java"} for n in range(9)],
                   None, None, "tpl", None, "m", concurrency=1)

        assert sent == ["F0.java", "F1.java", "F2.java", "F3.java"]

    def test_the_caller_is_told_once_why_it_stopped(self, monkeypatch):
        from scanner.pipeline import verify_all

        self._setup(monkeypatch, fail_from=2)
        reasons = []

        verify_all([{"sink_file": f"F{n}.java"} for n in range(6)],
                   None, None, "tpl", None, "m", concurrency=1, on_halt=reasons.append)

        assert len(reasons) == 1
        assert "rate limited" in reasons[0]

    def test_it_holds_on_the_concurrent_path_too(self, monkeypatch):
        """The exception arrives on a worker thread through executor.map,
        where the old behaviour was to re-raise it out of the whole stage."""
        from scanner.pipeline import verify_all

        self._setup(monkeypatch, fail_from=4)
        reasons = []

        verified = verify_all([{"sink_file": f"F{n}.java"} for n in range(8)],
                              None, None, "tpl", None, "m", concurrency=4, on_halt=reasons.append)

        assert len(verified) == 8
        assert len(reasons) == 1
        assert [v["sink_file"] for v in verified] == [f"F{n}.java" for n in range(8)]
        # Which candidates got in before the halt depends on thread timing;
        # that the run ends with both kinds present does not.
        assert any("finding" not in v for v in verified)
        assert any("finding" in v for v in verified)


class TestNoConsoleWindow:
    """semgrep is a console program, and the server that runs it has no
    console of its own (apps/launcher.py starts it detached). Windows hands
    such a child a brand new console -- a black window appearing mid-scan."""

    def test_windows_asks_for_no_console(self, monkeypatch):
        from scanner import core

        monkeypatch.setattr(core.sys, "platform", "win32")

        assert core._no_console() == {"creationflags": subprocess.CREATE_NO_WINDOW}

    @pytest.mark.parametrize("platform", ["linux", "darwin"])
    def test_other_platforms_pass_nothing(self, monkeypatch, platform):
        """creationflags does not exist off Windows; passing it raises."""
        from scanner import core

        monkeypatch.setattr(core.sys, "platform", platform)

        assert core._no_console() == {}
