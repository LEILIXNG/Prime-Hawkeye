"""Importable core of the A/B/C/E scan stages.

This is the same logic that used to live directly inside scripts/01_scan.py
and scripts/02_verify.py. It moved here so apps/api can import it as a
normal module (numbered scripts aren't valid `import` names) without
duplicating the parsing logic. scripts/01_scan.py and scripts/02_verify.py
now just re-export these functions so they keep working as standalone CLIs
and the existing tests (which load them by file path) keep passing.
"""
import json
import os
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import Path

from scanner.common import sha256
from scanner.cpp_validators import cpp_candidate_details, passes_cpp_validator
from scanner.languages import is_cpp_path

# Re-exported so `from scanner.core import build_context` keeps working for
# pipeline.py, scripts/02_verify.py and the tests that load them by path.
from scanner.context import (  # noqa: F401
    CONTEXT_WINDOW,
    build_caller_context,
    build_context,
    build_prompt,
    read_window,
)

# Windows refuses to open a path of 260 characters or more unless the
# process opts into long paths, and semgrep does not: it reports such files
# as neither scanned, skipped nor errored -- they simply are not there.
# Measured on the VulnerableApp zip extracted under a long temp path: the
# longest path semgrep scanned was 257 characters, the shortest it silently
# dropped was 260, and the scan came back 29 candidates instead of 44 with
# all ten SQL injection findings among the missing. A security scanner that
# quietly stops looking at a third of the code is worse than one that
# fails, so this is checked before the scan rather than hoped about.
WINDOWS_MAX_PATH = 260

# Directory names semgrep 1.173.0 ignores without being asked (measured, see
# rules/ruleset.yml's exclude_paths note). Files under these are already out
# of the scan, so a too-long path there costs nothing and must not fail the
# run -- an uploaded project's build/ output is the common case. semgrep has
# an --x-ls flag that would answer this exactly, but it is documented as
# internal and subject to change, so this mirrors the measurement instead.
SEMGREP_DEFAULT_IGNORED_DIRS = frozenset(
    {"build", "dist", "node_modules", "vendor", "test", "tests", ".venv"}
)


def long_paths(
    target: Path,
    exclude_paths: list[str] | None = None,
    limit: int = WINDOWS_MAX_PATH,
) -> list[Path]:
    """Files under `target` that Windows cannot open by path, ignoring the
    ones no scan would have looked at anyway.

    Always empty off Windows, where the limit does not apply.
    """
    if os.name != "nt":
        return []

    globs = [g.removeprefix("**/") for g in (exclude_paths or [])]
    found = []
    for path in target.rglob("*"):
        if not path.is_file() or len(str(path)) < limit:
            continue
        parts = path.relative_to(target).parts
        if SEMGREP_DEFAULT_IGNORED_DIRS.intersection(parts[:-1]):
            continue
        # Matches how semgrep reads these: a bare name is a directory at any
        # depth, a multi-segment glob is a run of consecutive directories,
        # and a glob containing a wildcard but no slash is a filename
        # pattern -- not just the `*.ext` shape (`*.min.js`): `*_test.go`
        # has its wildcard at the front instead, and both need the same
        # fnmatch treatment rather than being read as a literal directory
        # name that will never appear in `parts`.
        dirs = "/" + "/".join(parts[:-1]) + "/"
        if any(
            fnmatch(path.name, g) if "*" in g and "/" not in g
            else (f"/{g}/" in dirs if "/" in g else g in parts[:-1])
            for g in globs
        ):
            continue
        found.append(path)
    return sorted(found)


def run_semgrep(
    target: Path,
    configs: list[str],
    exclude_rules: list[str] | None = None,
    exclude_paths: list[str] | None = None,
) -> dict:
    # --no-git-ignore: semgrep's default is to enumerate files via `git
    # ls-files` when the target sits inside a git working tree, which
    # silently skips anything not tracked by git. That's exactly what
    # scanner/pipeline.py's data/workspaces/{scan_id}/ extraction dirs are
    # (data/ is gitignored, see .gitignore) -- without this flag every
    # Phase 1 API scan finds 0 results while the file is right there.
    cmd = ["semgrep", "--json", "--dataflow-traces", "--metrics=off", "--no-git-ignore"]
    for c in configs:
        cmd += ["--config", c]
    for rule_id in exclude_rules or []:
        cmd += ["--exclude-rule", rule_id]
    # --exclude globs containing a slash are anchored to the scan root, so
    # ruleset.yml writes those as **/src/it; passed through verbatim here.
    for pattern in exclude_paths or []:
        cmd += ["--exclude", pattern]
    cmd.append(str(target))

    unreachable = long_paths(target, exclude_paths)
    if unreachable:
        longest = max(unreachable, key=lambda p: len(str(p)))
        raise SystemExit(
            f"{len(unreachable)} file(s) under {target} exceed Windows' {WINDOWS_MAX_PATH}-character "
            f"path limit and would be skipped without any warning from semgrep, making this scan "
            f"silently incomplete. Longest ({len(str(longest))} chars): {longest}. "
            f"Move the target (or this tool) somewhere with a shorter path and scan again."
        )

    print(f"[scan] running: {' '.join(cmd)}", file=sys.stderr)
    # Semgrep is a Python program and reads its YAML rules using the host's
    # default code page. On a Chinese Windows install that is commonly GBK,
    # while the bundled rule library is UTF-8. Enable Python's UTF-8 mode for
    # this child only; it does not change Windows, Hawkeye, or the target files.
    semgrep_env = os.environ.copy()
    semgrep_env["PYTHONUTF8"] = "1"
    # Capture bytes so the parent process does not try to decode Semgrep's
    # UTF-8 output with the Windows code page in its pipe-reader thread.
    proc = subprocess.run(cmd, capture_output=True, env=semgrep_env, **_no_console())
    if proc.returncode not in (0, 1):  # semgrep exits 1 when findings exist
        stderr = proc.stderr.decode("utf-8", errors="replace") if isinstance(proc.stderr, bytes) else proc.stderr
        print(stderr, file=sys.stderr)
        raise SystemExit(f"semgrep failed with exit code {proc.returncode}")
    return json.loads(proc.stdout)


def _no_console() -> dict:
    """Keeps semgrep from flashing up a console window of its own.

    The server is started detached and console-less (apps/launcher.py), and
    when a process with no console starts a console program, Windows gives
    the child a brand new one -- a black window appearing mid-scan, right
    after ingest, for as long as semgrep runs. Redirecting the child's
    output is not enough on its own; the console is allocated regardless of
    where its streams point.
    """
    if sys.platform != "win32":
        return {}
    return {"creationflags": subprocess.CREATE_NO_WINDOW}


def path_is_excluded(rel_path: str, globs: list[str]) -> bool:
    """Whether a workspace-relative path falls under one of the exclusions.

    Semgrep's own --exclude cannot express these, which is why they are
    checked again here. Measured against the pinned 1.173.0: a pattern with
    no slash matches a path segment at any depth, but one containing a slash
    is anchored to the scan root, and a leading `**/` does not lift that --
    it makes the pattern match nothing at all. Anchoring is useless for this
    tool anyway, since an ingested zip puts the project one or more levels
    below the scan root.

    Here every glob matches as a run of consecutive segments at any depth,
    which is what the ruleset file has always claimed the entries do.
    """
    parts = rel_path.replace("\\", "/").strip("/").split("/")
    for glob in globs:
        wanted = [segment for segment in glob.split("/") if segment and segment != "**"]
        if not wanted:
            continue
        for start in range(len(parts) - len(wanted) + 1):
            if all(fnmatch(parts[start + i], wanted[i]) for i in range(len(wanted))):
                return True
    return False


def drop_excluded_paths(candidates: list[dict], globs: list[str]) -> list[dict]:
    """Findings whose sink sits in excluded code. Judged on the sink rather
    than the source: the sink is where the finding is reported, and taint
    arriving from a test helper into production code is still a finding
    about the production code."""
    return [c for c in candidates if not path_is_excluded(c["sink_file"], globs)]


def relpath(target: Path, abs_path: str) -> str:
    try:
        return str(Path(abs_path).resolve().relative_to(target.resolve()))
    except ValueError:
        return abs_path


def extract_source_location(result: dict, target: Path):
    """Pull the taint source location out of --dataflow-traces output, if present.

    Semgrep's --dataflow-traces JSON encodes taint_source as a tagged tuple:
    ["CliLoc", [{"path": ..., "start": {"line": ...}, ...}, "<var name>"]]
    (or ["ToCtx", [...]] in some rule shapes) -- not a plain {"location": ...}
    dict, which is easy to assume by reading the schema name alone.
    """
    trace = result.get("extra", {}).get("dataflow_trace")
    if not trace:
        return None
    source = trace.get("taint_source")
    if not source or not isinstance(source, list) or len(source) < 2:
        return None
    payload = source[1]
    if not isinstance(payload, list) or not payload:
        return None
    loc = payload[0]
    if not isinstance(loc, dict) or "start" not in loc:
        return None
    return {
        "file": relpath(target, loc.get("path", "")),
        "line": loc.get("start", {}).get("line"),
    }


def normalize(raw: dict, target: Path) -> list[dict]:
    candidates = []
    for result in raw.get("results", []):
        sink_file = relpath(target, result["path"])
        sink_line = result["start"]["line"]

        source_loc = extract_source_location(result, target)
        if source_loc and source_loc["line"] is not None:
            source_file, source_line = source_loc["file"], source_loc["line"]
            is_intraprocedural = source_file == sink_file
        else:
            # No dataflow trace available (plain pattern rule, not taint mode) —
            # treat the match location as both source and sink for now.
            source_file, source_line = sink_file, sink_line
            is_intraprocedural = True

        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        if metadata.get("hawkeye_language") == "cpp" and Path(sink_file).suffix.lower() == ".h":
            if not is_cpp_path(target / sink_file):
                continue
        if not passes_cpp_validator(result, target):
            continue
        cpp_details = cpp_candidate_details(result, target)
        dedup_key = sha256(f"{source_file}:{source_line}:{sink_file}:{sink_line}")

        start = result.get("start", {})
        end = result.get("end", {})

        candidates.append({
            "rule_id": result.get("check_id"),
            "message": cpp_details.get("message", (extra.get("message") or "").strip()),
            "severity": extra.get("severity"),
            "cwe": metadata.get("cwe"),
            "owasp": metadata.get("owasp"),
            "source_file": source_file,
            "source_line": source_line,
            "sink_file": sink_file,
            "sink_line": sink_line,
            "sink_column": start.get("col"),
            "sink_end_line": end.get("line"),
            "sink_end_column": end.get("col"),
            "code_snippet": _matched_source(result, target),
            "dedup_key": dedup_key,
            "is_intraprocedural": is_intraprocedural,
            "verification_mode": metadata.get("hawkeye_verification", "dataflow"),
            "rule_confidence": cpp_details.get("rule_confidence", metadata.get("confidence")),
            "rule_remediation": metadata.get("hawkeye_remediation", ""),
            "static_analysis": cpp_details.get("static_analysis"),
        })
    return candidates


def _matched_source(result: dict, target: Path) -> str:
    """Read the exact matched source span; Semgrep redacts `extra.lines`."""
    try:
        path = Path(result["path"])
        if not path.is_absolute():
            path = target / path
        data = path.read_bytes()
        start = int(result["start"]["offset"])
        end = int(result["end"]["offset"])
        return data[start:end].decode("utf-8", errors="replace")
    except (KeyError, TypeError, ValueError, OSError):
        return ""


def cwe_ids(candidate: dict) -> set[str]:
    """The bare `CWE-nnn` ids on a candidate. Semgrep reports the field as a
    list of full descriptions in production and older fixtures use a plain
    string, so both shapes are accepted (same reason render._cwe_text does)."""
    cwe = candidate.get("cwe")
    listed = cwe if isinstance(cwe, list) else ([cwe] if cwe else [])
    return {str(c).split(":")[0].strip().upper() for c in listed if c}


def drop_out_of_scope(candidates: list[dict], out_of_scope: frozenset[str]) -> list[dict]:
    """Candidates whose weakness has no source -> sink path to judge.

    This tool's scope is dataflow: externally controlled data reaching a
    dangerous operation. A rule matching a static property of the code -- a
    weak hash, a missing cookie flag, a disabled certificate check -- gives
    the verify stage nothing to trace, and it answers the question it was not
    asked. The same empty checkServerTrusted() came back "not reachable" in
    one run and "reachable, the untrusted input is the peer's certificate" in
    the next; both readings are defensible, which is why the finding does not
    belong in a report whose column heading is reachability.

    Runs before dedup(), while each candidate still carries exactly one rule
    and one CWE: a (source, sink) pair that an in-scope rule *also* hit
    survives on that rule's candidate and merges normally.

    A candidate with no CWE at all is kept. The list in ruleset.yml is a
    denylist for that reason -- an unclassified weakness stays in the scan,
    because a false negative costs more than a false positive.
    """
    if not out_of_scope:
        return candidates
    return [c for c in candidates if not (cwe_ids(c) and cwe_ids(c) <= out_of_scope)]


def dedup(candidates: list[dict]) -> list[dict]:
    """Merge candidates that share the same (source, sink) pair; keep every
    distinct rule_id that hit that pair instead of silently dropping any."""
    merged: dict[str, dict] = {}
    for c in candidates:
        key = c["dedup_key"]
        if key not in merged:
            merged[key] = {**c, "rule_ids": [c["rule_id"]], "messages": [c["message"]]}
        else:
            merged[key]["rule_ids"].append(c["rule_id"])
            merged[key]["messages"].append(c["message"])
            if c.get("verification_mode") != merged[key].get("verification_mode"):
                # A dataflow rule sharing the location still needs its
                # source-to-sink judgement; only all-static groups bypass it.
                merged[key]["verification_mode"] = "dataflow"
    return list(merged.values())


# Lines a copied-and-renamed Java module differs by, and the only ones the
# copy fingerprint is allowed to ignore. Everything else has to match byte
# for byte, so two files that merely share a name never collapse.
_COPY_IGNORED_PREFIXES = ("package ", "import ")


def _copy_fingerprint(target: Path, rel_path: str, cache: dict[str, str]) -> str:
    if rel_path not in cache:
        try:
            text = (Path(target) / rel_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            # Unreadable: fall back to the path itself so this candidate can
            # only ever match itself. Failing to read a file must not merge
            # two findings that might be unrelated.
            cache[rel_path] = f"path:{rel_path}"
        else:
            body = [
                line.rstrip()
                for line in text.splitlines()
                if not line.lstrip().startswith(_COPY_IGNORED_PREFIXES)
            ]
            cache[rel_path] = sha256("\n".join(body))
    return cache[rel_path]


def dedup_copies(candidates: list[dict], target: Path) -> list[dict]:
    """Merge candidates that are the same code shipped at two paths.

    Real Java repos carry the same module twice -- a service and its
    "-platform" fork, a vendored copy, a module renamed into a different
    package. Semgrep reports both, and dedup() above cannot merge them
    because its key is built from paths. The verify stage then spends two
    LLM calls on identical code and, at this project's measured ~16%
    run-to-run flip rate, frequently returns two different verdicts for it:
    on the vmscode corpus 8 of 72 candidates were copies, and 4 of those 8
    pairs disagreed with themselves. A report that judges the same lines
    both reachable and not reachable is worse than one that judges them
    once.

    The surviving candidate keeps the other paths in `duplicate_locations`
    so the report can still point at every copy -- this drops a verify call,
    never a location.

    Line numbers are part of the key, so two copies whose import blocks are
    different lengths simply will not collapse. That is deliberate: the
    fingerprint proves the files are the same, and the line number proves
    the finding is at the same place in them.
    """
    fingerprints: dict[str, str] = {}
    merged: dict[tuple, dict] = {}
    for c in candidates:
        key = (
            _copy_fingerprint(target, c["source_file"], fingerprints), c["source_line"],
            _copy_fingerprint(target, c["sink_file"], fingerprints), c["sink_line"],
            tuple(sorted(c.get("rule_ids") or [c.get("rule_id")])),
        )
        if key not in merged:
            merged[key] = {**c, "duplicate_locations": []}
        else:
            merged[key]["duplicate_locations"].append(c["sink_file"])
    return list(merged.values())


def parse_llm_json(raw_text: str) -> dict:
    if raw_text is None:
        # A provider can return an empty/filtered completion (seen with a
        # newer, less-tested OpenAI-compatible endpoint) rather than
        # unparseable text -- scanner/verify.py's call_llm already treats
        # any JSONDecodeError here as one verifier_failed finding instead
        # of aborting the whole scan; this folds "no content at all" into
        # that same existing, intentional degrade path instead of raising
        # an unhandled AttributeError that would abort it.
        raise json.JSONDecodeError("empty response from provider", "", 0)
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    return json.loads(text.strip())
