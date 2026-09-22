"""B + D: the code context handed to the verify stage.

Split out of core.py once it crossed the size CLAUDE.md section 2 asks for a
split at. The division is by stage: core.py runs semgrep and turns its output
into candidates (A/C), this builds what the LLM actually reads (B/D).

build_caller_context is the D stage docs/framework.md specifies and Phase 1
skipped -- without it the prompt shows one method and asks a question its
callers answer.
"""
from pathlib import Path

from scanner.callgraph import MAX_DEPTH, callers_of, enclosing_method, trace_to_entry_points


CONTEXT_WINDOW = 15  # lines of code above/below each location to include

# A fixed window cuts methods in half. Measured over the VulnerableApp
# corpus, 21 of 51 candidates had their enclosing method truncated by
# CONTEXT_WINDOW, the worst losing 31 lines above the sink -- and what sits
# above a sink is the signature, which is where @RequestParam / @GetMapping
# say whether the value is user-controlled at all. That is the question the
# verify stage is being asked, so the window snaps to the enclosing method.
#
# tree-sitter puts a method's annotations inside its span, so snapping picks
# up @VulnerableAppRequestMapping and friends for free -- checked, not
# assumed. The cap stops one long method from crowding out the call paths
# printed below it; past the cap the head is what is kept, because the head
# is the signature.
MAX_METHOD_LINES = 120
METHOD_HEAD_LINES = 12


def _source_lines(target: Path, rel_path: str) -> list[str] | None:
    full_path = target / rel_path
    if not full_path.exists():
        return None
    return full_path.read_text(encoding="utf-8", errors="replace").splitlines()


def _numbered(lines: list[str], start: int, end: int) -> str:
    """Lines `start`..`end`, 1-based and inclusive, clamped to the file."""
    start = max(1, start)
    end = min(len(lines), end)
    return "\n".join(f"{i:>5} | {lines[i - 1]}" for i in range(start, end + 1))


def read_window(target: Path, rel_path: str, line: int, window: int) -> str:
    lines = _source_lines(target, rel_path)
    if lines is None or line is None:
        return f"(file not found: {rel_path})"
    return _numbered(lines, line - window, line + window)


def read_method_window(target: Path, rel_path: str, line: int, index,
                       window: int = CONTEXT_WINDOW) -> str:
    """The whole method containing `line`, or a plain window around it when
    there is no method to snap to.

    Falls back to read_window whenever the call graph cannot place the line
    -- a field initialiser, a static block, a file that failed to parse --
    so the verify stage never loses context just because the index came up
    empty.
    """
    lines = _source_lines(target, rel_path)
    if lines is None or line is None:
        return f"(file not found: {rel_path})"
    method = enclosing_method(index, rel_path, line) if index is not None else None
    if method is None:
        return _numbered(lines, line - window, line + window)

    if method.end_line - method.start_line + 1 <= MAX_METHOD_LINES:
        return _numbered(lines, method.start_line, method.end_line)

    head_end = method.start_line + METHOD_HEAD_LINES - 1
    tail_start = max(line - window, head_end + 1)
    tail_end = min(line + window, method.end_line)
    if tail_start > tail_end:
        return _numbered(lines, method.start_line, head_end)
    omitted = tail_start - head_end - 1
    return (
        _numbered(lines, method.start_line, head_end)
        + f"\n      | ... {omitted} lines omitted ...\n"
        + _numbered(lines, tail_start, tail_end)
    )


MAX_CALLER_CHAINS = 4  # a shared sink can have many; four is enough to show the pattern
CALLER_WINDOW = 8


def _identity(method):
    """A method's identity for closure walking: the owning type rather than
    the file, because a module shipped twice under two paths (see
    dedup_copies) otherwise looks like each copy calling the other, and a
    method calling itself is not somebody else calling it."""
    return (method.owner.name, method.name, method.arity)


def _owner_phrase(method) -> str:
    if not method.owner.name:
        return ""
    if method.owner.anonymous:
        return f"an anonymous {method.owner.name}"
    if method.owner.supertypes:
        return f"{method.owner.name} ({', '.join(method.owner.supertypes)})"
    return method.owner.name


MAX_CLOSURE = 200  # a runaway closure is not worth walking to describe it
MAX_LEAVES_SHOWN = 4


def _closure_leaves(index, method):
    """The methods the call chains into `method` actually terminate at.

    Reporting these instead of guessing is the point. The three candidates
    whose chains "died in internal code" on the vmscode corpus all terminate
    at DictionaryApp.main() -- a SpringApplication.run() bootstrap, so they
    run at startup and no request reaches them, which is a definite answer
    rather than the shrug the old message offered.
    """
    seen = {_identity(method)}
    frontier, leaves = [method], []
    while frontier and len(seen) < MAX_CLOSURE:
        nxt = []
        for current in frontier:
            callers = [c for c in callers_of(index, current)
                       if _identity(c.caller) != _identity(current)]
            if not callers:
                leaves.append(current)
            for call in callers:
                key = _identity(call.caller)
                if key in seen:
                    continue
                seen.add(key)
                nxt.append(call.caller)
        frontier = nxt
    return leaves


def _describe(method) -> str:
    owner = f"{method.owner.name}." if method.owner.name else ""
    return f"{owner}{method.name}() in {method.file}"


def _reflective_dispatch_note(index, name: str) -> str:
    """Where a method's name turns up as a string literal.

    When nothing calls a method, this is the evidence a human goes looking
    for, and it was decisive here: OaSysUserManage.insertObj() has no call
    site anywhere, and its name sits in OaEnum.java as
    INSERT_USER("insertUser", "user", "insertObj", "N") -- a registry walked
    with Method.invoke, which no call graph can follow.
    """
    files = sorted(getattr(index, "string_literals", {}).get(name, ()))
    if not files:
        return ""
    shown = ", ".join(files[:2]) + (f" (+{len(files) - 2} more)" if len(files) > 2 else "")
    return (f' Its name appears as a string literal in {shown}, which is what dispatch '
            f"by reflection or a name-keyed registry looks like.")


def _no_entry_point(index, method) -> str:
    """Why no call path was found -- which is three different situations, and
    the verify stage answers them differently.

    The single sentence this replaced ("either it is dead code, or it is called
    from a framework or injection point this name-based call graph cannot see")
    described all three at once, and reads as a shrug. It is the line behind
    most of the corpus's `uncertain` verdicts, and behind a pair of false
    positives: an empty checkServerTrusted() in an anonymous X509TrustManager
    came back "reachable" because nothing told the model that no call site in
    the codebase hands it anything.
    """
    if method is None:
        return ("The call graph could not place this line inside a method -- a field "
                "initialiser, a static block, or a file it failed to parse -- so it has "
                "nothing to say about how a request reaches it.")

    others = [c for c in callers_of(index, method)
              if _identity(c.caller) != _identity(method)]
    if others:
        leaves = _closure_leaves(index, method)
        mains = [m for m in leaves if m.name == "main"]
        if mains and len(mains) == len(leaves):
            where = ", ".join(_describe(m) for m in mains[:MAX_LEAVES_SHOWN])
            return (f"Every path into {method.name}() terminates at {where}. That is the "
                    "application's startup path, not a request handler: whatever reaches this "
                    "code runs at boot, with values chosen by whoever deployed it rather than "
                    "by a caller of the running service.")
        if leaves:
            listed = "; ".join(_describe(m) for m in leaves[:MAX_LEAVES_SHOWN])
            extra = f" (+{len(leaves) - MAX_LEAVES_SHOWN} more)" if len(leaves) > MAX_LEAVES_SHOWN else ""
            overrides = [m for m in leaves if m.overrides_supertype and m.owner.supertypes]
            note = ""
            if overrides:
                supers = sorted({t for m in overrides for t in m.owner.supertypes})
                note = (f" Those are overrides of {', '.join(supers)} that nothing calls by "
                        "name, so they are dispatched through the interface rather than from "
                        "a call site this graph can see.")
                note += _reflective_dispatch_note(index, overrides[0].name)
            return (f"No chain from a request entry point reaches {method.name}() within "
                    f"{MAX_DEPTH} hops. Following its callers as far as they go, every path "
                    f"ends at: {listed}{extra}.{note}")
        return (f"{method.name}() is called only from other internal code, and no chain from a "
                f"request entry point reaches it within {MAX_DEPTH} hops.")

    owner = _owner_phrase(method)
    where = f", declared in {owner}," if owner else ""
    if method.overrides_supertype or method.owner.anonymous:
        return (f"Nothing in this codebase calls {method.name}(){where} and it overrides a "
                "supertype method, so it is a callback: whatever consumes that type invokes "
                "it, not application code. No call site here hands it an argument, so judge "
                "the parameters by what that type's contract supplies."
                + _reflective_dispatch_note(index, method.name))

    return (f"Nothing in this codebase calls {method.name}(){where} so no call site shows what "
            "its parameters hold. It is either unused, or invoked by name through reflection, "
            "configuration or generated code."
            + _reflective_dispatch_note(index, method.name))


def build_caller_context(target: Path, candidate: dict, index) -> str:
    """The call paths by which a request can reach this sink, with the code
    at each entry point.

    This is the half of the picture semgrep cannot supply: its taint analysis
    stops at the method boundary, so a sink reached through a service call
    reports a local variable as its "source" and the verify stage is left
    guessing whether that variable is user-controlled. Where that guessing has
    actually gone wrong on this corpus -- CommandInjection's shared ping
    helper -- the reason becomes visible here: four request handlers call it,
    and they do not all validate first.
    """
    chains = trace_to_entry_points(index, candidate["sink_file"], candidate["sink_line"])
    if not chains:
        method = enclosing_method(index, candidate["sink_file"], candidate["sink_line"])
        return "### Call path\n" + _no_entry_point(index, method)
    if chains == [[]]:
        return "### Call path\nThe sink sits directly inside a request handler."

    blocks = ["### Call paths from request entry points to this sink"]
    for chain in chains[:MAX_CALLER_CHAINS]:
        hops = " <- ".join(f"{c.caller.name}() at {c.file}:{c.line}" for c in chain)
        entry = chain[-1].caller
        blocks.append(
            f"\n{hops}\nEntry point: {entry.name}() in {entry.file}, reached via {entry.entry_reason}\n"
            + read_window(target, entry.file, entry.start_line, CALLER_WINDOW)
        )
    if len(chains) > MAX_CALLER_CHAINS:
        blocks.append(f"\n(+{len(chains) - MAX_CALLER_CHAINS} more call paths not shown)")
    return "\n".join(blocks)


MAX_CALLEE_BODIES = 3
CALLEE_MAX_LINES = 40

# Value transformers get shown; boolean predicates do not. The block's
# purpose is "what did this do to the value", and a predicate answers a
# different question -- whether the flow was guarded -- which the sink's own
# code already shows at the call site.
#
# This is not a style preference, it is the measured difference between the
# two cases that moved. sanitizeToolName() returns the string that reaches
# the sink, and showing it corrected BenchmarkResultWriter:41. isUrlValid()
# returns a boolean, and showing it broke SSRFVulnerability:129 and :146 in
# both runs it was present for: handed the body, the model wrote "the
# endpoint explicitly validates the URL" and called them sanitized, where
# seeing only the call site it had correctly said a denylist of one metadata
# IP is insufficient. Prefacing the block with a caution did not help.
PREDICATE_RETURN_TYPES = frozenset({"boolean", "Boolean"})


def build_callee_context(target: Path, candidate: dict, index) -> str:
    """The bodies of the project's own methods called on the way to the sink.

    The caller context answers "can a request get here". This answers the
    other half, "was it cleaned on the way in", and without it the verify
    stage guesses. Measured on the corpus: BenchmarkResultWriter's sink is
    `dir.resolve(sanitizeToolName(...) + "-results.json")`, and
    sanitizeToolName -- which strips everything outside [a-z0-9_-] and so
    makes traversal impossible -- sits below the enclosing method, outside
    any window anchored on the sink. The verifier called it exploitable and
    said why: "if sanitizeToolName doesn't properly neutralize '..'".

    Only calls that resolve to a method in the index are shown, which is
    what keeps this small: library calls like Paths.get or Files.copy
    resolve to nothing and drop out on their own, with no allowlist to
    maintain. Only calls at or before the sink line are considered, since a
    value reaching the sink was computed before it.
    """
    method = enclosing_method(index, candidate["sink_file"], candidate["sink_line"])
    if method is None:
        return ""
    here = (method.file, method.name, method.arity, method.start_line)
    sink_line = candidate["sink_line"]

    resolved: list = []
    seen = set()
    calls = [c for c in index.calls
             if c.caller is not None
             and (c.caller.file, c.caller.name, c.caller.arity, c.caller.start_line) == here
             and c.line <= sink_line]
    for call in sorted(calls, key=lambda c: sink_line - c.line):
        matches = index.methods_named(call.callee, call.arity)
        # The call graph matches on name and arity with no type resolution,
        # so an ambiguous name resolves to every same-shaped method in the
        # project. For the caller chains that is a deliberate trade -- an
        # extra plausible chain costs a few lines. Here it is not: printing
        # some unrelated class's toString() as "the method called on the way
        # to the sink" states something false. PasswordResetVulnerability
        # :333 pulled in three unrelated toString() bodies this way.
        #
        # One narrowing before giving up: prefer a match declared in the
        # caller's own file. A private helper with a generic name
        # (doSomething, process, handle) that every file in a project
        # redeclares is not actually ambiguous -- Java resolves `new
        # Test().doSomething(...)` to *this* file's Test at compile time,
        # every time, because target_owner isn't tracked for Java calls
        # (unlike C++, see model.py's Call.target_owner) to tell them apart
        # by type. Same-file is the cheap proxy that recovers the same
        # answer without it. Measured on a 351-case OWASP Benchmark sample:
        # 230 of 351 files (65%) declare their own same-named/same-arity
        # private inner helper, so this was not a rare edge case -- it was
        # silently dropping the one piece of context (does the helper
        # actually forward the tainted value, or substitute a hardcoded
        # constant, per that Benchmark's own decoy convention) the verify
        # stage needed most, on the majority of candidates in the sample.
        # If the caller's own file still doesn't narrow it to exactly one,
        # this falls back to the original conservative drop.
        if len(matches) != 1:
            same_file = [m for m in matches if m.file == method.file]
            if len(same_file) == 1:
                matches = same_file
            else:
                continue
        callee = matches[0]
        key = (callee.file, callee.name, callee.arity, callee.start_line)
        if key in seen or key == here:
            continue
        seen.add(key)
        if callee.return_type in PREDICATE_RETURN_TYPES:
            continue
        resolved.append(callee)

    if not resolved:
        return ""

    # Prefacing this block with a caution -- "a check being present is not
    # evidence it is sufficient" -- was tried against the SSRF regression
    # described above. It did not recover those two labels, and across four
    # verify passes its presence or absence never separated from the ~16%
    # run-to-run flip rate the verifier has on this corpus. Left out: the
    # filters above fixed the regression structurally, and paying for
    # wording on every prompt needs better evidence than a 20-label set can
    # currently give.
    blocks = ["### Methods called on the way to the sink"]
    for callee in resolved[:MAX_CALLEE_BODIES]:
        end = min(callee.end_line, callee.start_line + CALLEE_MAX_LINES - 1)
        lines = _source_lines(target, callee.file)
        rendered = _numbered(lines, callee.start_line, end) if lines else "(file not found)"
        elided = "" if end >= callee.end_line else f"\n      | ... {callee.end_line - end} more lines ..."
        blocks.append(f"\n{callee.name}() in {callee.file}\n{rendered}{elided}")
    if len(resolved) > MAX_CALLEE_BODIES:
        blocks.append(f"\n(+{len(resolved) - MAX_CALLEE_BODIES} more called methods not shown)")
    return "\n".join(blocks)


def build_context(target: Path, candidate: dict, index=None) -> str:
    sink_block = read_method_window(target, candidate["sink_file"], candidate["sink_line"], index)
    if candidate["source_file"] == candidate["sink_file"] and candidate["source_line"] == candidate["sink_line"]:
        parts = [f"### {candidate['sink_file']} (source == sink)\n{sink_block}"]
    else:
        source_block = read_method_window(target, candidate["source_file"], candidate["source_line"], index)
        parts = [
            f"### Source: {candidate['source_file']}\n{source_block}\n\n"
            f"### Sink: {candidate['sink_file']}\n{sink_block}"
        ]

    if index is not None:
        parts.append(build_caller_context(target, candidate, index))
        callees = build_callee_context(target, candidate, index)
        if callees:
            parts.append(callees)
    return "\n\n".join(parts)


def build_prompt(template: str, candidate: dict, code_context: str) -> str:
    return template.format(
        rule_ids=", ".join(candidate.get("rule_ids", [candidate.get("rule_id", "")])),
        message=" / ".join(candidate.get("messages", [candidate.get("message", "")])),
        cwe=candidate.get("cwe"),
        source_file=candidate["source_file"],
        source_line=candidate["source_line"],
        sink_file=candidate["sink_file"],
        sink_line=candidate["sink_line"],
        code_context=code_context,
    )
