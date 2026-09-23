"""Walking the graph backwards: from a sink location to the request entry
points that can reach it."""
import re

from scanner.callgraph.model import ANY_ARITY, MAX_DEPTH, Call, Index, Method


def _short_type(value: str) -> str:
    value = re.sub(r"\b(?:const|volatile|signed|unsigned)\b", " ", value)
    for token in ("*", "&", "&&"):
        value = value.replace(token, " ")
    value = " ".join(value.split())
    return value.split("::")[-1] if value else ""


def _typed_call_can_reach(call: Call, method: Method) -> bool:
    if call.target_owner and method.owner.name:
        if _short_type(call.target_owner) != _short_type(method.owner.name):
            return False
    if not call.argument_types or not method.parameter_types:
        return True
    if len(call.argument_types) != len(method.parameter_types):
        return True
    numeric = {"short", "int", "long", "float", "double", "size_t"}
    strings = {"string-literal", "char", "string", "string_view"}
    for actual, expected in zip(call.argument_types, method.parameter_types):
        left, right = _short_type(actual), _short_type(expected)
        if not left or not right or left == right or re.fullmatch(r"[A-Z]\w*", right):
            continue
        if left in numeric and right in numeric:
            continue
        if left in strings and right in strings:
            continue
        return False
    return True


def enclosing_method(index: Index, file: str, line: int) -> Method | None:
    """The innermost method containing `line`. Nested declarations (anonymous
    classes, lambdas holding methods) mean several can match; the smallest
    span is the one the sink actually sits in."""
    file = file.replace("\\", "/")
    holding = [m for m in index.methods if m.file == file and m.start_line <= line <= m.end_line]
    return min(holding, key=lambda m: m.end_line - m.start_line, default=None)


def _self_call_can_reach(index: Index, call: Call, method: Method) -> bool:
    """Whether a `this.x()` / `super.x()` call site could be calling `method`.

    Only ever consulted for self-receiver calls, and only ever used to *drop*
    an edge: such a call resolves inside the caller's own class hierarchy,
    never in an unrelated one. Owners we could not name are let through -- a
    lost caller costs the answer, and this exists to remove edges that are
    provably wrong, not merely unproven.

    Both directions of the hierarchy count. `this.x()` in a subclass can land
    on a base-class method, and `this.x()` in an abstract base lands on the
    subclass override -- that is the template-method pattern, and checking
    only one direction quietly deletes it.
    """
    caller_owner, target_owner = call.caller.owner, method.owner
    if not caller_owner.name or not target_owner.name:
        return True
    if target_owner.name == caller_owner.name:
        return True
    return (target_owner.name in index.ancestors.get(caller_owner.name, ())
            or caller_owner.name in index.ancestors.get(target_owner.name, ()))


def _qualified_related(index: Index, a: str, b: str) -> bool:
    """Same type, or one is a supertype of the other: a call on an interface
    lands on its implementations, and a call on a subclass lands on a method
    it inherits."""
    return (a == b or a in index.qualified_ancestors.get(b, ())
            or b in index.qualified_ancestors.get(a, ()))


def _java_call_can_reach(index: Index, call: Call, method: Method) -> bool:
    """Whether a Java call site could be calling `method`, using the receiver
    type index.py resolved. Only ever drops an edge whose types are known on
    both sides and provably unrelated; anything unknown keeps the plain
    name + arity edge.

    Measured on HA_Benchmark (412 cases, one Maven project, many same-named
    classes and methods across packages): with name + arity alone, 189
    methods were named refine/1, a sink's method had 140 direct callers, and
    every sink reached every one of the 412 request handlers. The four
    shortest chains the context builder prints held the case's real entry
    point for 1 case in 412, so the verify stage judged each candidate on
    some other case's call chain -- and never saw the sanitizer on its own.
    """
    caller_owner = call.caller.owner
    if call.receiver_is_self:
        # _self_call_can_reach already ran on bare names, and lets an empty
        # one through -- which a MyBatis statement's Owner always is, so
        # `this.enrich(v)` in any class reached every <select id="enrich">.
        if not caller_owner.qualified or not method.owner.qualified:
            return True
        return _qualified_related(index, caller_owner.qualified, method.owner.qualified)
    if call.implicit_self:
        if not caller_owner.qualified or not method.owner.qualified or method.file == call.file:
            return True
        return _qualified_related(index, caller_owner.qualified, method.owner.qualified)
    target = call.target_qualified
    if not target or not method.owner.qualified:
        return True
    if target.startswith("?"):
        # A type the workspace does not declare. It can still be a
        # workspace class's supertype (Runnable, HttpServlet), which
        # index.py records under the same `?Name` spelling.
        return target in index.qualified_ancestors.get(method.owner.qualified, ())
    if target.startswith("~"):
        name = target[1:]
        return (not method.owner.name or method.owner.name == name
                or name in index.ancestors.get(method.owner.name, ())
                or method.owner.name in index.ancestors.get(name, ()))
    return _qualified_related(index, target, method.owner.qualified)


def callers_of(index: Index, method: Method) -> list[Call]:
    return [c for c in index.calls
            if c.callee == method.name
            and (method.arity == ANY_ARITY or c.arity == method.arity)
            and c.caller is not None
            and (not c.receiver_is_self or _self_call_can_reach(index, c, method))
            and _typed_call_can_reach(c, method)
            and _java_call_can_reach(index, c, method)]


def trace_to_entry_points(index: Index, file: str, line: int, max_depth: int = MAX_DEPTH) -> list[list[Call]]:
    """Call chains from a request entry point down to the method holding
    (file, line), nearest caller first.

    Only chains that actually reach an entry point are returned: a chain that
    peters out in internal code says nothing the sink's own context did not
    already say.

    Breadth-first with a *shared* visited set, one shortest chain per entry
    point reached. The depth-first version this replaces carried a per-chain
    visited set, so it enumerated every distinct path and its cost grew
    exponentially with max_depth: on the vmscode corpus, depth 5 produced
    1,914 chains in 5.2s and depth 7 produced 33,248 in 99s, to feed a
    context builder that prints four of them. Expanding each method once is
    what makes a depth worth having affordable.

    Nothing is lost by expanding once. An entry point is found by reaching
    it as some method's caller, and every reachable method still gets
    expanded -- just via whichever route found it first, which under BFS is
    a shortest one. If anything the shared set reaches further, because a
    method entered by its shortest route has more of the depth budget left.
    Four chains to four different handlers also say more than four
    permutations of the route to one.
    """
    start = enclosing_method(index, file, line)
    if start is None:
        return []
    if start.entry_definitive:
        return [[]]

    found: list[list[Call]] = []
    visited = {(start.file, start.owner.name, start.name, start.arity, start.parameter_types)}
    frontier: list[tuple[Method, list[Call]]] = [(start, [])]
    for _ in range(max_depth):
        next_frontier: list[tuple[Method, list[Call]]] = []
        for method, chain in frontier:
            for call in callers_of(index, method):
                caller = call.caller
                key = (caller.file, caller.owner.name, caller.name, caller.arity,
                       caller.parameter_types)
                if key in visited:
                    continue
                visited.add(key)
                extended = chain + [call]
                if caller.is_entry_point:
                    found.append(extended)
                else:
                    next_frontier.append((caller, extended))
        if not next_frontier:
            break
        frontier = next_frontier
    if not found and start.is_entry_point:
        # Only a hinted entry (a request-shaped parameter type) and nothing
        # calls it: the hint is the best answer available, so report it as
        # the handler rather than as unreachable.
        return [[]]
    return sorted(found, key=len)
