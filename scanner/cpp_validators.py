"""Optional high-confidence validators for C++ Semgrep candidates.

Most rules need no second pass. A rule opts in through
`metadata.hawkeye_validator`; registered validators can reject an AST match
when the pinned engine deliberately normalizes away a distinction the rule
needs, such as scalar versus array delete.
"""
import re
from pathlib import Path
from typing import Callable

from scanner.callgraph.cpp_syntax import _declarator_name, _parser
from scanner.languages import _code_without_comments_and_literals, iter_cpp_files


Validator = Callable[[dict, Path], bool]
VALIDATORS: dict[str, Validator] = {}


def validator(name: str):
    def register(func: Validator) -> Validator:
        VALIDATORS[name] = func
        return func
    return register


def passes_cpp_validator(result: dict, target: Path) -> bool:
    name = (result.get("extra", {}).get("metadata", {})
            .get("hawkeye_validator"))
    if not name:
        return True
    names = name if isinstance(name, list) else [name]
    return all(registered and registered(result, target)
               for registered in (VALIDATORS.get(item) for item in names))


def cpp_candidate_details(result: dict, target: Path) -> dict:
    validators = (result.get("extra", {}).get("metadata", {})
                  .get("hawkeye_validator"))
    names = validators if isinstance(validators, list) else [validators]
    if "memcpy-bounds" in names:
        status, capacity, copied, func = _memcpy_bounds_status(result, target)
        if status == "overflow":
            return {
                "message": f"{func} length {copied} exceeds destination capacity {capacity}.",
                "rule_confidence": "HIGH",
                "static_analysis": "definite-overflow",
            }
        return {"static_analysis": "bounds-unknown"} if status == "unknown" else {}
    if "string-copy-bounds" in names:
        status, dest_capacity, src_capacity = _string_copy_bounds_status(result, target)
        if status == "overflow":
            return {
                "message": (f"strcpy source (up to {src_capacity} bytes) exceeds "
                            f"destination capacity {dest_capacity}."),
                "rule_confidence": "HIGH",
                "static_analysis": "definite-overflow",
            }
        return {"static_analysis": "bounds-unknown"} if status == "unknown" else {}
    if "gets-always-unsafe" in names:
        return {
            "message": "gets() reads unbounded input with no destination size limit.",
            "rule_confidence": "HIGH",
            "static_analysis": "definite-overflow",
        }
    return {}


def _result_path(result: dict, target: Path) -> Path:
    path = Path(result["path"])
    return path if path.is_absolute() else target / path


def _walk(node):
    yield node
    for child in node.named_children:
        yield from _walk(child)


@validator("standard-function-call")
def _standard_function_call(result: dict, target: Path) -> bool:
    """Reject an unqualified call shadowed by a local function or macro."""
    try:
        source = _result_path(result, target).read_bytes()
        start = int(result["start"]["offset"])
        end = int(result["end"]["offset"])
    except (KeyError, TypeError, ValueError, OSError):
        return False
    matched = source[start:end].decode("utf-8", errors="replace").lstrip()
    call = re.search(r"([A-Za-z_]\w*)\s*\(", matched)
    if not call:
        return False
    # Explicit global/std qualification is an intentional library call.
    if matched.startswith("::") or matched.startswith("std::"):
        return True
    called = call.group(1)

    for node in _walk(_parser().parse(source).root_node):
        if node.type == "function_definition":
            if _declarator_name(node.child_by_field_name("declarator"), source) == called:
                return False
        elif node.type == "declaration":
            for child in _walk(node):
                if child.type == "function_declarator" and _declarator_name(child, source) == called:
                    return False
        elif node.type in {"preproc_function_def", "preproc_def"}:
            name = node.child_by_field_name("name")
            if name is not None and source[name.start_byte:name.end_byte].decode() == called:
                return False
    return True


@validator("new-delete-mismatch")
def _new_delete_mismatch(result: dict, target: Path) -> bool:
    """Confirm the deleted object ultimately came from the opposite form."""
    try:
        source = _result_path(result, target).read_bytes()
        start = int(result["start"]["offset"])
        end = int(result["end"]["offset"])
    except (KeyError, TypeError, ValueError, OSError):
        return False

    # Semgrep offsets are byte offsets. Decoding the whole file first changes
    # their positions on CRLF files because Python normalizes newlines in text
    # mode, and it also makes offsets drift after non-ASCII source text.
    matched = source[start:end].decode("utf-8", errors="replace")
    deletion = re.search(
        r"\bdelete\s*(\[\s*\])?\s*((?:this\s*->\s*)?"
        r"[A-Za-z_]\w*(?:(?:\s*->\s*|\s*\.\s*)[A-Za-z_]\w*)*)",
        matched,
    )
    if not deletion:
        return False
    delete_array = deletion.group(1) is not None
    pointer = _symbol(deletion.group(2))
    code = _code_without_comments_and_literals(
        source[:start].decode("utf-8", errors="replace")
    )
    allocation_array = _allocation_form(
        pointer, code, source.decode("utf-8", errors="replace")
    )
    if allocation_array is None:
        allocation_array = _caller_allocation_form(source, start, pointer, target)
    if allocation_array is None:
        return False
    return allocation_array != delete_array



# memcpy/memmove/strncpy all take (destination, source, length) and share the
# exact overflow condition -- length compared against destination's declared
# capacity -- so one bounds check covers all three (see build_juliet_subset.py's
# 2026 measurement: Juliet's memmove/strncpy variants were previously invisible
# to this rule entirely since only "memcpy" was matched).
_BOUNDED_COPY_FUNCS = ("memcpy", "memmove", "strncpy")


@validator("memcpy-bounds")
def _memcpy_bounds(result: dict, target: Path) -> bool:
    """Drop a bounded copy only when its constant length is proven to fit."""
    status, _capacity, _copied, _func = _memcpy_bounds_status(result, target)
    return status != "safe"


def _memcpy_bounds_status(result: dict, target: Path) -> tuple[str, int | None, int | None, str | None]:
    loaded = _load_match(result, target)
    if loaded is None:
        return "invalid", None, None, None
    source, matched, start = loaded
    func = next((f for f in _BOUNDED_COPY_FUNCS
                 if re.search(rf"(?:\b|::){f}\s*\(", matched)), None)
    if func is None:
        return "unknown", None, None, None
    call = _call_arguments(matched, func)
    if call is None or len(call) < 3:
        return "unknown", None, None, func
    destination, length = call[0], call[2]
    if re.fullmatch(r"sizeof\s*\(\s*" + re.escape(destination.strip()) + r"\s*\)"
                    r"(?:\s*-\s*\d+)?", length.strip()):
        return "safe", None, None, func
    capacity = _buffer_capacity(source[:start], destination)
    copied = _integer(length)
    if capacity is None or copied is None:
        return "unknown", capacity, copied, func
    return ("overflow" if copied > capacity else "safe"), capacity, copied, func


@validator("string-copy-bounds")
def _string_copy_bounds(result: dict, target: Path) -> bool:
    """Drop an strcpy only when the source is provably no larger than the
    destination. Reuses _buffer_capacity on both arguments -- it already
    recognizes any declared fixed-size char array, dest or source alike."""
    status, _dest, _src = _string_copy_bounds_status(result, target)
    return status != "safe"


def _string_copy_bounds_status(result: dict, target: Path) -> tuple[str, int | None, int | None]:
    loaded = _load_match(result, target)
    if loaded is None:
        return "invalid", None, None
    source, matched, start = loaded
    call = _call_arguments(matched, "strcpy")
    if call is None or len(call) < 2:
        return "unknown", None, None
    destination, src = call[0], call[1]
    before = source[:start]
    dest_capacity = _buffer_capacity(before, destination)
    src_capacity = _buffer_capacity(before, src)
    if dest_capacity is None or src_capacity is None:
        return "unknown", dest_capacity, src_capacity
    return ("overflow" if src_capacity > dest_capacity else "safe"), dest_capacity, src_capacity


@validator("gets-always-unsafe")
def _gets_always_unsafe(result: dict, target: Path) -> bool:
    """gets() has no length-limited form -- every call is the vulnerability,
    unlike the other CPP rules there is no "proven safe" case to drop."""
    return True


@validator("null-dereference")
def _null_dereference(result: dict, target: Path) -> bool:
    loaded = _load_match(result, target)
    if loaded is None:
        return False
    source, matched, start = loaded
    dereference = re.search(
        r"(?:\*\s*|\b)((?:this\s*->\s*)?[A-Za-z_]\w*)"
        r"\s*(?:->|\[|(?=\s*$))",
        matched.strip(),
    )
    if dereference is None:
        return False
    pointer = _symbol(dereference.group(1))
    code = _code_without_comments_and_literals(source[:start])
    if _has_terminating_null_guard(code, pointer):
        return False
    return _resolves_to_null(code, pointer, set())


@validator("hardcoded-secret")
def _hardcoded_secret(result: dict, target: Path) -> bool:
    loaded = _load_match(result, target)
    if loaded is None:
        return False
    source, matched, start = loaded
    assignment = re.search(r"=\s*(.+?)\s*;?$", matched, re.DOTALL)
    if assignment is None:
        return False
    return _expression_has_literal(
        assignment.group(1), _code_without_comments(source[:start]), set()
    )


@validator("dangerous-file-operation")
def _dangerous_file_operation(result: dict, target: Path) -> bool:
    loaded = _load_match(result, target)
    if loaded is None:
        return False
    source, matched, start = loaded
    name_match = re.search(r"(?:::|std::)*([A-Za-z_]\w*)\s*\(", matched)
    if name_match is None:
        return False
    name = name_match.group(1)
    arguments = _call_arguments(matched, name) or []
    if name in {"mktemp", "tmpnam"}:
        return True
    if name == "chmod" and len(arguments) >= 2:
        mode = _integer(arguments[1])
        return mode is not None and bool(mode & 0o002)
    if name == "fopen" and len(arguments) >= 2:
        path, mode = arguments[0].strip(), arguments[1].strip()
        writing = bool(re.fullmatch(r'(?:u8|u|U|L)?\"[^\"]*[wa+][^\"]*\"', mode))
        predictable = bool(re.search(
            r'(?:/tmp/|/var/tmp/|\\\\temp\\\\|\\\\tmp\\\\)',
            path,
            re.IGNORECASE,
        ))
        if not predictable and re.fullmatch(r"[A-Za-z_]\w*", path):
            previous = _last_assignment(
                _code_without_comments_and_literals(source[:start]), path
            )
            predictable = bool(previous and re.search(r"\b(?:tmpnam|mktemp)\s*\(", previous))
        return writing and predictable
    if name == "open" and len(arguments) >= 3 and "O_CREAT" in arguments[1]:
        mode = _integer(arguments[2])
        return mode is not None and bool(mode & 0o002)
    return False


def _load_match(result: dict, target: Path) -> tuple[str, str, int] | None:
    try:
        raw = _result_path(result, target).read_bytes()
        start = int(result["start"]["offset"])
        end = int(result["end"]["offset"])
    except (KeyError, TypeError, ValueError, OSError):
        return None
    return (
        raw.decode("utf-8", errors="replace"),
        raw[start:end].decode("utf-8", errors="replace"),
        len(raw[:start].decode("utf-8", errors="replace")),
    )


def _symbol(value: str) -> str:
    return re.sub(r"\s+", "", value).removeprefix("this->")


def _allocation_form(pointer: str, code: str, full_source: str) -> bool | None:
    aliases = {pointer}
    forms: list[bool] = []
    assignment = re.compile(
        r"(?P<left>(?:this->)?[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)"
        r"\s*=\s*(?P<right>[^;]+);"
    )
    for found in assignment.finditer(code):
        left, right = _symbol(found.group("left")), found.group("right").strip()
        simple = re.fullmatch(
            r"(?:this\s*->\s*)?[A-Za-z_]\w*(?:(?:\s*->\s*|\s*\.\s*)[A-Za-z_]\w*)*",
            right,
        )
        if left in aliases:
            if re.match(r"^new\b", right):
                forms.append(bool(re.search(r"\[[^\]]*\]", right)))
            elif simple:
                aliases.add(_symbol(right))
            else:
                called = re.match(r"([A-Za-z_]\w*)\s*\(", right)
                if called:
                    returned = _returned_allocation_form(full_source, called.group(1))
                    if returned is not None:
                        forms.append(returned)
        elif simple and _symbol(right) in aliases:
            aliases.add(left)
    if not forms:
        # Constructor/destructor member ownership often spans methods. Keep
        # it only when every assignment in the file agrees on the form.
        for alias in aliases:
            pattern = re.compile(re.escape(alias) + r"\s*=\s*new\b([^;]+);")
            forms.extend(bool(re.search(r"\[[^\]]*\]", item.group(1)))
                         for item in pattern.finditer(full_source))
    return forms[-1] if forms and len(set(forms)) == 1 else None


def _returned_allocation_form(source: str, function: str) -> bool | None:
    definition = re.search(
        rf"\b{re.escape(function)}\s*\([^)]*\)\s*\{{(?P<body>.*?)\}}",
        source,
        re.DOTALL,
    )
    if definition is None:
        return None
    returned = re.findall(r"\breturn\s+new\b([^;]+);", definition.group("body"))
    forms = {bool(re.search(r"\[[^\]]*\]", value)) for value in returned}
    return next(iter(forms)) if len(forms) == 1 else None


def _caller_allocation_form(source: bytes, offset: int, pointer: str,
                            target: Path) -> bool | None:
    tree = _parser().parse(source)
    function = next((
        node for node in _walk(tree.root_node)
        if node.type == "function_definition"
        and node.start_byte <= offset <= node.end_byte
    ), None)
    if function is None:
        return None
    declarator = function.child_by_field_name("declarator")
    name = _declarator_name(declarator, source)
    params = next((node for node in _walk(declarator)
                   if node.type == "parameter_list"), None)
    if not name or params is None:
        return None
    names = [
        _declarator_name(param.child_by_field_name("declarator"), source)
        for param in params.named_children
        if param.type == "parameter_declaration"
    ]
    if pointer not in names:
        return None
    parameter_index = names.index(pointer)
    forms: list[bool] = []
    for path in iter_cpp_files(target):
        try:
            caller_source = path.read_bytes()
        except OSError:
            continue
        caller_text = caller_source.decode("utf-8", errors="replace")
        caller_tree = _parser().parse(caller_source)
        for call in _walk(caller_tree.root_node):
            if call.type != "call_expression":
                continue
            called = call.child_by_field_name("function")
            if called is None or _declarator_name(called, caller_source) != name:
                continue
            args = call.child_by_field_name("arguments")
            if args is None or len(args.named_children) <= parameter_index:
                continue
            argument = caller_source[
                args.named_children[parameter_index].start_byte:
                args.named_children[parameter_index].end_byte
            ].decode("utf-8", errors="replace").strip()
            if re.match(r"^new\b", argument):
                forms.append(bool(re.search(r"\[[^\]]*\]", argument)))
            elif re.fullmatch(r"[A-Za-z_]\w*", argument):
                before = caller_source[:call.start_byte].decode("utf-8", errors="replace")
                found = _allocation_form(argument, before, caller_text)
                if found is not None:
                    forms.append(found)
    return forms[-1] if forms and len(set(forms)) == 1 else None


def _call_arguments(matched: str, name: str) -> list[str] | None:
    opened = re.search(rf"(?:\b|::){re.escape(name)}\s*\(", matched)
    if opened is None:
        return None
    text = matched[opened.end():]
    arguments: list[str] = []
    current: list[str] = []
    depth = 0
    quote = ""
    escaped = False
    for char in text:
        if quote:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
        elif char in "([{<":
            depth += 1
            current.append(char)
        elif char in ")]}>":
            if char == ")" and depth == 0:
                arguments.append("".join(current).strip())
                return arguments
            depth = max(0, depth - 1)
            current.append(char)
        elif char == "," and depth == 0:
            arguments.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    return None


def _integer(value: str) -> int | None:
    text = re.sub(r"[uUlL]+$", "", value.strip())
    try:
        if re.fullmatch(r"0[0-7]+", text):
            return int(text, 8)
        return int(text, 0)
    except ValueError:
        return None


def _buffer_capacity(source: str, destination: str) -> int | None:
    name_match = re.search(r"([A-Za-z_]\w*)\s*(?:\.data\s*\(\s*\))?\s*$",
                           destination.strip())
    if name_match is None:
        return None
    name = re.escape(name_match.group(1))
    forms = [
        rf"\b(?:char|unsigned\s+char|std::byte)\s+{name}\s*\[\s*(\d+)\s*\]",
        rf"\bstd::array\s*<\s*(?:char|unsigned\s+char|std::byte)\s*,\s*(\d+)\s*>\s*{name}\b",
        rf"\b{name}\s*=\s*new\s+(?:char|unsigned\s+char|std::byte)\s*\[\s*(\d+)\s*\]",
    ]
    found = [int(match.group(1)) for pattern in forms
             for match in re.finditer(pattern, source)]
    return found[-1] if found else None


def _last_assignment(code: str, name: str) -> str | None:
    escaped = re.escape(_symbol(name))
    matches = list(re.finditer(
        rf"(?:\b[A-Za-z_:][\w:\s<>*&]*\s+)?(?:this->)?{escaped}\s*=\s*([^;]+);",
        code,
    ))
    return matches[-1].group(1).strip() if matches else None


def _resolves_to_null(code: str, name: str, seen: set[str]) -> bool:
    symbol = _symbol(name)
    if symbol in seen:
        return False
    state = _last_assignment(code, symbol)
    if state is None:
        return False
    if re.fullmatch(
        r"(?:nullptr|NULL|0|static_cast\s*<[^>]*>\s*\(\s*nullptr\s*\))",
        state.strip(),
    ):
        return True
    alias = state.strip()
    return bool(re.fullmatch(r"[A-Za-z_]\w*", alias)
                and _resolves_to_null(code, alias, seen | {symbol}))


def _has_terminating_null_guard(code: str, pointer: str) -> bool:
    name = re.escape(_symbol(pointer))
    return bool(re.search(
        rf"if\s*\(\s*!\s*{name}\s*\)\s*"
        rf"(?:\{{[^}}]*(?:return|throw)\b[^}}]*\}}|(?:return|throw)\b[^;]*;)"
        rf"\s*$",
        code,
        re.DOTALL,
    ))


def _expression_has_literal(expression: str, code: str, seen: set[str]) -> bool:
    if re.search(r'(?:u8|u|U|L)?\"(?:\\.|[^\"\\])*\"', expression):
        return True
    identifier = expression.strip()
    if not re.fullmatch(r"[A-Za-z_]\w*", identifier) or identifier in seen:
        return False
    previous = _last_assignment(code, identifier)
    return bool(previous and _expression_has_literal(previous, code, seen | {identifier}))


def _code_without_comments(source: str) -> str:
    out: list[str] = []
    index = 0
    quote = ""
    escaped = False
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if quote:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            out.append(char)
            index += 1
            continue
        if char == "/" and following == "/":
            end = source.find("\n", index + 2)
            if end < 0:
                out.extend(" " * (len(source) - index))
                break
            out.extend(" " * (end - index))
            index = end
            continue
        if char == "/" and following == "*":
            end = source.find("*/", index + 2)
            end = len(source) - 2 if end < 0 else end
            block = source[index:end + 2]
            out.extend("\n" if item == "\n" else " " for item in block)
            index = end + 2
            continue
        out.append(char)
        index += 1
    return "".join(out)
