"""MyBatis mapper XML, linked onto the Java interfaces it implements.

A mapper statement is a sink location like any other, but it sits in XML that
no Java call site names directly. `<mapper namespace="com.x.XMapper">` plus
`<select id="listX">` is the other half of `xMapper.listX(...)`, and this
module turns that pair into an ordinary Method node, so the rest of the graph
traces through a mapper without knowing XML exists.
"""
from pathlib import Path
from xml.parsers import expat

from scanner.callgraph.model import ANY_ARITY, Index, Method, Owner


# MyBatis statement tags that a mapper interface method maps onto. <sql> is
# deliberately absent: it is a fragment other statements <include>, not
# something Java calls by name.
MYBATIS_STATEMENT_TAGS = frozenset({"select", "insert", "update", "delete"})


def _mybatis_statements(src: bytes) -> tuple[str, list[tuple[str, int, int]]]:
    """`(namespace, [(statement id, start line, end line)])` for a MyBatis
    mapper XML; `("", [])` for any other XML.

    expat rather than a regex because the span has to be right for
    enclosing_method() to place a sink inside a statement, and statements
    nest <if>/<foreach>/<include>/CDATA freely. Parameter-entity parsing is
    turned off explicitly: every mapper opens with a DOCTYPE pointing at
    mybatis.org, and ingested code is untrusted data that must never cause
    a fetch (CLAUDE.md section 4).
    """
    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    namespace = ""
    open_statements: list[tuple[str | None, int]] = []
    statements: list[tuple[str, int, int]] = []

    def on_start(name: str, attrs: dict) -> None:
        nonlocal namespace
        tag = name.split(":")[-1]
        if tag == "mapper" and not namespace:
            namespace = attrs.get("namespace", "")
        elif tag in MYBATIS_STATEMENT_TAGS:
            open_statements.append((attrs.get("id"), parser.CurrentLineNumber))

    def on_end(name: str) -> None:
        if name.split(":")[-1] not in MYBATIS_STATEMENT_TAGS or not open_statements:
            return
        statement_id, start_line = open_statements.pop()
        if statement_id:
            statements.append((statement_id, start_line, parser.CurrentLineNumber))

    parser.StartElementHandler = on_start
    parser.EndElementHandler = on_end
    try:
        parser.Parse(src, True)
    except expat.ExpatError:
        # Malformed, or not XML at all. Nothing to link; the sink keeps the
        # plain window it had before.
        return "", []
    return namespace, statements


def index_mybatis_mappers(root: Path, index: Index) -> None:
    """Give every MyBatis mapper statement a Method, so a sink inside the
    XML can be traced back through the Java that calls it.

    Measured on the vmscode corpus: 25 of 64 candidates sat in mapper XML
    and every single one reported "no request entry point", because this
    module only ever parsed .java. The XML carries the missing link itself
    -- <mapper namespace="com.x.XMapper"> names the interface exactly and
    <select id="listX"> names the method -- so unlike the name matching
    everywhere else here, this half is resolved rather than guessed.

    A statement gets one Method. Where the interface declares overloads of
    that name, or cannot be found at all, that Method takes ANY_ARITY:
    registering one node per overload would make trace_to_entry_points pick
    just one of them and lose the others' callers.
    """
    by_file: dict[str, list[Method]] = {}
    for method in index.methods:
        by_file.setdefault(method.file, []).append(method)

    for path in sorted(root.rglob("*.xml")):
        try:
            src = path.read_bytes()
        except OSError:
            continue
        namespace, statements = _mybatis_statements(src)
        # No namespace means no mapper: requiring it keeps an unrelated XML
        # that happens to contain <select id="..."> out of the call graph.
        if not namespace or not statements:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        suffix = namespace.replace(".", "/") + ".java"
        declared = next((m for f, m in by_file.items() if f.endswith(suffix)), [])
        for statement_id, start_line, end_line in statements:
            arities = {m.arity for m in declared if m.name == statement_id}
            index.methods.append(Method(
                file=rel,
                name=statement_id,
                arity=arities.pop() if len(arities) == 1 else ANY_ARITY,
                start_line=start_line,
                end_line=end_line,
                # The namespace *is* the mapper interface's qualified name,
                # so a call on a typed mapper field reaches only its own XML.
                # The bare name stays empty: the older checks read an empty
                # owner as "unknown, keep the edge", which is still true here.
                owner=Owner(qualified=namespace),
            ))
