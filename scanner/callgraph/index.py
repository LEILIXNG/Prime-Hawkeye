"""Parsing a workspace into methods, call sites and a type hierarchy.

The tree-sitter walk itself, plus the two passes that finish the index: the
transitive supertype closure, and the MyBatis mapper linking.
"""
import re
from pathlib import Path

from tree_sitter import Node, Parser

from scanner.callgraph.cpp_index import index_cpp_workspace
from scanner.callgraph.csharp_index import index_csharp_workspace
from scanner.callgraph.entrypoints import _entry_reason
from scanner.callgraph.go_index import index_go_workspace
from scanner.callgraph.java_types import (TYPE_DECLARATIONS, FileScope, Scope, Workspace, declared_types,
                                          field_types, package_of, parameter_types, record_component_types,
                                          supertype_texts, type_parameter_names)
from scanner.callgraph.js_index import index_js_workspace
from scanner.callgraph.kotlin_index import index_kotlin_workspace
from scanner.callgraph.model import Call, Index, Method, Owner
from scanner.callgraph.mybatis import index_mybatis_mappers
from scanner.callgraph.php_index import index_php_workspace
from scanner.callgraph.python_index import index_python_workspace
from scanner.callgraph.ruby_index import index_ruby_workspace
from scanner.callgraph.rust_index import index_rust_workspace
from scanner.callgraph.scala_index import index_scala_workspace
from scanner.callgraph.scala_routes import index_play_routes
from scanner.callgraph.syntax import _annotation_names, _arity, _owner_of, _parser, _text


# A method name that shows up only as a string literal is the fingerprint of
# reflective dispatch, and it is the evidence a human looks for when nothing
# calls a method. Measured: OaSysUserManage.insertObj() has no call site
# anywhere in the corpus, and its name appears in OaEnum.java as
# INSERT_USER("insertUser", "user", "insertObj", "N") -- a registry the
# application walks with Method.invoke. Only identifier-shaped literals are
# kept, so ordinary message text does not fill the index.
IDENTIFIER_LITERAL = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]{2,63}")


def index_workspace(root: Path, parser: Parser | None = None) -> Index:
    """Parse supported Java, Python, JS/TS, Go, C++, Rust, C#, PHP, Ruby,
    Kotlin and Scala files into one shared index of methods and call
    sites, then link the MyBatis mapper statements and Play routes onto
    the methods they name.

    One index rather than one per language: Method, Call and Owner (see
    model.py) carry nothing language-specific, and traverse.py's BFS does
    not care which parser produced a node it is walking through. A repo
    that is only ever one language pays nothing extra -- the other
    language's glob just matches no files. `parser` is Java's own parser
    only, kept as a constructor argument for the tests that already pass
    one in; every other language's parsing always builds its own.
    """
    parser = parser or _parser()
    index = Index()
    # Two passes over Java: every declared type has to be known before any
    # file's names can be resolved against the workspace (java_types.py).
    parsed: list[tuple[str, bytes, Node]] = []
    workspace = Workspace()
    for path in sorted(root.rglob("*.java")):
        try:
            src = path.read_bytes()
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        tree = parser.parse(src).root_node
        parsed.append((rel, src, tree))
        for qualified in declared_types(tree, src, package_of(tree, src)).values():
            workspace.add(qualified)
    for rel, src, tree in parsed:
        scope = Scope(file=FileScope(tree, src, workspace))
        _walk(tree, src, rel, index, current=None, owner=Owner(), scope=scope)
    index_python_workspace(root, index)
    index_js_workspace(root, index)
    index_go_workspace(root, index)
    index_cpp_workspace(root, index)
    index_rust_workspace(root, index)
    index_csharp_workspace(root, index)
    index_php_workspace(root, index)
    index_ruby_workspace(root, index)
    index_kotlin_workspace(root, index)
    index_scala_workspace(root, index)
    _build_ancestors(index)
    _build_qualified_ancestors(index)
    index_mybatis_mappers(root, index)
    index_play_routes(root, index)
    return index


def _build_ancestors(index: Index) -> None:
    """Transitive closure of Index.supertypes, cycle-safe. Java forbids cyclic
    inheritance, but this reads whatever is on disk, including half-written or
    generated sources."""
    def walk(name: str, seen: set[str]) -> frozenset[str]:
        if name in index.ancestors:
            return index.ancestors[name]
        reached: set[str] = set()
        for parent in index.supertypes.get(name, ()):
            if parent in seen:
                continue
            reached.add(parent)
            reached |= walk(parent, seen | {parent})
        result = frozenset(reached)
        index.ancestors[name] = result
        return result

    for type_name in list(index.supertypes):
        walk(type_name, {type_name})


def _build_qualified_ancestors(index: Index) -> None:
    """The same closure over Index.qualified_supertypes."""
    def walk(name: str, seen: set[str]) -> frozenset[str]:
        if name in index.qualified_ancestors:
            return index.qualified_ancestors[name]
        reached: set[str] = set()
        for parent in index.qualified_supertypes.get(name, ()):
            if parent in seen:
                continue
            reached.add(parent)
            reached |= walk(parent, seen | {parent})
        result = frozenset(reached)
        index.qualified_ancestors[name] = result
        return result

    for type_name in list(index.qualified_supertypes):
        walk(type_name, {type_name})


def _walk(node: Node, src: bytes, rel: str, index: Index,
          current: Method | None, owner: Owner, scope: Scope) -> None:
    if node.type in TYPE_DECLARATIONS:
        outer = owner.qualified or scope.file.package
        owner = _owner_of(node, src)
        if owner.name:
            index.supertypes[owner.name] = owner.supertypes
            owner.qualified = f"{outer}.{owner.name}" if outer else owner.name
            type_params = scope.type_params | type_parameter_names(node, src)
            index.qualified_supertypes[owner.qualified] = tuple(
                q for q in (scope.file.resolve(t, type_params) for t in supertype_texts(node, src)) if q)
            fields = field_types(node.child_by_field_name("body"), src, scope.file, type_params)
            if node.type == "record_declaration":
                fields |= record_component_types(node, src, scope.file, type_params)
            scope = Scope(file=scope.file, fields=scope.fields.new_child(fields),
                          locals=None, type_params=frozenset(type_params))
    elif node.type == "object_creation_expression" and any(c.type == "class_body" for c in node.children):
        # `new X509TrustManager() { ... }`: the type being instantiated is the
        # only name the methods inside have, and it is the informative one.
        type_node = node.child_by_field_name("type")
        if type_node is not None:
            owner = Owner(name=_text(type_node, src).split("<")[0].split(".")[-1], anonymous=True)
            body = next(c for c in node.children if c.type == "class_body")
            # The enclosing method's locals stay visible inside the body.
            scope = Scope(file=scope.file,
                          fields=scope.fields.new_child(field_types(body, src, scope.file, scope.type_params)),
                          locals=dict(scope.locals) if scope.locals is not None else None,
                          type_params=scope.type_params)

    if node.type in ("method_declaration", "constructor_declaration"):
        type_params = scope.type_params | type_parameter_names(node, src)
        scope = Scope(file=scope.file, fields=scope.fields, type_params=frozenset(type_params),
                      locals=parameter_types(node.child_by_field_name("parameters"), src, scope.file,
                                             frozenset(type_params)))
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            reason, definitive = _entry_reason(node, src, owner)
            return_node = node.child_by_field_name("type")
            modifiers = next((c for c in node.children if c.type == "modifiers"), None)
            current = Method(
                file=rel,
                name=_text(name_node, src),
                arity=_arity(node, "parameters"),
                return_type=_text(return_node, src) if return_node is not None else "",
                owner=owner,
                overrides_supertype=(modifiers is not None
                                     and "Override" in _annotation_names(modifiers, src)),
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                entry_reason=reason,
                entry_definitive=definitive,
            )
            index.methods.append(current)
    elif node.type == "string_literal":
        text = _text(node, src).strip('"')
        if IDENTIFIER_LITERAL.fullmatch(text):
            index.string_literals.setdefault(text, set()).add(rel)
    elif node.type in ("local_variable_declaration", "enhanced_for_statement", "resource"):
        scope.declare_locals(node, src)
    elif node.type == "method_invocation":
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            receiver = node.child_by_field_name("object")
            is_self = receiver is not None and receiver.type in ("this", "super")
            index.calls.append(Call(
                file=rel,
                callee=_text(name_node, src),
                arity=_arity(node, "arguments"),
                line=node.start_point[0] + 1,
                caller=current,
                receiver_is_self=is_self,
                implicit_self=receiver is None,
                target_qualified=(scope.expression_type(receiver, src)
                                  if receiver is not None and not is_self else ""),
            ))

    for child in node.children:
        _walk(child, src, rel, index, current, owner, scope)
