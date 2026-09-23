"""Java type resolution for the call graph: which class a call's receiver is.

index.py used to record a Java call as name + arity and nothing else, so
`executor.refine(x)` reached every `refine(1)` in the workspace. On a real
multi-module codebase that is not a few stray edges: HA_Benchmark's 412
cases share class and method names across packages, and every sink ended up
reachable from every request handler (see traverse._java_call_can_reach).

This reads what the source states and no more: the file's package and
imports, the declared types of fields, parameters and locals, and the class
named in a static call, a `new` or a cast. No inference beyond that -- a
receiver that is itself a call result, a lambda parameter or a generic type
variable stays unknown, and an unknown receiver keeps the old name + arity
edge. Resolving a name that is not a workspace type at all yields `?Name`,
one that is a workspace type the imports did not pin down yields `~Name`;
model.Call.target_qualified documents what traversal does with each.
"""
import re
from collections import ChainMap
from dataclasses import dataclass, field

from tree_sitter import Node

from scanner.callgraph.syntax import _text

TYPE_DECLARATIONS = ("class_declaration", "interface_declaration",
                     "enum_declaration", "record_declaration")
PRIMITIVES = frozenset({"byte", "short", "int", "long", "float", "double", "boolean", "char", "void", "var"})


@dataclass
class Workspace:
    """Every type the workspace declares, by qualified and by bare name."""
    known: set[str] = field(default_factory=set)
    by_simple: dict[str, set[str]] = field(default_factory=dict)

    def add(self, qualified: str) -> None:
        self.known.add(qualified)
        self.by_simple.setdefault(qualified.rsplit(".", 1)[-1], set()).add(qualified)


def package_of(root: Node, src: bytes) -> str:
    for child in root.children:
        if child.type == "package_declaration":
            for part in child.children:
                if part.type in ("scoped_identifier", "identifier"):
                    return _text(part, src)
    return ""


def declared_types(root: Node, src: bytes, package: str) -> dict[str, str]:
    """Bare name -> qualified name for every type declared in one file,
    nested ones included (`Outer.Inner` is `package.Outer.Inner`)."""
    found: dict[str, str] = {}

    def walk(node: Node, prefix: str) -> None:
        for child in node.children:
            if child.type in TYPE_DECLARATIONS:
                name = child.child_by_field_name("name")
                if name is None:
                    continue
                qualified = f"{prefix}.{_text(name, src)}" if prefix else _text(name, src)
                found.setdefault(_text(name, src), qualified)
                body = child.child_by_field_name("body")
                if body is not None:
                    walk(body, qualified)
            elif child.type in ("program", "class_body", "interface_body", "enum_body",
                                "enum_body_declarations"):
                walk(child, prefix)

    walk(root, package)
    return found


def _strip_type(text: str) -> str:
    """`final List<Map<String, Foo>>[]` -> `List`; annotations, generics,
    array brackets and varargs dots all go."""
    text = re.sub(r"@[\w.]+(\([^)]*\))?\s*", "", text)
    while "<" in text:
        stripped = re.sub(r"<[^<>]*>", "", text)
        if stripped == text:
            break
        text = stripped
    text = text.replace("...", "").replace("[]", "")
    text = re.sub(r"\b(final)\b", "", text)
    return text.strip()


class FileScope:
    """Resolves type names the way javac would inside one file: types the
    file declares, then single-type imports, then the file's own package,
    then on-demand imports."""

    def __init__(self, root: Node, src: bytes, workspace: Workspace):
        self.package = package_of(root, src)
        self.workspace = workspace
        self.local_types = declared_types(root, src, self.package)
        self.single: dict[str, str] = {}
        self.on_demand: list[str] = []
        for child in root.children:
            if child.type != "import_declaration":
                continue
            if any(c.type == "static" for c in child.children):
                continue
            name = next((_text(c, src) for c in child.children
                         if c.type in ("scoped_identifier", "identifier")), "")
            if not name:
                continue
            if any(c.type == "asterisk" for c in child.children):
                self.on_demand.append(name)
            else:
                self.single[name.rsplit(".", 1)[-1]] = name

    def resolve(self, text: str, type_params: frozenset[str] = frozenset()) -> str:
        name = _strip_type(text)
        if not name or name in PRIMITIVES:
            return ""
        if "." in name:
            if name in self.workspace.known:
                return name
            head, rest = name.split(".", 1)
            outer = self.resolve(head, type_params)
            if outer and outer[0] not in "?~" and f"{outer}.{rest}" in self.workspace.known:
                return f"{outer}.{rest}"
            if head[:1].islower():
                # A package-qualified name outside the workspace.
                return "?" + name.rsplit(".", 1)[-1]
            name = name.rsplit(".", 1)[-1]
        if name in type_params:
            return ""
        if name in self.local_types:
            return self.local_types[name]
        if name in self.single:
            imported = self.single[name]
            return imported if imported in self.workspace.known else "?" + name
        own_package = f"{self.package}.{name}" if self.package else name
        if own_package in self.workspace.known:
            return own_package
        for package in self.on_demand:
            if f"{package}.{name}" in self.workspace.known:
                return f"{package}.{name}"
        if name in self.workspace.by_simple:
            return "~" + name
        return "?" + name


def type_parameter_names(node: Node, src: bytes) -> set[str]:
    params = node.child_by_field_name("type_parameters")
    if params is None:
        return set()
    names = set()
    for child in params.children:
        if child.type == "type_parameter":
            ident = next((c for c in child.children if c.type in ("type_identifier", "identifier")), None)
            if ident is not None:
                names.add(_text(ident, src))
    return names


def supertype_texts(node: Node, src: bytes) -> list[str]:
    """The written supertypes of a type declaration: `extends` class,
    `implements` list, and an interface's own `extends` list."""
    texts = []
    for child in node.children:
        if child.type in ("superclass", "super_interfaces", "extends_interfaces"):
            for part in child.children:
                if part.type in ("type_identifier", "scoped_type_identifier", "generic_type"):
                    texts.append(_text(part, src))
                elif part.type == "type_list":
                    texts.extend(_text(t, src) for t in part.children if t.is_named)
    return texts


def field_types(body: Node | None, src: bytes, scope: FileScope, type_params: frozenset[str]) -> dict[str, str]:
    """Field name -> resolved type, for the fields a class body declares
    directly. Read up front because a field is usable above its declaration."""
    found: dict[str, str] = {}
    if body is None:
        return found
    for child in body.children:
        if child.type == "field_declaration":
            declared = child.child_by_field_name("type")
            if declared is None:
                continue
            resolved = scope.resolve(_text(declared, src), type_params)
            for declarator in child.children:
                if declarator.type == "variable_declarator":
                    name = declarator.child_by_field_name("name")
                    if name is not None:
                        found[_text(name, src)] = resolved
    return found


def record_component_types(node: Node, src: bytes, scope: FileScope, type_params: frozenset[str]) -> dict[str, str]:
    params = node.child_by_field_name("parameters")
    return parameter_types(params, src, scope, type_params) if params is not None else {}


def parameter_types(params: Node | None, src: bytes, scope: FileScope, type_params: frozenset[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    if params is None:
        return found
    for child in params.children:
        if child.type == "formal_parameter":
            declared, name = child.child_by_field_name("type"), child.child_by_field_name("name")
        elif child.type == "spread_parameter":
            declared = next((c for c in child.children if c.is_named and c.type != "modifiers"), None)
            declarator = next((c for c in child.children if c.type == "variable_declarator"), None)
            name = declarator.child_by_field_name("name") if declarator is not None else None
        else:
            continue
        if declared is not None and name is not None:
            found[_text(name, src)] = scope.resolve(_text(declared, src), type_params)
    return found


@dataclass
class Scope:
    """What the walk knows about names at one point in a file."""
    file: FileScope
    fields: ChainMap = field(default_factory=ChainMap)
    locals: dict[str, str] | None = None
    type_params: frozenset[str] = frozenset()

    def declare_locals(self, node: Node, src: bytes) -> None:
        """Record a local variable, enhanced-for variable or try resource."""
        if self.locals is None:
            return
        if node.type == "local_variable_declaration":
            declared = node.child_by_field_name("type")
            if declared is None:
                return
            for declarator in node.children:
                if declarator.type != "variable_declarator":
                    continue
                name = declarator.child_by_field_name("name")
                if name is None:
                    continue
                text = _text(declared, src)
                if text == "var":
                    value = declarator.child_by_field_name("value")
                    resolved = self.expression_type(value, src) if value is not None else ""
                else:
                    resolved = self.file.resolve(text, self.type_params)
                self.locals[_text(name, src)] = resolved
        elif node.type in ("enhanced_for_statement", "resource"):
            declared, name = node.child_by_field_name("type"), node.child_by_field_name("name")
            if declared is not None and name is not None:
                text = _text(declared, src)
                self.locals[_text(name, src)] = "" if text == "var" else self.file.resolve(text, self.type_params)

    def expression_type(self, node: Node, src: bytes) -> str:
        """The resolved type of a call receiver, or "" when the source does
        not state it."""
        kind = node.type
        if kind == "identifier":
            name = _text(node, src)
            if self.locals is not None and name in self.locals:
                return self.locals[name]
            if name in self.fields:
                return self.fields[name]
            # `Util.run()` names a class; `LOGGER.info()` is a constant from
            # somewhere we did not read, and `helper.run()` an inherited field.
            if name[:1].isupper() and not name.isupper():
                return self.file.resolve(name, self.type_params)
            return ""
        if kind == "field_access":
            obj, member = node.child_by_field_name("object"), node.child_by_field_name("field")
            if obj is not None and obj.type == "this" and member is not None:
                return self.fields.get(_text(member, src), "")
            text = _text(node, src)
            last = text.rsplit(".", 1)[-1]
            if re.fullmatch(r"[\w.]+", text) and last[:1].isupper() and not last.isupper():
                return self.file.resolve(text, self.type_params)
            return ""
        if kind in ("object_creation_expression", "cast_expression"):
            declared = node.child_by_field_name("type")
            return self.file.resolve(_text(declared, src), self.type_params) if declared is not None else ""
        if kind == "parenthesized_expression":
            inner = next((c for c in node.children if c.is_named), None)
            return self.expression_type(inner, src) if inner is not None else ""
        return ""
