"""The call graph's data model: what a method, a call site and the index
holding them look like.

No parsing and no traversal, so every other module in the package imports
this one without pulling tree-sitter in with it.
"""
from dataclasses import dataclass, field


# An arity we could not read off a mapper interface, matched by callers_of()
# against any argument count. A mapper XML names its method but never its
# parameter list, so when the namespace lookup comes up empty a caller with
# the wrong arity is still a better answer than no caller at all -- the same
# trade this module's docstring makes for name matching generally.
ANY_ARITY = -1

# Hops from a sink back to a request handler. 3 was chosen when the walk was
# depth-first and every extra hop multiplied the work; with the breadth-first
# walk in trace_to_entry_points() the cost is flat enough to set this from
# the code instead. Measured on the vmscode corpus (64 candidates), candidates
# with no reachable entry point: depth 3 -> 22, depth 5 -> 14, depth 7 -> 13,
# depth 10 and 15 -> 13. So 7 is where a real layered Spring app saturates,
# not a round number: the last chain it recovers is TemplateUtil.writeFile <-
# ExportUtil x3 <- VulnerabilityService x3 <- an @PostMapping handler, checked
# hop by hop against the source. The whole sweep costs 1.8s.
#
# Raised to 20 once Java calls carried receiver types (java_types.py). 7
# only ever looked sufficient on deep code because name + arity matching
# connected nearly everything within a few hops -- through the wrong
# classes. HA_Benchmark's real chains run 2 to 19 hops (median 10); with
# typed edges, depth 7 finds 114 of its 412 real entry points, 12 finds 284,
# 20 finds all 412, and the whole 412-sink sweep still takes 6.6s. A chain
# prints as one short line per hop (context.build_caller_context), so a
# longer one costs the prompt little.
MAX_DEPTH = 20


@dataclass
class Owner:
    """The class, interface or anonymous class body a method is declared in.

    Tracked because "nothing calls this method" is not one situation but
    several, and the supertype is what tells them apart. An @Override nobody
    calls inside `new X509TrustManager() {...}` is a TLS callback the JDK
    invokes; the same shape inside a class implementing the application's own
    OaUpdateServiceInterface is a strategy the application dispatches, and can
    carry a message payload. Handing the verify stage the type instead of a
    shrug is the difference between a confident verdict and a coin flip.
    """
    name: str = ""
    supertypes: tuple[str, ...] = ()
    anonymous: bool = False
    # Package-qualified name (`com.northwind.accountposting.dao.TariffExecutor`),
    # Java only for now; empty everywhere else. `name` stays the bare name
    # because entry-point detection and Index.ancestors key on it. This is
    # what tells apart the five TariffExecutor classes a real multi-module
    # codebase can hold -- see traverse._java_call_can_reach.
    qualified: str = ""


@dataclass
class Method:
    file: str
    name: str
    arity: int
    start_line: int
    end_line: int
    return_type: str = ""
    owner: Owner = field(default_factory=Owner)
    # Optional language-specific signature information. Empty means the
    # parser could not prove a type, so traversal keeps the edge instead of
    # guessing. C++ uses this to separate same-arity overloads.
    parameter_types: tuple[str, ...] = ()
    parameter_names: tuple[str, ...] = ()
    overrides_supertype: bool = False
    entry_reason: str = ""
    # Whether entry_reason is proof or only a hint. A mapping annotation, or
    # a parameter the framework binds from the request, only ever appears on
    # a real handler. A parameter *type* does not: any helper can be handed
    # an HttpServletRequest or a MultipartFile, and treating those as proof
    # made trace_to_entry_points stop at the helper and never show the
    # handlers that call it -- which is where the validation lives.
    entry_definitive: bool = False

    @property
    def is_entry_point(self) -> bool:
        return bool(self.entry_reason)


@dataclass
class Call:
    file: str
    callee: str
    arity: int
    line: int
    caller: Method | None
    # `this.x()` / `super.x()`, which cannot land in an unrelated class. The
    # rest of the graph matches on name and arity alone, and `run()` is the
    # case that proves the cost: MockUserLoginInit.refreshMockUser() calls
    # `this.run()`, and without this flag that edge bridged into a completely
    # different module's OracleAQConsumer.run(), inventing a chain from a
    # @KafkaListener to a JMS connector it has nothing to do with.
    receiver_is_self: bool = False
    # A qualified/static receiver (Service::run) or the declared type of a
    # local receiver (service.run). Empty keeps the historical conservative
    # name+arity behaviour.
    target_owner: str = ""
    # Best-effort argument types. Unknown arguments are stored as empty
    # strings and never remove an edge.
    argument_types: tuple[str, ...] = ()
    argument_symbols: tuple[str, ...] = ()
    # Java's receiver type, resolved through the file's package and imports.
    # Three shapes: a package-qualified name of a workspace type; `?Name` for
    # a type that is not in the workspace at all (StringBuilder, List), which
    # can then reach no workspace method; `~Name` for a workspace type name
    # the imports did not pin down, matched by bare name. Empty means the
    # receiver's type could not be read (a call chain, a lambda parameter)
    # and the edge falls back to name + arity. Kept apart from target_owner
    # because that field's check compares bare names exactly, which would
    # cut interface dispatch -- the call is on the interface, the method on
    # the implementation.
    target_qualified: str = ""
    # Java call with no receiver at all (`helper(x)`): it lands in the
    # caller's own class hierarchy, its enclosing classes, or a static import.
    implicit_self: bool = False


@dataclass
class Index:
    methods: list[Method] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    # Type name -> its direct supertypes, and the transitive closure of that,
    # built once by index_workspace. Real hierarchies are more than one level
    # deep -- FileInfoDataUpload extends AbstractDeviceDataUpload extends
    # AbstractDataUpload -- and a one-level check silently drops the middle.
    supertypes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    ancestors: dict[str, frozenset[str]] = field(default_factory=dict)
    # Identifier-shaped string literal -> the files it appears in. Lets
    # "nothing calls this method" be followed by "but its name is a string
    # in OaEnum.java", which is the difference between a shrug and a lead.
    string_literals: dict[str, set[str]] = field(default_factory=dict)
    # supertypes/ancestors again, keyed and valued by Owner.qualified
    # (Java). Bare names cannot tell two same-named interfaces in different
    # packages apart, and dispatch through the wrong one is exactly the
    # cross-package edge the qualified names exist to remove.
    qualified_supertypes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    qualified_ancestors: dict[str, frozenset[str]] = field(default_factory=dict)

    def methods_named(self, name: str, arity: int) -> list[Method]:
        return [m for m in self.methods if m.name == name and m.arity == arity]
