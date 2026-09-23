"""Unit tests for scanner/callgraph.py.

The call graph exists to answer one question the sink's own file cannot:
can a request reach this method. Every test here is a small Java source
written to disk and parsed for real -- there are no hand-built index
fixtures, because the thing most likely to break is the tree-sitter node
walking, and a fixture would skip exactly that.
"""
from pathlib import Path

import pytest

from scanner.callgraph import (
    ANY_ARITY,
    Index,
    callers_of,
    enclosing_method,
    enclosing_method as _enclosing,
    index_workspace,
    trace_to_entry_points,
)


def workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


class TestIndexing:
    def test_finds_methods_and_their_arity(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                void none() {}
                void two(String a, int b) { helper(a); }
            }
        """}))
        by_name = {m.name: m for m in idx.methods}
        assert by_name["none"].arity == 0
        assert by_name["two"].arity == 2

    def test_records_call_sites_with_their_caller(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                void caller() { callee("x"); }
            }
        """}))
        call = next(c for c in idx.calls if c.callee == "callee")
        assert call.arity == 1 and call.caller.name == "caller"

    def test_paths_are_relative_and_posix(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"pkg/deep/A.java": "class A { void m() {} }"}))
        assert idx.methods[0].file == "pkg/deep/A.java"


class TestEntryPoints:
    def test_mapping_annotation_on_the_method(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                @GetMapping("/x")
                public String handler() { return ""; }
            }
        """}))
        assert idx.methods[0].entry_reason == "@GetMapping"

    def test_request_annotation_on_a_parameter(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                public String handler(@RequestParam String q) { return q; }
            }
        """}))
        assert "@RequestParam" in idx.methods[0].entry_reason

    def test_servlet_request_parameter_type(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                public String handler(HttpServletRequest request) { return ""; }
            }
        """}))
        assert "HttpServletRequest" in idx.methods[0].entry_reason

    def test_plain_method_is_not_an_entry_point(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                public String helper(String q) { return q; }
            }
        """}))
        assert idx.methods[0].entry_reason == "" and not idx.methods[0].is_entry_point


class TestEnclosingMethod:
    def test_picks_the_innermost_method(self, tmp_path):
        """An anonymous class inside a method puts one declaration inside
        another; the sink belongs to the tighter one."""
        src = """
            class A {
                void outer() {
                    Runnable r = new Runnable() {
                        public void run() { sink(); }
                    };
                }
            }
        """
        idx = index_workspace(workspace(tmp_path, {"A.java": src}))
        sink_line = next(i for i, l in enumerate(src.splitlines(), 1) if "sink()" in l)
        assert enclosing_method(idx, "A.java", sink_line).name == "run"

    def test_returns_none_outside_any_method(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": "class A {\n  int field = 1;\n}"}))
        assert enclosing_method(idx, "A.java", 2) is None

    def test_accepts_windows_separators(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"pkg/A.java": "class A { void m() { x(); } }"}))
        assert enclosing_method(idx, "pkg\\A.java", 1).name == "m"


class TestTraceToEntryPoints:
    CROSS_FILE = {
        "web/Controller.java": """
            class Controller {
                @GetMapping("/login")
                public String login(@RequestParam String username) {
                    return service.authenticate(username);
                }
            }
        """,
        "svc/Service.java": """
            class Service {
                public String authenticate(String username) {
                    return jdbc.query("SELECT * FROM u WHERE n='" + username + "'");
                }
            }
        """,
    }

    def test_finds_the_caller_in_another_file(self, tmp_path):
        """The case semgrep OSS cannot see: the sink is in Service.java and
        the only thing that makes it exploitable is in Controller.java."""
        idx = index_workspace(workspace(tmp_path, self.CROSS_FILE))
        sink = enclosing_method(idx, "svc/Service.java", 3)
        assert sink.name == "authenticate"

        chains = trace_to_entry_points(idx, "svc/Service.java", 4)
        assert len(chains) == 1
        assert chains[0][-1].caller.name == "login"
        assert chains[0][-1].caller.file == "web/Controller.java"

    def test_sink_already_in_a_handler_reports_an_empty_chain(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                @PostMapping("/x")
                public String handler(@RequestParam String q) { return exec(q); }
            }
        """}))
        assert trace_to_entry_points(idx, "A.java", 4) == [[]]

    def test_no_chain_when_nothing_reaches_the_method(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                void orphan() { exec("x"); }
            }
        """}))
        assert trace_to_entry_points(idx, "A.java", 3) == []

    def test_arity_has_to_match(self, tmp_path):
        """A same-named method with a different parameter count is a
        different method, and treating it as a caller would invent a path."""
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                @GetMapping("/x")
                public String handler(@RequestParam String q) { return helper(q, 1); }
                void helper(String a) { exec(a); }
            }
        """}))
        assert trace_to_entry_points(idx, "A.java", 5) == []

    def test_every_caller_of_a_shared_sink_is_reported(self, tmp_path):
        """CommandInjection's shape: one helper, several handlers, and only
        some of them validate. Showing one of them would be worse than
        showing none, because it reads as the whole story."""
        src = """
            class A {
                @GetMapping("/1")
                public String one(@RequestParam String q) { return helper(q); }
                @GetMapping("/2")
                public String two(@RequestParam String q) { return helper(validate(q)); }
                String helper(String a) { return exec(a); }
            }
        """
        idx = index_workspace(workspace(tmp_path, {"A.java": src}))
        sink_line = next(i for i, l in enumerate(src.splitlines(), 1) if "exec(a)" in l)
        chains = trace_to_entry_points(idx, "A.java", sink_line)
        assert sorted(c[-1].caller.name for c in chains) == ["one", "two"]

    def test_two_routes_to_one_handler_report_it_once(self, tmp_path):
        """The breadth-first walk expands each method once, so a diamond
        yields one shortest chain rather than one chain per route. The
        depth-first version returned both, which is how a single sink came
        back with 740 chains for a context builder that prints four."""
        src = """
            class A {
                @GetMapping("/x")
                public String entry(@RequestParam String q) { left(q); right(q); }
                String left(String x) { return shared(x); }
                String right(String x) { return shared(x); }
                String shared(String x) { return exec(x); }
            }
        """
        idx = index_workspace(workspace(tmp_path, {"A.java": src}))
        sink_line = next(i for i, l in enumerate(src.splitlines(), 1) if "exec(x)" in l)
        chains = trace_to_entry_points(idx, "A.java", sink_line)
        assert len(chains) == 1
        assert chains[0][-1].caller.name == "entry"

    def test_distinct_handlers_behind_a_shared_helper_are_all_found(self, tmp_path):
        """Expanding a method once must not cost an entry point: `shared` is
        reached by one route, but both handlers call it and both matter."""
        src = """
            class A {
                @GetMapping("/1")
                public String one(@RequestParam String q) { return shared(q); }
                @GetMapping("/2")
                public String two(@RequestParam String q) { return shared(q); }
                String shared(String x) { return deep(x); }
                String deep(String x) { return exec(x); }
            }
        """
        idx = index_workspace(workspace(tmp_path, {"A.java": src}))
        sink_line = next(i for i, l in enumerate(src.splitlines(), 1) if "exec(x)" in l)
        chains = trace_to_entry_points(idx, "A.java", sink_line)
        assert sorted(c[-1].caller.name for c in chains) == ["one", "two"]

    def test_chains_come_back_shortest_first(self, tmp_path):
        """build_caller_context prints the first few, so the nearest handler
        has to be among them."""
        src = """
            class A {
                @GetMapping("/near")
                public String near(@RequestParam String q) { return sink(q); }
                @GetMapping("/far")
                public String far(@RequestParam String q) { return hop(q); }
                String hop(String x) { return sink(x); }
                String sink(String x) { return exec(x); }
            }
        """
        idx = index_workspace(workspace(tmp_path, {"A.java": src}))
        sink_line = next(i for i, l in enumerate(src.splitlines(), 1) if "exec(x)" in l)
        chains = trace_to_entry_points(idx, "A.java", sink_line)
        assert [len(c) for c in chains] == [1, 2]
        assert chains[0][-1].caller.name == "near"

    def test_recursion_terminates(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                void a(String x) { b(x); }
                void b(String x) { a(x); }
            }
        """}))
        assert trace_to_entry_points(idx, "A.java", 3) == []

    def test_depth_limit_is_honoured(self, tmp_path):
        files = {"A.java": """
            class A {
                @GetMapping("/x")
                public String entry(@RequestParam String q) { return one(q); }
                String one(String x) { return two(x); }
                String two(String x) { return three(x); }
                String three(String x) { return exec(x); }
            }
        """}
        idx = index_workspace(workspace(tmp_path, files))
        sink_line = 7
        assert enclosing_method(idx, "A.java", sink_line).name == "three"
        assert len(trace_to_entry_points(idx, "A.java", sink_line, max_depth=3)[0]) == 3
        assert trace_to_entry_points(idx, "A.java", sink_line, max_depth=2) == []


class TestCallersOf:
    def test_matches_on_name_and_arity(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                void caller() { target("a"); target("a", "b"); }
                void target(String a) {}
            }
        """}))
        target = next(m for m in idx.methods if m.name == "target")
        assert [c.arity for c in callers_of(idx, target)] == [1]

    def test_empty_index_is_safe(self):
        assert callers_of(Index(), _enclosing(Index(), "A.java", 1) or _dummy()) == []


def _dummy():
    from scanner.callgraph import Method
    return Method(file="A.java", name="x", arity=0, start_line=1, end_line=1)


class TestEntryPointStrength:
    """A mapping annotation, or a parameter the framework binds, only ever
    appears on a real handler. A parameter *type* does not -- any helper can
    be handed an HttpServletRequest or a MultipartFile. Treating the weak
    signal as proof made the search stop at the helper and never reach the
    handlers that call it, which is where the validation lives.
    """

    UPLOAD = """
        class Upload {
            @VulnerableAppRequestMapping(value = "LEVEL_1")
            public String levelOne(@RequestParam MultipartFile file) {
                return store(root, file.getOriginalFilename(), file);
            }

            @VulnerableAppRequestMapping(value = "LEVEL_2")
            public String levelTwo(@RequestParam MultipartFile file) {
                return store(root, sanitize(file.getOriginalFilename()), file);
            }

            private String store(Path root, String fileName, MultipartFile file) {
                return root.resolve(fileName).toString();
            }
        }
    """

    def test_a_helper_taking_a_request_type_still_reports_its_callers(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"Upload.java": self.UPLOAD}))
        store = next(m for m in idx.methods if m.name == "store")
        assert store.entry_reason, "the MultipartFile parameter is still worth noting"
        assert not store.entry_definitive, "but it is a hint, not proof"

        chains = trace_to_entry_points(idx, "Upload.java", store.start_line + 1)

        assert chains != [[]], "the helper must not be mistaken for the handler"
        assert len(chains) == 2, "both level handlers call it"
        assert {c[-1].caller.name for c in chains} == {"levelOne", "levelTwo"}

    def test_a_mapping_annotation_is_proof_and_stops_the_search(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"Upload.java": self.UPLOAD}))
        handler = next(m for m in idx.methods if m.name == "levelOne")
        assert handler.entry_definitive

        assert trace_to_entry_points(idx, "Upload.java", handler.start_line + 1) == [[]]

    def test_an_annotated_parameter_is_proof(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class A {
                public String handler(@RequestBody Payload body) { return sink(body); }
            }
        """}))
        method = next(m for m in idx.methods if m.name == "handler")
        assert method.entry_definitive and "RequestBody" in method.entry_reason

    def test_a_hinted_entry_with_no_callers_is_still_reported_as_the_handler(self, tmp_path):
        """Otherwise a real servlet-style handler nothing calls would come
        back as unreachable, which is worse than the hint."""
        idx = index_workspace(workspace(tmp_path, {"S.java": """
            class S {
                protected void doGet(HttpServletRequest request) {
                    sink(request);
                }
            }
        """}))
        method = next(m for m in idx.methods if m.name == "doGet")
        assert method.entry_reason and not method.entry_definitive

        assert trace_to_entry_points(idx, "S.java", method.start_line + 1) == [[]]


class TestMyBatisMappers:
    """A mapper XML is the one place in this module where the link is
    resolved rather than guessed: <mapper namespace> names the interface and
    <select id> names the method, so these tests pin that the span, the
    arity lookup and the namespace requirement all hold."""

    MAPPER_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.x.dao.LogMapper">
  <sql id="cols">id, detail</sql>
  <select id="listLogs" resultType="Log">
    select <include refid="cols"/> from log
    <if test="sorts != null">
      order by ${sorts}
    </if>
  </select>
  <update id="touch">update log set seen = 1</update>
</mapper>
"""

    INTERFACE_JAVA = """
        package com.x.dao;
        public interface LogMapper {
            List<Log> listLogs(LogQuery query);
            void touch();
        }
    """

    CONTROLLER_JAVA = """
        package com.x.web;
        class LogController {
            @GetMapping("/logs")
            public Object logs(@RequestParam String sorts) { return service.find(sorts); }
        }
        class LogService {
            Object find(String sorts) { return logMapper.listLogs(new LogQuery(sorts)); }
        }
    """

    def mapper_workspace(self, tmp_path, **overrides):
        files = {
            "src/main/resources/mapper/LogMapper.xml": self.MAPPER_XML,
            "src/main/java/com/x/dao/LogMapper.java": self.INTERFACE_JAVA,
            "src/main/java/com/x/web/LogController.java": self.CONTROLLER_JAVA,
        }
        files.update(overrides)
        return workspace(tmp_path, files)

    def test_a_statement_becomes_a_method_spanning_its_tag(self, tmp_path):
        idx = index_workspace(self.mapper_workspace(tmp_path))
        statement = next(m for m in idx.methods if m.file.endswith("LogMapper.xml") and m.name == "listLogs")
        assert statement.start_line == 6 and statement.end_line == 11

    def test_arity_comes_from_the_interface_the_namespace_names(self, tmp_path):
        idx = index_workspace(self.mapper_workspace(tmp_path))
        by_name = {m.name: m for m in idx.methods if m.file.endswith(".xml")}
        assert by_name["listLogs"].arity == 1
        assert by_name["touch"].arity == 0

    def test_a_sink_in_the_xml_traces_back_to_the_request_handler(self, tmp_path):
        """The whole point: the ${sorts} line inside <select> is 25 of the 64
        vmscode candidates, and before this it reported no entry point."""
        root = self.mapper_workspace(tmp_path)
        chains = trace_to_entry_points(index_workspace(root), "src/main/resources/mapper/LogMapper.xml", 9)
        assert chains
        assert chains[0][-1].caller.name == "logs"

    def test_sql_fragments_are_not_statements(self, tmp_path):
        idx = index_workspace(self.mapper_workspace(tmp_path))
        assert not [m for m in idx.methods if m.name == "cols"]

    def test_xml_without_a_mapper_namespace_is_ignored(self, tmp_path):
        """Otherwise any config file holding <select id="..."> would join the
        call graph and start answering questions about reachability."""
        idx = index_workspace(workspace(tmp_path, {
            "conf/menu.xml": '<?xml version="1.0"?><menu><select id="listLogs">x</select></menu>',
        }))
        assert idx.methods == []

    def test_overloads_fall_back_to_matching_any_arity(self, tmp_path):
        """One node per statement, not one per overload: registering both
        would make trace_to_entry_points pick one and lose the other's
        callers."""
        root = self.mapper_workspace(tmp_path, **{"src/main/java/com/x/dao/LogMapper.java": """
            package com.x.dao;
            public interface LogMapper {
                List<Log> listLogs(LogQuery query);
                List<Log> listLogs(LogQuery query, Page page);
            }
        """})
        idx = index_workspace(root)
        statement = next(m for m in idx.methods if m.file.endswith(".xml") and m.name == "listLogs")
        assert statement.arity == ANY_ARITY
        assert {c.arity for c in callers_of(idx, statement)} >= {1}

    def test_an_unresolvable_namespace_still_matches_callers(self, tmp_path):
        root = workspace(tmp_path, {
            "src/main/resources/mapper/LogMapper.xml": self.MAPPER_XML,
            "src/main/java/com/x/web/LogController.java": self.CONTROLLER_JAVA,
        })
        idx = index_workspace(root)
        statement = next(m for m in idx.methods if m.file.endswith(".xml") and m.name == "listLogs")
        assert statement.arity == ANY_ARITY
        assert [c.caller.name for c in callers_of(idx, statement)] == ["find"]

    def test_a_mapper_resolves_across_modules_in_a_multi_module_workspace(self, tmp_path):
        """The shape a real corpus actually has: an uploaded zip is 13 sibling
        module directories, so the namespace lookup runs against every module's
        sources at once and must land on the module that declares the
        interface, not on a same-named class in a neighbour.

        Measured on the 13-module vmscode corpus: 445 mapper statements
        indexed, 401 of them with a resolved Java caller.
        """
        root = workspace(tmp_path, {
            "service-log/src/main/resources/mapper/LogMapper.xml": self.MAPPER_XML,
            "service-log/src/main/java/com/x/dao/LogMapper.java": self.INTERFACE_JAVA,
            "service-log/src/main/java/com/x/web/LogController.java": self.CONTROLLER_JAVA,
            # A neighbouring module with an unrelated same-named statement id;
            # its callers must not be attributed to the mapper above.
            "service-audit/src/main/java/com/y/AuditJob.java": """
                package com.y;
                class AuditJob { void run() { auditDao.listLogs(a, b, c); } }
            """,
        })
        idx = index_workspace(root)
        statement = next(m for m in idx.methods
                         if m.file.endswith("LogMapper.xml") and m.name == "listLogs")

        assert statement.arity == 1
        chains = trace_to_entry_points(idx, "service-log/src/main/resources/mapper/LogMapper.xml", 9)
        assert [c[-1].caller.name for c in chains] == ["logs"]

    def test_a_statement_id_the_interface_does_not_declare_still_gets_a_node(self, tmp_path):
        """Mappers outlive their interfaces: a statement left behind after the
        method was renamed still has to be placeable, or a sink inside it gets
        no enclosing method at all and the verify stage sees a bare SQL
        fragment with no file context."""
        root = self.mapper_workspace(tmp_path, **{"src/main/java/com/x/dao/LogMapper.java": """
            package com.x.dao;
            public interface LogMapper { void touch(); }
        """})
        idx = index_workspace(root)
        statement = next(m for m in idx.methods if m.file.endswith(".xml") and m.name == "listLogs")

        assert statement.arity == ANY_ARITY
        assert enclosing_method(idx, "src/main/resources/mapper/LogMapper.xml", 9) is statement

    def test_malformed_xml_is_skipped_rather_than_raised(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {
            "mapper/Broken.xml": '<mapper namespace="com.x.A"><select id="q">unclosed',
        }))
        assert idx.methods == []


class TestFrameworkEntryPoints:
    def test_a_message_listener_is_an_entry_point(self, tmp_path):
        """A Kafka payload is written by whoever put it on the topic, which
        makes the listener a request entry point in the sense that matters."""
        src = """
            class Consumer {
                @KafkaListener(topics = "t")
                public void listener(String value) { handle(value); }
                void handle(String v) { exec(v); }
            }
        """
        idx = index_workspace(workspace(tmp_path, {"A.java": src}))
        sink_line = next(i for i, l in enumerate(src.splitlines(), 1) if "exec(v)" in l)
        chains = trace_to_entry_points(idx, "A.java", sink_line)
        assert chains and chains[0][-1].caller.entry_reason == "@KafkaListener"

    def test_a_scheduled_job_is_not_an_entry_point(self, tmp_path):
        """The framework invokes it, but with nothing a user chose. Calling it
        a request entry point would tell the verify stage a lie."""
        src = """
            class Job {
                @Scheduled(cron = "0 0 * * * *")
                public void nightly() { exec("x"); }
            }
        """
        idx = index_workspace(workspace(tmp_path, {"A.java": src}))
        assert not [m for m in idx.methods if m.is_entry_point]

    def test_a_servlet_method_is_an_entry_point_via_its_supertype(self, tmp_path):
        src = """
            class Upload extends HttpServlet {
                protected void doPost(HttpServletRequest req, HttpServletResponse resp) { exec(req); }
            }
        """
        idx = index_workspace(workspace(tmp_path, {"A.java": src}))
        method = next(m for m in idx.methods if m.name == "doPost")
        assert method.entry_definitive and "HttpServlet" in method.entry_reason

    def test_the_same_method_name_without_the_supertype_is_not(self, tmp_path):
        """`service` and `doFilter` are ordinary words; matching on the name
        alone would invent entry points across a Spring codebase."""
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class Helper {
                void service(String a) { exec(a); }
            }
        """}))
        assert not [m for m in idx.methods if m.is_entry_point]


class TestOwners:
    def test_a_named_class_records_its_supertypes(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class Impl extends Base implements Runnable, java.io.Closeable {
                public void run() {}
            }
        """}))
        owner = next(m for m in idx.methods if m.name == "run").owner
        assert owner.name == "Impl"
        assert set(owner.supertypes) == {"Base", "Runnable", "Closeable"}
        assert not owner.anonymous

    def test_an_anonymous_class_takes_the_type_it_implements(self, tmp_path):
        """The name is the whole point: `checkServerTrusted` says nothing, and
        `an anonymous X509TrustManager` says it is a TLS callback."""
        idx = index_workspace(workspace(tmp_path, {"A.java": """
            class F {
                void build() {
                    TrustManager tm = new X509TrustManager() {
                        @Override
                        public void checkServerTrusted(X509Certificate[] c, String t) {}
                    };
                }
            }
        """}))
        method = next(m for m in idx.methods if m.name == "checkServerTrusted")
        assert method.owner.name == "X509TrustManager" and method.owner.anonymous
        assert method.overrides_supertype

    def test_supertypes_are_closed_transitively(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {
            "A.java": "class Leaf extends Middle {}",
            "B.java": "class Middle extends Root {}",
            "C.java": "class Root {}",
        }))
        assert idx.ancestors["Leaf"] == frozenset({"Middle", "Root"})

    def test_an_inheritance_cycle_does_not_hang(self, tmp_path):
        """Java forbids it; this reads whatever is on disk, generated sources
        and half-written files included."""
        idx = index_workspace(workspace(tmp_path, {
            "A.java": "class A extends B {}",
            "B.java": "class B extends A {}",
        }))
        assert "B" in idx.ancestors["A"]


class TestSelfReceiverCalls:
    def test_this_call_does_not_bridge_into_an_unrelated_class(self, tmp_path):
        """The measured case: MockUserLoginInit.refreshMockUser() calls
        `this.run()`, and name-and-arity matching alone bridged that into a
        different module's OracleAQConsumer.run(), inventing a chain from a
        @KafkaListener to a JMS connector it has nothing to do with."""
        idx = index_workspace(workspace(tmp_path, {
            "Init.java": """
                class Init {
                    @KafkaListener(topics = "t")
                    public void listener(String v) { this.run(); }
                    public void run() {}
                }
            """,
            "Consumer.java": """
                class Consumer {
                    public void run() { exec("x"); }
                }
            """,
        }))
        assert trace_to_entry_points(idx, "Consumer.java", 3) == []

    def test_this_call_still_reaches_an_override_two_levels_down(self, tmp_path):
        """The template-method shape, and the reason the hierarchy is closed
        transitively: FileInfoDataUpload extends AbstractDeviceDataUpload
        extends AbstractDataUpload, and the `this.getData()` that reaches the
        sink is written in the outermost base."""
        idx = index_workspace(workspace(tmp_path, {
            "Base.java": """
                abstract class Base {
                    @PostMapping("/x")
                    public void handler() { this.getData(); }
                    abstract void getData();
                }
            """,
            "Middle.java": "abstract class Middle extends Base {}",
            "Leaf.java": """
                class Leaf extends Middle {
                    void getData() { exec("x"); }
                }
            """,
        }))
        chains = trace_to_entry_points(idx, "Leaf.java", 3)
        assert chains and chains[0][-1].caller.name == "handler"

    def test_this_call_does_not_reach_an_unrelated_mappers_statement(self, tmp_path):
        """A mapper statement used to have no owner type at all, so this edge
        was kept as unprovable. Its namespace *is* the owner's qualified name,
        though, and Svc is not com.x.M: on HA_Benchmark every class's
        `this.enrich(v)` reached every <select id="enrich"> in the project."""
        idx = index_workspace(workspace(tmp_path, {
            "mapper/M.xml": '<mapper namespace="com.x.M"><select id="q">select ${a}</select></mapper>',
            "Svc.java": """
                class Svc {
                    @PostMapping("/x")
                    public void handler() { this.q(); }
                }
            """,
        }))
        assert trace_to_entry_points(idx, "mapper/M.xml", 1) == []

    def test_a_typed_mapper_field_reaches_its_own_statement(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {
            "mapper/M.xml": '<mapper namespace="com.x.M"><select id="q">select ${a}</select></mapper>',
            "com/x/M.java": "package com.x;\ninterface M { String q(String a); }",
            "com/x/Svc.java": """package com.x;
                class Svc {
                    private final M mapper;
                    @PostMapping("/x")
                    public void handler(String a) { mapper.q(a); }
                }
            """,
        }))
        chains = trace_to_entry_points(idx, "mapper/M.xml", 1)
        assert chains and chains[0][-1].caller.name == "handler"


class TestJavaReceiverTypes:
    """Receiver types resolved through package and imports (java_types.py).
    The measured failure: on HA_Benchmark, name + arity matching made every
    sink reachable from every one of 412 request handlers, and the four
    chains shown to the verifier held the real entry point for 1 case."""

    TWO_PACKAGES = {
        "a/Exec.java": "package a;\nclass Exec { void refine(String v) { exec(v); } }",
        "a/Ctl.java": """package a;
            class Ctl {
                private final Exec executor;
                @GetMapping("/a")
                public void handle(String v) { executor.refine(v); }
            }""",
        "b/Exec.java": "package b;\nclass Exec { void refine(String v) { exec(v); } }",
        "b/Ctl.java": """package b;
            class Ctl {
                private final Exec executor;
                @GetMapping("/b")
                public void handle(String v) { executor.refine(v); }
            }""",
    }

    def test_same_named_classes_in_other_packages_do_not_connect(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, self.TWO_PACKAGES))
        chains = trace_to_entry_points(idx, "a/Exec.java", 2)
        assert [c[-1].caller.file for c in chains] == ["a/Ctl.java"]

    def test_an_import_resolves_across_packages(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {
            "dao/Exec.java": "package dao;\npublic class Exec { public void refine(String v) { exec(v); } }",
            "other/Exec.java": "package other;\npublic class Exec { public void refine(String v) { exec(v); } }",
            "web/Ctl.java": """package web;
                import dao.Exec;
                class Ctl {
                    @GetMapping("/x")
                    public void handle(String v) { new Exec().refine(v); }
                }""",
        }))
        assert trace_to_entry_points(idx, "dao/Exec.java", 2)
        assert trace_to_entry_points(idx, "other/Exec.java", 2) == []

    def test_a_call_on_an_interface_reaches_its_implementation(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {
            "p/Plan.java": "package p;\ninterface Plan { void run(String v); }",
            "p/PlanImpl.java": "package p;\nclass PlanImpl implements Plan { public void run(String v) { exec(v); } }",
            "p/Ctl.java": """package p;
                class Ctl {
                    @GetMapping("/x")
                    public void handle(Plan plan, String v) { plan.run(v); }
                }""",
        }))
        chains = trace_to_entry_points(idx, "p/PlanImpl.java", 2)
        assert chains and chains[0][-1].caller.name == "handle"

    def test_a_library_receiver_reaches_no_workspace_method(self, tmp_path):
        """`buffer.append(v)` on a StringBuilder used to be an edge into every
        workspace method named append/1."""
        idx = index_workspace(workspace(tmp_path, {
            "p/Log.java": "package p;\nclass Log { void append(String v) { exec(v); } }",
            "p/Ctl.java": """package p;
                class Ctl {
                    @GetMapping("/x")
                    public void handle(String v) { StringBuilder buffer = new StringBuilder(); buffer.append(v); }
                }""",
        }))
        assert trace_to_entry_points(idx, "p/Log.java", 2) == []

    def test_a_static_call_names_its_class(self, tmp_path):
        idx = index_workspace(workspace(tmp_path, {
            "p/Util.java": "package p;\nclass Util { static void run(String v) { exec(v); } }",
            "q/Util.java": "package q;\nclass Util { static void run(String v) { exec(v); } }",
            "p/Ctl.java": """package p;
                class Ctl {
                    @GetMapping("/x")
                    public void handle(String v) { Util.run(v); }
                }""",
        }))
        assert trace_to_entry_points(idx, "p/Util.java", 2)
        assert trace_to_entry_points(idx, "q/Util.java", 2) == []

    def test_an_unknown_receiver_keeps_the_name_match(self, tmp_path):
        """A call result's type is not read; the old edge stays."""
        idx = index_workspace(workspace(tmp_path, {
            "p/Exec.java": "package p;\nclass Exec { void refine(String v) { exec(v); } }",
            "p/Ctl.java": """package p;
                class Ctl {
                    @GetMapping("/x")
                    public void handle(String v) { lookup().refine(v); }
                }""",
        }))
        assert trace_to_entry_points(idx, "p/Exec.java", 2)


class TestPackageSurface:
    """callgraph.py became the scanner/callgraph/ package; context.py,
    pipeline.py and scripts/02_verify.py all import from the old module
    path, so every public name has to stay re-exported from it."""

    def test_the_public_names_are_still_importable_from_scanner_callgraph(self):
        import scanner.callgraph as callgraph

        for name in ("Index", "Method", "Call", "Owner", "ANY_ARITY", "MAX_DEPTH",
                     "index_workspace", "index_mybatis_mappers", "enclosing_method",
                     "callers_of", "trace_to_entry_points"):
            assert hasattr(callgraph, name), name

    def test_the_model_module_does_not_need_tree_sitter(self):
        # model.py is imported by every other module in the package, which is
        # only cheap while it stays free of the parser.
        source = (Path(__file__).resolve().parents[1] / "scanner" / "callgraph" / "model.py").read_text(
            encoding="utf-8")
        assert "tree_sitter" not in source
