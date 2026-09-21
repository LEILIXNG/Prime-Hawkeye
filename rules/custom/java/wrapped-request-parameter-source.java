// Annotated fixture for wrapped-request-parameter-source.yml, run by
// `semgrep --test` (tests/test_ruleset.py::test_custom_rules_match_their_fixtures).
//
// RequestParamWrapper below stands in for the real-world shape this rule
// targets (and for OWASP Benchmark's own SeparateClassRequest, which is
// what the rule's header comment measured the gap against): a small
// object built from the HttpServletRequest, exposing a pass-through getter
// alongside a same-shaped getter that does not touch the request at all.
// The `ok:` cases on the decoy getter are the point of this fixture: this
// rule reads the getter's name, not its body, so proving it stays off a
// getTheValue()-style method is what would actually catch a regression
// that widened the name regex too far.
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class RequestParamWrapper {
    private HttpServletRequest request;

    RequestParamWrapper(HttpServletRequest request) {
        this.request = request;
    }

    String getTheParameter(String name) {
        return request.getParameter(name);
    }

    // Same shape as getTheParameter above, but does not touch the request
    // -- the decoy every `ok:` case below exercises.
    String getTheValue(String name) {
        return "constant";
    }
}

class WrappedRequestParameterSourceFixture {

    void writerSink(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        RequestParamWrapper scr = new RequestParamWrapper(request);
        String param = scr.getTheParameter("p");
        // ruleid: wrapped-request-param-into-response-writer
        response.getWriter().write(param);
    }

    void writerSinkViaDecoy(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        RequestParamWrapper scr = new RequestParamWrapper(request);
        String param = scr.getTheValue("p");
        // ok: wrapped-request-param-into-response-writer
        response.getWriter().write(param);
    }

    void sqlSinkPreparedStatement(HttpServletRequest request, Connection connection)
            throws java.sql.SQLException {
        RequestParamWrapper scr = new RequestParamWrapper(request);
        String param = scr.getTheParameter("p");
        String sql = "SELECT * FROM users WHERE name = '" + param + "'";
        // ruleid: wrapped-request-param-into-sql
        PreparedStatement statement = connection.prepareStatement(sql);
        statement.executeQuery();
    }

    void sqlSinkCallableStatementNoArgExecute(HttpServletRequest request, Connection connection)
            throws java.sql.SQLException {
        RequestParamWrapper scr = new RequestParamWrapper(request);
        String param = scr.getTheParameter("p");
        String sql = "{call proc('" + param + "')}";
        // ruleid: wrapped-request-param-into-sql
        CallableStatement statement = connection.prepareCall(sql);
        ResultSet rs = statement.executeQuery();
    }

    void sqlSinkViaDecoy(HttpServletRequest request, Connection connection)
            throws java.sql.SQLException {
        RequestParamWrapper scr = new RequestParamWrapper(request);
        String param = scr.getTheValue("p");
        String sql = "SELECT * FROM users WHERE name = '" + param + "'";
        // ok: wrapped-request-param-into-sql
        Statement statement = connection.createStatement();
        statement.execute(sql);
    }

    void execSink(HttpServletRequest request) throws IOException {
        RequestParamWrapper scr = new RequestParamWrapper(request);
        String param = scr.getTheParameter("p");
        Runtime r = Runtime.getRuntime();
        // ruleid: wrapped-request-param-into-exec
        r.exec("echo " + param);
    }

    void execSinkViaDecoy(HttpServletRequest request) throws IOException {
        RequestParamWrapper scr = new RequestParamWrapper(request);
        String param = scr.getTheValue("p");
        Runtime r = Runtime.getRuntime();
        // ok: wrapped-request-param-into-exec
        r.exec("echo " + param);
    }

    void filePathSink(HttpServletRequest request) {
        RequestParamWrapper scr = new RequestParamWrapper(request);
        String param = scr.getTheParameter("p");
        // ruleid: wrapped-request-param-into-file-path
        File f = new File("/data/" + param);
    }

    void filePathSinkViaDecoy(HttpServletRequest request) {
        RequestParamWrapper scr = new RequestParamWrapper(request);
        String param = scr.getTheValue("p");
        // ok: wrapped-request-param-into-file-path
        File f = new File("/data/" + param);
    }

    void sessionAttributeSink(HttpServletRequest request) {
        RequestParamWrapper scr = new RequestParamWrapper(request);
        String param = scr.getTheParameter("p");
        // ruleid: wrapped-request-param-into-session-attribute
        request.getSession().setAttribute(param, "value");
    }

    void sessionAttributeSinkViaDecoy(HttpServletRequest request) {
        RequestParamWrapper scr = new RequestParamWrapper(request);
        String param = scr.getTheValue("p");
        // ok: wrapped-request-param-into-session-attribute
        request.getSession().setAttribute(param, "value");
    }
}
