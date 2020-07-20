/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind path-problem
 * @id cpp/SQLIVulnerable
 * @problem.severity warning
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class SqliFlowConfig extends TaintTracking::Configuration {
    SqliFlowConfig() { this = "SqliFlow" }

    override predicate isSource(DataFlow::Node source) {
        // count = read(STDIN_FILENO, buf, BUFSIZE);
        exists(FunctionCall read |
            read.getTarget().getName() = "read" and
            read.getArgument(1) = source.asExpr()
        )
    }

    override predicate isSanitizer(DataFlow::Node sanitizer) { none() }

    override predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) { none() }

    override predicate isSink(DataFlow::Node sink) {
        // rc = sqlite3_exec(db, query, NULL, 0, &zErrMsg);
        exists(FunctionCall exec |
            exec.getTarget().getName() = "sqlite3_exec" and
            exec.getArgument(1) = sink.asExpr()
        )
    }
}

// from SqliFlowConfig conf, DataFlow::PathNode source, DataFlow::PathNode sink
// where conf.hasFlowPath(source, sink)
// select sink, source, sink, "Possible SQL injection"

// Extra taint step
//     snprintf(query, bufsize, "INSERT INTO users VALUES (%d, '%s')", id, info);
// But snprintf is a macro on mac os.  The actual function's name is
//     #undef snprintf
//     #define snprintf(str, len, ...) \
//       __builtin___snprintf_chk (str, len, 0, __darwin_obsz(str), __VA_ARGS__)
//     #endif
from FunctionCall printf, DataFlow::Node into, DataFlow::Node out
where
    printf.getTarget().getName().matches("%snprintf%") and
    printf.getArgument(0) = out.asExpr() and
    // very specific: shifted index for macro.  We can generalize this to consider
    // all trailing arguments as sources.
    printf.getArgument(6) = into.asExpr()
select printf, into, out
