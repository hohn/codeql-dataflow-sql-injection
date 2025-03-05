/**
* @name SQLI Vulnerability
* @description Using untrusted strings in a sql query allows sql injection attacks.
* @kind path-problem
* @id cpp/sqlivulnerable
* @problem.severity warning
*/

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

module SqliFlowConfig implements DataFlow::ConfigSig {

    predicate isSource(DataFlow::Node source) {
        // count = read(STDIN_FILENO, buf, BUFSIZE);
        exists(FunctionCall read |
            read.getTarget().getName() = "read" and
            read.getArgument(1) = source.asDefiningArgument()
        )
    }

    predicate isBarrier(DataFlow::Node sanitizer) { none() }

    predicate isSink(DataFlow::Node sink) {
        // rc = sqlite3_exec(db, query, NULL, 0, &zErrMsg);
        exists(FunctionCall exec |
            exec.getTarget().getName() = "sqlite3_exec" and
            exec.getArgument(1) = sink.asIndirectArgument()
        )
    }
}

module MyFlow = TaintTracking::Global<SqliFlowConfig>;
import MyFlow::PathGraph

from  MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink, source, sink, "Possible SQL injection"

