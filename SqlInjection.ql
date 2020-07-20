/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind path-problem
 * @id cpp/SQLIVulnerable
 * @problem.severity warning
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

class SqliFlowConfig extends TaintTracking::Configuration {
    SqliFlowConfig() { this = "SqliFlow" }

    override predicate isSource(DataFlow::Node source) { any() }

    override predicate isSanitizer(DataFlow::Node sanitizer) { none() }

    override predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) { none() }

    override predicate isSink(DataFlow::Node sink) { any() }
}

// from SqliFlowConfig conf, DataFlow::PathNode source, DataFlow::PathNode sink
// where conf.hasFlowPath(source, sink)
// select sink, source, sink, "Possible SQL injection"


// Source identification
// count = read(STDIN_FILENO, buf, BUFSIZE);
from FunctionCall read, DataFlow::Node source
where read.getTarget().getName() = "read"
and read.getArgument(1) = source.asExpr()
select read, source
