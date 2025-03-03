/**
 * @name SQLI Vulnerability
 * @description Using untrusted strings in a sql query allows sql injection attacks.
 * @kind path-problem
 * @id cpp/sqlivulnerable
 * @problem.severity warning
 */

import cpp

// 1. invalid input -- source
//    count = read(STDIN_FILENO, buf, BUFSIZE - 1);
//

class DataSource extends VariableAccess {
    DataSource() {
      exists(FunctionCall read |
        read.getTarget().getName() = "read" and
        read.getArgument(1) = this
      )
    }
  }

// from DataSource buf
// select buf
  
// 2. gets to a sql statement -- flow
//    flow config
//
// 3. drops table -- sink
//    rc = sqlite3_exec(db, query, NULL, 0, &zErrMsg);


class DataSink extends Expr {
    DataSink() {
      exists(FunctionCall read |
       read.getTarget().getName() = "sqlite3_exec" and
       read.getArgument(1) = this
      )
    }
  }

// from DataSource ds
// select ds


// from FunctionCall exec, Expr query 
// where exec.getTarget().getName() = "sqlite3_exec" and
// exec.getArgument(1) = query
// select query
// from StmtParent st
// where not (st instanceof VariableAccess)
// select st



// All predicates and classes are using one of:
// AST Abstract syntax tree
// CFG Control flow graph
// DFG Data flow graph
// Type hierarchy
//


import semmle.code.cpp.dataflow.new.TaintTracking


module SqliFlowConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) {
        exists(DataSource ds |
            source.asExpr() = ds
            )
    }

    predicate isSink(DataFlow::Node sink) {
        exists(DataSink ds |
            sink.asExpr() = ds
            )

    }
  
}


module MyFlow = TaintTracking::Global<SqliFlowConfig>;
import MyFlow::PathGraph

from  MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink, source, sink, "Possible SQL injection"
