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

from DataSink ds
select ds

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
