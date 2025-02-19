
import cpp

// 1. invalid input -- source
//    count = read(STDIN_FILENO, buf, BUFSIZE - 1);
//
// 2. gets to a sql statement -- flow
//    flow config
//
// 3. drops table -- sink
//    rc = sqlite3_exec(db, query, NULL, 0, &zErrMsg);

// All predicates and classes are using one of:
// AST Abstract syntax tree
// CFG Control flow graph
// DFG Data flow graph
// Type hierarchy

from FunctionCall read, VariableAccess buf
where read.getTarget().getName() = "read" and
    read.getArgument(1) = buf
select buf
