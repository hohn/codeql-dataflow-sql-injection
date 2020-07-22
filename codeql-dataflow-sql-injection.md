<!-- -*- coding: utf-8 -*- -->
<!-- https://gist.github.com/hohn/
 -->
# CodeQL tutorial for C/C++: data flow and SQL injection

xx:
md_toc github <  codeql-dataflow-sql-injection.md 

- [CodeQL tutorial for C/C++: data flow and SQL injection](#codeql-tutorial-for-cc-data-flow-and-sql-injection)
  - [Setup instructions](#setup-instructions)
  - [Documentation links](#documentation-links)
  - [The Problem in Action: running the code to see the problem](#the-problem-in-action-running-the-code-to-see-the-problem)
  - [Problem statement](#problem-statement)
  - [Data flow overview and illustration](#data-flow-overview-and-illustration)
  - [Tutorial: recap, sources and sinks](#tutorial-recap-sources-and-sinks)
    - [Codeql recap](#codeql-recap)
    - [Call to SQL query execution (the data sink)](#call-to-sql-query-execution-the-data-sink)
    - [Non-constant query strings and untrusted data (the data source)](#non-constant-query-strings-and-untrusted-data-the-data-source)
  - [Data flow overview](#data-flow-overview)
    - [Taint flow configuration](#taint-flow-configuration)
    - [Path problem setup](#path-problem-setup)
    - [Path problem query format](#path-problem-query-format)
  - [Tutorial: data flow details](#tutorial-data-flow-details)
    - [isSource predicate ](#issource-predicate-)
    - [isSink predicate ](#issink-predicate-)
    - [Additional data flow features: the isAdditionalTaintStep predicate](#additional-data-flow-features-the-isadditionaltaintstep-predicate)
    - [Complete query](#complete-query)
  - [Appendix](#appendix)
    - [Test case: simple.cc](#test-case-simplecc)
    - [bslstrings query and library: bslstrings.ql](#bslstrings-query-and-library-bslstringsql)

## Setup instructions

To run CodeQL queries on dotnet/coreclr, follow these steps:

1. Install the Visual Studio Code IDE.
2. Download and install the [CodeQL extension for Visual Studio Code](https://help.semmle.com/codeql/codeql-for-vscode.html). Full setup instructions are [here](https://help.semmle.com/codeql/codeql-for-vscode/procedures/setting-up.html).
3. [Set up the starter workspace](https://help.semmle.com/codeql/codeql-for-vscode/procedures/setting-up.html#using-the-starter-workspace).
    - **Important**: Don't forget to `git clone --recursive` or `git submodule update --init --remote`, so that you obtain the standard query libraries.
4. Open the starter workspace: File > Open Workspace > Browse to `vscode-codeql-starter/vscode-codeql-starter.code-workspace`.

5. Download the sample database [`codeql-dataflow-sql-injection-d5b28fb.zip`](https://drive.google.com/file/d/1eBZ69ZQx6YnnZu41iUL0m8_e9qyMCZ9B/view?usp=sharing)

6. Unzip the database.

7. Import the unzipped database into Visual Studio Code:
    - Click the **CodeQL** icon in the left sidebar.
    - Place your mouse over **Databases**, and click the + sign that appears on
      the right. 
    - Choose the unzipped database directory on your filesystem.

8. Create a new file, name it `SqliInjection.ql`, save it under `codeql-custom-queries-cpp`.


## Documentation links
If you get stuck, try searching our documentation and blog posts for help and ideas. Below are a few links to help you get started:
- [Learning CodeQL](https://help.semmle.com/QL/learn-ql)
- [Learning CodeQL for C/C++](https://help.semmle.com/QL/learn-ql/cpp/ql-for-cpp.html)
- [Using the CodeQL extension for VS Code](https://help.semmle.com/codeql/codeql-for-vscode.html)

## The Problem in Action: running the code to see the problem

This program can be compiled and linked, and a simple sqlite db created via 

```sh
# Build
./build.sh

# Prepare db
./admin rm-db
./admin create-db
./admin show-db
```

Users can be added via `stdin` in several ways; the second is a pretend "server"
using the `echo` command.

```sh
# Add regular user interactively
./add-user 2>> users.log
First User

# Regular user via "external" process
echo "User Outside" | ./add-user 2>> users.log
```

Check the db and log:
```
# Check
./admin show-db

tail -4 users.log 
```

Looks ok:
```
0:$ ./admin show-db
87797|First User
87808|User Outside

0:$ tail -4 users.log 
[Tue Jul 21 14:15:46 2020] query: INSERT INTO users VALUES (87797, 'First User')
[Tue Jul 21 14:17:07 2020] query: INSERT INTO users VALUES (87808, 'User Outside')
```

But there may be bad input; this one guesses the table name and drops it:
```sh
# Add Johnny Droptable 
./add-user 2>> users.log
Johnny'); DROP TABLE users; --
```

And then we have this:
```sh
# And the problem:
./admin show-db
0:$ ./admin show-db
Error: near line 2: no such table: users
```

What happened?  The log shows that data was treated as command:
```
1:$ tail -4 users.log 
[Tue Jul 21 14:15:46 2020] query: INSERT INTO users VALUES (87797, 'First User')
[Tue Jul 21 14:17:07 2020] query: INSERT INTO users VALUES (87808, 'User Outside')
[Tue Jul 21 14:18:25 2020] query: INSERT INTO users VALUES (87817, 'Johnny'); DROP TABLE users; --')
```

Looking ahead, we now *know* that there is unsafe external data (source)
which reaches (flow path) a database-writing command (sink).  Thus, a query
written against this code should find at least one taint flow path.

## Problem statement

Many security problems can be phrased in terms of _information flow_:

_Given a (problem-specific) set of sources and sinks, is there a path in the data
flow graph from some source to some sink?_

The example we look at is SQL injection: sources are user-input, sinks are SQL
queries processing a string formed at runtime.

When parts of the string can be specified by the user, they allow an attacker to
insert arbitrary sql statements; these could erase a table or extract internal
data etc.

We will use CodeQL to analyze the source code constructing a SQL
query using string concatenation and then executing that query
string.  The following example uses the `sqlite3` library; it 
- receives user-provided data from `stdin` and keeps it in `buf`
- uses environment data and stores it in `id`,
- runs a query in `sqlite3_exec`

This is intentionally simple code, but it has all the elements that have to be
considered in real code and illustrates the QL features. 

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sqlite3.h>
#include <time.h>

void write_log(const char* fmt, ...);

void abort_on_error(int rc, sqlite3 *db);

void abort_on_exec_error(int rc, sqlite3 *db, char* zErrMsg);
    
char* get_user_info() {
#define BUFSIZE 1024
    char* buf = (char*) malloc(BUFSIZE * sizeof(char));
    int count;
    // Disable buffering to avoid need for fflush
    // after printf().
    setbuf( stdout, NULL );
    printf("*** Welcome to sql injection ***\n");
    printf("Please enter name: ");
    count = read(STDIN_FILENO, buf, BUFSIZE);
    if (count <= 0) abort();
    /* strip trailing whitespace */
    while (count && isspace(buf[count-1])) {
        buf[count-1] = 0; --count;
    }
    return buf;
}

int get_new_id() {
    int id = getpid();
    return id;
}

void write_info(int id, char* info) {
    sqlite3 *db;
    int rc;
    int bufsize = 1024;
    char *zErrMsg = 0;
    char query[bufsize];
    
    /* open db */
    rc = sqlite3_open("users.sqlite", &db);
    abort_on_error(rc, db);

    /* Format query */
    snprintf(query, bufsize, "INSERT INTO users VALUES (%d, '%s')", id, info);
    write_log("query: %s\n", query);

    /* Write info */
    rc = sqlite3_exec(db, query, NULL, 0, &zErrMsg);
    abort_on_exec_error(rc, db, zErrMsg);

    sqlite3_close(db);
}

int main(int argc, char* argv[]) {
    char* info;
    int id;
    info = get_user_info();
    id = get_new_id();
    write_info(id, info);
    /*
     * show_info(id);
     */
}

```

In terms of sources, sinks, and information flow, the concrete problem for codeql is:
1. specifying `buf` as **source**,
2. specifying the `query` argument to `sqlite3_exec()` as **sink**, 
3. specifying some code-specific data flow steps for the codeql library,
3. using the codeql taint flow library find taint flow paths (if there are any)
   between the source and the sink.

In the following, we go into more concrete detail and develop codedql scripts to
solve this problem.



## Data flow overview and illustration
In the previous sections we identified the sources of problematic strings
(accesses of `info` etc.), and the sink that their data may flow to (the argument
to `sqlite3_exec`).

We need to see if there is data flow between the source(s) and this sink.

The solution here is to use the data flow library.  Data flow is, as the name
suggests, about tracking the flow of data through the program. It helps answers
questions like: does this expression ever hold a value that originates from a
particular other place in the program?

We can visualize the data flow problem as one of finding paths through a directed
graph, where the nodes of the graph are elements in program, and the edges
represent the flow of data between those elements. If a path exists, then the data
flows between those two nodes.

This graph represents the flow of data from the tainted parameter. The nodes of
graph represent program elements that have a value, such as function parameters
and expressions. The edges of this graph represent flow through these nodes.

There are two variants of data flow available in CodeQL:
 - Local (“intra-procedural”) data flow models flow within one function; feasible
   to compute for all functions in a CodeQL database.
 - Global (“inter-procedural”) data flow models flow across function calls; not
   feasible to compute for all functions in a CodeQL database.

While local data flow is feasible to compute for all functions in a CodeQL
database, global data flow is not. This is because the number of paths becomes
_exponentially_ larger for global data flow.

The global data flow (and taint tracking) library avoids this problem by requiring
that the query author specifies which _sources_ and _sinks_ are applicable. This
allows the implementation to compute paths only between the restricted set of
nodes, rather than for the full graph.

To illustrate the dataflow for this problem, we have a [collection of slides](https://drive.google.com/file/d/1eEG0eGVDVEQh0C-0_4UIMcD23AWwnGtV/view?usp=sharing)
for this workshop.

## Tutorial: recap, sources and sinks
XX:
<!--
 !-- The complete project can be downloaded via this 
 !-- [drive](https://drive.google.com/file/d/1-6c3S-e4FKa_IsuuzhhXupiAwCzzPgD-/view?usp=sharing)
 !-- link.
  -->

The tutorial is split into several steps and introduces concepts as they are
needed.  Experimentation with the presented queries is encouraged, and the
autocomplete suggestions (Ctrl + Space) and the jump-to-definition command (F12 in
VS Code) are good ways explore the libraries.


### Codeql recap
As quick test of your setup, import the ql cpp library and run the empty query
```ql
import cpp
select 1
```

We'll assume the `import cpp` is in the header of our query and not rewrite it
every time.

Now let's find the function `executeStatement`.  In CodeQL, this uses `Function`
and a `getName()` attribute.

```ql
from Function f
where f.getName() = "executeStatement" 
select f
```

This should find one result, 
```ql
void executeStatement(const bsl::string &sQuery);
```
on line 5 of `simple.cc`

### Call to SQL query execution (the data sink)

The brings us closer to our sql statement execution.  This part of our problem is
to identify the call
```c
    executeStatement(sQuery);
```
and choosing the argument to `executeStatement()` as sink.  Let's start with the
call. 

We really need the function *call*, not the function *definition*.  Also, a call
has no name; it does have a *target* (the function), which has a name as we saw
above. 

To combine these, use the auto-completion.  After typing `Function<tab>`, we see a
list including `FunctionCall`; we can start with

```ql
from FunctionCall fc
where fc.<tab>
```

Now, we are looking for the call's *target*; completion shows `getTarget()`,
and we can finish that to 

```ql
from FunctionCall fc
where fc.getTarget().getName() = "executeStatement" 
select fc
```

Now that we have the function call, let's get the argument to it.  We don't care
about the exact type of the argument, so an `Expr` is a good choice.  Arguments
are part of the function *call* and using completion finds `getArgument` and some
others.  Our query now becomes
```ql
from FunctionCall fc, Expr sink
where
    fc.getTarget().getName() = "executeStatement" and
    fc.getArgument(0) = sink
select fc, sink
```
and it finds the call and the argument:

    1	call to executeStatement	sQuery

For reuse, we can turn this into a predicate.  Contents of `from` become arguments
to the predicate, the `where` becomes the body, the `select` is dropped:

```ql
predicate sqliSink(FunctionCall fc, Expr sink) {
    fc.getTarget().getName() = "executeStatement" and
    fc.getArgument(0) = sink
}

from FunctionCall fc, Expr sink
where sqliSource(fc, sink)
select fc, sink
```

This successfully identifies our (potentially) unsafe use of a string in a SQL
query.

### Non-constant query strings and untrusted data (the data source)
If we consider what we mean by "non-constant" strings and untrusted data, what we
really care about is whether an attacker can provide (part of) the query string.

Thus, before we get into the the full dataflow details, let's identify the sources
of problematic data.  This part of our problem is to identify (at least) `argv`,
`iUUID`, and `sObjectName` as *sources*.  For this example, all variables
represent values that would ordinarily come from external sources and are thus
untrusted.  This simplifies our query; we can simply identify *uses* of variables as
taint sources.

A `Variable` refers to a definition; with completion we find `VariableAccess`,
which is what we want.  Further, we don't care about variables in libraries, only
in the main program.  Put together, this query lists 12 results, including
destructor calls for some of the variables:

```ql
from  VariableAccess va
where va.getLocation().getFile().getShortName() = "simple"
select va, va.getTarget() as definition
```

Note that our query structure will extend to more complex cases lateron; only the
source identification will need updating.

## Data flow overview



To use global data flow and taint tracking we need to 
 - a taint flow configuration 
 - use path queries
 - add extra taint steps for taint flow 

These are done next.

### Taint flow configuration
The way we configure global data flow is by creating a custom extension of the
`TaintTracking::Configuration` class, and speciyfing `isSource`, `isSink`, and 
`isAdditionalTaintStep` predicates.  A starting configuration can look like the
following, with details to follow.

```ql
class SqliFlowConfig extends TaintTracking::Configuration {
    SqliFlowConfig() { this = "SqliFlow" }

    override predicate isSource(DataFlow::Node source) {
        // Use sqliSourceProduction(this, source) in that case
        sqliSourceDemo(source)
    }

    override predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
        stlBslTaintStep(n1, n2)
    }

    override predicate isSanitizer(DataFlow::Node sanitizer) { none() }

    override predicate isSink(DataFlow::Node sink) { sqliSink(sink, _) }
}
```

`TaintTracking::Configuration` is a _configuration_ class. In this case, there will be
a single instance of the class, identified by a unique string specified in the
characteristic predicate. We then override the `isSource` predicates to represent
the set of possible sources in the program, and `isSink` to represent the possible
set of sinks in the program.

### Path problem setup
Taint flow queries will only list sources and sinks by default.  To inspect
these results and work with them, we also need the data paths from source to sink.
For this, the query needs to have the form of _path problem_ query.

This requires a modifications to the query header and an extra import: 
 - The `@kind` comment has to be `path-problem`. This tells the CodeQL toolchain
   to interpret the results of this query as path results. 
 - Add a new import `DataFlow::PathGraph`, which will report the path data
   alongside the query results. 

Together, this looks like
```ql
/**
 * @name SQLI Vulnerability
 * @description Building a sql query dynamically may lead to sql injection vulnerability
 * @kind path-problem
 * @id cpp/SQLIVulnerable
 * @problem.severity warning
 */

import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.models.implementations.Pure
import DataFlow::PathGraph
```

### Path problem query format
To use this new configuration and `path-problem` class we call the
`hasFlowPath(source, sink)` predicate, which will compute a reachability table
between the defined sources and sinks.  Behind the scenes, you can think of this as
performing a graph search algorithm from sources to sinks.  The query will look
like this:

```ql
from SqliFlowConfig conf, DataFlow::PathNode source, DataFlow::PathNode sink
where
    // Flow path setup
    conf.hasFlowPath(source, sink) and
    source != sink 
select sink, source, sink, "Sqli flow from $@", source, "source"
```

## Tutorial: data flow details
With the dataflow configuration in place, we just need to provide the details for source(s), sink(s), and taint step(s). 

### isSource predicate 
Recall the query we have to find variable accesses:

    from  VariableAccess va
    where va.getLocation().getFile().getShortName() = "simple"
    select va, va.getTarget() as definition

This query uses the structural information from `VariableAccess`.  For taint flow,
we use a `DataFlow::Node nd`.

This is a direct conversion:
- to get a `VariableAccess` from a `Node`, use `node.asExpr` to get an `Expr` 
- and then narrow the `Expr`  to `VariableAccess` 
- the location information is also available from the `Node nd`

Together, this gives us

```ql
    import cpp
    import semmle.code.cpp.dataflow.TaintTracking

    from DataFlow::Node nd
    where 
        nd.asExpr() instanceof VariableAccess and
        nd.getLocation().getFile().getShortName() = "simple"
    select nd
```

In the TaintTracking configuration, we use

    sqliSourceDemo(source)

so we convert to a predicate:

    predicate sqliSourceDemo(DataFlow::Node nd) {
        // variable use
        nd.asExpr() instanceof VariableAccess and
        nd.getLocation().getFile().getShortName() = "simple"
    }

This source definition is good for our example but needs adjustment for larger
codebases.  See `sqliSourceProduction` in the appendix for an adjusted version.

### isSink predicate 
We have identified arguments to the `executeStatement`
function previously via the query

```ql
from FunctionCall fc, Expr sink
where
    fc.getTarget().getName() = "executeStatement" and
    fc.getArgument(0) = sink
select fc, sink
```

This query uses the structural information from `FunctionCall` and `Expr`.  The
`FunctionCall` is needed for the query, but not for the configuration; this is the
reason for using the "don't care" operator, `_` in the configuration:

    sqliSink(sink, _)

The first argument to the predicate is `DataFlow::Node`, our query has an `Expr`.
As above, the direct conversion from `Node` to `Expr` is done via 
`nd.asExpr()`.  Changing from `sink` to `nd` in the query gives

```ql
from DataFlow::Node nd, FunctionCall fc
where
    fc.getTarget().getName() = "executeStatement" and
    fc.getArgument(0) = nd.asExpr()
select fc, nd
```

For use as a dataflow sink, we need this as a predicate:

    predicate sqliSink(DataFlow::Node nd, FunctionCall fc) {
        fc.getTarget().getName() = "executeStatement" and
        fc.getArgument(0) = nd.asExpr()
    }

### Additional data flow features: the isAdditionalTaintStep predicate

Data flow and taint tracking configuration classes support a number of additional
features that help configure the process of building and exploring the data flow
path.

One such feature is adding additional taint steps. This is useful if you use
libraries which are not modelled by the default taint tracking. You can implement
this by overriding `isAdditionalTaintStep` predicate. This has two parameters, the
`from` and the `to` node, and essentially allows you to add extra edges into the
taint tracking or data flow graph.

For this tutorial, we have provided several predicates that track string and integer
taint flow across `stl` and `bsl` functions.  They are listed in the appendix
`bslstrings library`; here we will use them as library functions via the single
predicate 
```ql
stlBslTaintStep(n1, n2)
```

### Complete query
Using the previous predicates 

    sqliSourceDemo(source)
    sqliSink(sink, _)
    stlBslTaintStep(n1, n2)

our full query is now

```ql
/**
 * @name SQLI Vulnerability
 * @description Building a sql query dynamically may lead to sql injection vulnerability
 * @kind path-problem
 * @id cpp/SQLIVulnerable
 * @problem.severity warning
 */

import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.models.implementations.Pure
import DataFlow::PathGraph

/**
 * The taint tracking configuration
 */
class SqliFlowConfig extends TaintTracking::Configuration {
    SqliFlowConfig() { this = "SqliFlow" }

    override predicate isSource(DataFlow::Node source) {
        // Use sqliSourceProduction(this, source) in that case
        sqliSourceDemo(source)
    }

    override predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
        stlBslTaintStep(n1, n2)
    }

    override predicate isSanitizer(DataFlow::Node sanitizer) { none() }

    override predicate isSink(DataFlow::Node sink) { sqliSink(sink, _) }
}

/*
 * The main query
 */

from SqliFlowConfig conf, DataFlow::PathNode source, DataFlow::PathNode sink, string label
where
    // Flow path setup
    conf.hasFlowPath(source, sink) and
    source != sink and
    if source.getNode().asExpr().(VariableAccess).getTarget().hasName(_)
    then label = source.getNode().asExpr().(VariableAccess).getTarget().getName()
    else label = "source"
select sink, source, sink, "Sqli flow from $@", source, label

```

## Appendix
This appendix has the C++ test source, the bslstrings query, and the bslstrings
library.  The latter are in one file for convenience.

### Test case: simple.cc
```c
#include <bslstl_string.h>
#include <bslstl_stringstream.h>

void executeStatement(const bsl::string &sQuery);

int checkClusterSQL(const bsl::string &sDatabase, const bsl::string &sQuery,
                    const bsl::string &sObjectName);

int main(int argc, char **argv) {

    bsl::stringstream oSS;
    // Local constants
    int iUUID = 123;
    bsl::string sObjectName("HELLO");
    // User-supplied iLevel
    int iLevel = std::stol(argv[1]);

    oSS << "SELECT object_name_upper, object_value_name_upper "
        << "FROM pvfx_privilege "
        << "WHERE uuid=" << iUUID << " "
        << "AND object_name_upper=\"" << sObjectName << "\" "
        << "AND pvf_function=\"" << "sFunction" << "\" "
        << "AND pvf_level=" << iLevel;
    bsl::string sQuery(oSS.str());
    int iErrorCode = checkClusterSQL("pvfxdb", sQuery, sObjectName);

    // a_cdb2::SqlService sqlService("default");
    // sqlService.executeStatement(sQuery);
    executeStatement(sQuery);
}
    
```

### bslstrings query and library: bslstrings.ql
The complete query is first, followed by the library components.
```ql
/**
 * @name SQLI Vulnerability
 * @description Building a sql query dynamically may lead to sql injection vulnerability
 * @kind path-problem
 * @id cpp/SQLIVulnerable
 * @problem.severity warning
 */

import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.models.implementations.Pure
import DataFlow::PathGraph

/**
 * The taint tracking configuration
 */
class SqliFlowConfig extends TaintTracking::Configuration {
    SqliFlowConfig() { this = "SqliFlow" }

    override predicate isSource(DataFlow::Node source) {
        // Use sqliSourceProduction(this, source) in that case
        sqliSourceDemo(source)
    }

    override predicate isAdditionalTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
        stlBslTaintStep(n1, n2)
    }

    override predicate isSanitizer(DataFlow::Node sanitizer) { none() }

    override predicate isSink(DataFlow::Node sink) { sqliSink(sink, _) }
}

/*
 * The main query
 */

from SqliFlowConfig conf, DataFlow::PathNode source, DataFlow::PathNode sink, string label
where
    // Flow path setup
    conf.hasFlowPath(source, sink) and
    source != sink and
    if source.getNode().asExpr().(VariableAccess).getTarget().hasName(_)
    then label = source.getNode().asExpr().(VariableAccess).getTarget().getName()
    else label = "source"
select sink, source, sink, "Sqli flow from $@", source, label

// Identify the sink(s) for DataFlow
predicate sqliSink(DataFlow::Node nd, FunctionCall fc) {
    fc.getTarget().getName() = "executeStatement" and
    fc.getArgument(0) = nd.asExpr()
}

// Identify the source(s) for DataFlow; this version for the demonstration.
predicate sqliSourceDemo(DataFlow::Node nd) {
    // variable use
    nd.asExpr() instanceof VariableAccess and
    nd.getLocation().getFile().getShortName() = "simple"
}

// Identify the source(s) for DataFlow; this version for full applications
predicate sqliSourceProduction(SqliFlowConfig config, DataFlow::Node source) {
    // Approximates places where we concatenate a var with a string
    source.asExpr() instanceof VariableAccess and
    config.isAdditionalTaintStep(source, _) and
    // These are the steps where we get an existing value out, so don't use as source.
    not qualifierToCallStep(source, _, _) and
    (
        // We are reading a non-local variable (field, param, etc)
        exists(Variable v |
            source.asExpr().(VariableAccess).getTarget() = v and
            not v instanceof LocalVariable
        )
        or
        // We are reading a local, but something wrote to it since definition
        exists(LocalVariable v, VariableAccess mid |
            source.asExpr().(VariableAccess).getTarget() = v and
            mid.getTarget() = v and
            mid = v.getInitializer().getASuccessor+() and
            source.asExpr() = mid.getASuccessor+()
        )
    )
}

/**
 * Library routines.  These are for more in-depth development.
 */
// argv is a Parameter and exists(DataFlow::Node n | n.asParameter() = e) holds
predicate whatsThere(Element e, string info, int line, string file) {
    line = e.getLocation().getStartLine() and
    line = [10] and
    file = e.getLocation().getFile().getShortName() and
    file.matches("%simple%") and
    info = e.getAQlClass() and
    exists(DataFlow::Node n | n.asParameter() = e)
}

// Basic type that represents a string for our purposes
class StringLikeType extends Type {
    StringLikeType() {
        this.getName().matches("%string%") or
        this.getName().matches("%stream%") or
        this.(ReferenceType).getBaseType() instanceof StringLikeType
    }
}

// Capture all types that may be used to form or append to a string.
class AppendableToString extends Type {
    AppendableToString() {
        this instanceof StringLikeType or
        this instanceof CharPointerType or
        this instanceof IntegralType
    }
}

// Identify pure, non-member functions taking a tainted value and returning a taint, of the form
// val = func(arg).  Avoids overlap with instance-modifying members and generic functions.
predicate pureFuncArgToCallStep(Function f) {
    not f.isMember() and
    (
        f instanceof PureStrFunction or
        f.getName() = "stol"
    ) and
    f.getAParameter().getType().getUnspecifiedType() instanceof AppendableToString and
    f.getType().getUnspecifiedType() instanceof AppendableToString
}

predicate pureFuncArgToCallStep(DataFlow::Node n1, DataFlow::Node n2, FunctionCall fc) {
    pureFuncArgToCallStep(fc.getTarget()) and
    (
        // argument taints call result.  Note that pure functions don't have PostUpdateNodes
        n1.asExpr() = fc.getAnArgument() and
        n2.asExpr() = fc
    )
}

// Identify member functions taking a tainted value and returning a taint, of the form
// qual.func(arg).
predicate argToCallStep(Function f) {
    f.getDeclaringType() instanceof StringLikeType and
    f.getAParameter().getType().getUnspecifiedType() instanceof AppendableToString and
    f.getType().getUnspecifiedType() instanceof StringLikeType
}

predicate argToCallStep(DataFlow::Node n1, DataFlow::Node n2, FunctionCall fc) {
    argToCallStep(fc.getTarget()) and
    (
        // argument taints call result
        n1.asExpr() = fc.getAnArgument() and
        n2.(DataFlow::PostUpdateNode).getPreUpdateNode().asExpr() = fc
        or
        // The argument taints the post-update node of the qualifier
        // or
        // the argument taints leftmost argument in the call chain
        n1.asExpr() = fc.getArgument(0) and
        exists(Expr found |
            leftmost(fc.getQualifier(), found) and
            n2.(DataFlow::PostUpdateNode).getPreUpdateNode().asExpr() = found
        )
    )
}

// Identify functions where a tainted qualifier taints the result.
// This includes qual.str() and stream << arg (which is stream::operator<<(arg))
//
// In the FunctionCall, not here, the qualifier is `this`.  Here, the declaring
// type is the later type of `this`.
// This covers chaining of methods.  e.g., foo << seek(10) << "hello" will chain
predicate qualifierToCallStep(Function f) {
    f.getDeclaringType() instanceof StringLikeType and
    f.getType().getUnspecifiedType() instanceof StringLikeType
}

// Tainted qualifier taints the call's result, e.g., qual.str()
predicate qualifierToCallStep(DataFlow::Node n1, DataFlow::Node n2, FunctionCall fc) {
    qualifierToCallStep(fc.getTarget()) and
    (
        n1.asExpr() = fc.getQualifier() and
        n2.(DataFlow::PostUpdateNode).getPreUpdateNode().asExpr() = fc
        or
        // Cover cases missing the PostUpdateNode, like oSS.str()
        n1.asExpr() = fc.getQualifier() and
        n2.asExpr() = fc
    )
}

// Find parameterized override of operator<<, typically of the form
// stream&  operator<<(stream&, AppendableToString)
predicate operatorAsFunctionStep(Function f) {
    not exists(f.getDeclaringType()) and
    f.getName() = "operator<<" and
    f.getParameter(0).getType().getUnspecifiedType() instanceof StringLikeType and
    f.getParameter(1).getType().getUnspecifiedType() instanceof AppendableToString and
    f.getType().getUnspecifiedType() instanceof StringLikeType
}

predicate operatorAsFunctionStep(DataFlow::Node n1, DataFlow::Node n2, FunctionCall fc) {
    operatorAsFunctionStep(fc.getTarget()) and
    (
        // both arguments taint result
        n1.asExpr() = fc.getArgument(0) and
        n2.(DataFlow::PostUpdateNode).getPreUpdateNode().asExpr() = fc
        or
        n1.asExpr() = fc.getArgument(1) and
        n2.(DataFlow::PostUpdateNode).getPreUpdateNode().asExpr() = fc
        or
        // The second argument taints the post-update node of the first
        // or
        // the rightmost (second) argument also taints the leftmost argument at the
        // beginning of the call chain.
        // ( ( head << mid) << last)
        //      ^________________/
        //   \-left-------/
        n1.asExpr() = fc.getArgument(1) and
        exists(Expr found |
            leftmost(fc.getArgument(0), found) and
            n2.(DataFlow::PostUpdateNode).getPreUpdateNode().asExpr() = found
        )
    )
}

// For a FunctionCall chain like (((head << n1) << n2) << last),
// find `head` starting from `last`
//
// The rightmost argument also taints the leftmost argument at the
// beginning of the call chain.
// ( ( head << mid) << last)
//      ^________________/
//   \-left-------/
predicate leftmost(FunctionCall fc, Expr head) {
    //
    operatorAsFunctionStep(fc.getTarget()) and
    not fc.getArgument(0) instanceof FunctionCall and
    head = fc.getArgument(0)
    or
    //
    (argToCallStep(fc.getTarget()) or qualifierToCallStep(fc.getTarget())) and
    not fc.getQualifier() instanceof FunctionCall and
    head = fc.getQualifier()
    or
    //
    leftmost(fc.getArgument(0), head)
    or
    leftmost(fc.getQualifier(), head)
}

// Propagate values from an array to an element access, `a` taints `a[i]`
predicate elementAccessStep(DataFlow::Node n1, DataFlow::Node n2, ArrayExpr a) {
    // arr -> arr[ind]
    n2.asExpr() = a and
    a.getArrayBase() = n1.asExpr()
}

// All the stl and bsl taint steps in a single predicate.
predicate stlBslTaintStep(DataFlow::Node n1, DataFlow::Node n2) {
    operatorAsFunctionStep(n1, n2, _) or
    qualifierToCallStep(n1, n2, _) or
    argToCallStep(n1, n2, _) or
    pureFuncArgToCallStep(n1, n2, _) or
    elementAccessStep(n1, n2, _)
}

```

