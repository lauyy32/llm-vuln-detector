/**
 * @name CPG taint CWE-089 (upstream SqlInjectionFlow)
 * @description Per-CWE taint evidence reusing CodeQL's own SqlInjectionFlow.
 * @kind table
 * @id lauyy32/cpg/taint-cwe-089
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.security.dataflow.SqlInjectionQuery

from DataFlow::Node source, DataFlow::Node sink
where SqlInjectionFlow::flow(source, sink)
select "CWE-089" as cwe,
  source.getLocation().getStartLine() as sourceLine,
  source.toString() as sourceNode,
  sink.getLocation().getStartLine() as sinkLine,
  sink.toString() as sinkNode
