/**
 * @name CPG taint CWE-094 (upstream CodeInjectionFlow)
 * @description Per-CWE taint evidence reusing CodeQL's own CodeInjectionFlow.
 * @kind table
 * @id lauyy32/cpg/taint-cwe-094
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.security.dataflow.CodeInjectionQuery

from DataFlow::Node source, DataFlow::Node sink
where CodeInjectionFlow::flow(source, sink)
select "CWE-094" as cwe,
  source.getLocation().getStartLine() as sourceLine,
  source.toString() as sourceNode,
  sink.getLocation().getStartLine() as sinkLine,
  sink.toString() as sinkNode
