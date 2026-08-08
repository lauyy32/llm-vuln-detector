/**
 * @name CPG taint CWE-078 (upstream CommandInjectionFlow)
 * @description Per-CWE taint evidence reusing CodeQL's own CommandInjectionFlow.
 * @kind table
 * @id lauyy32/cpg/taint-cwe-078
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.security.dataflow.CommandInjectionQuery

from DataFlow::Node source, DataFlow::Node sink
where CommandInjectionFlow::flow(source, sink)
select "CWE-078" as cwe,
  source.getLocation().getStartLine() as sourceLine,
  source.toString() as sourceNode,
  sink.getLocation().getStartLine() as sinkLine,
  sink.toString() as sinkNode
