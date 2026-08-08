/**
 * @name CPG taint CWE-022 (upstream PathInjectionFlow)
 * @description Per-CWE taint evidence reusing CodeQL's own PathInjectionFlow.
 *              Replaces the old method-name heuristic (get->execute). Output is
 *              normalised to (cwe, sourceLine, sourceNode, sinkLine, sinkNode)
 *              and aggregated by pipeline.py into taint.csv.
 * @kind table
 * @id lauyy32/cpg/taint-cwe-022
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.security.dataflow.PathInjectionQuery

from DataFlow::Node source, DataFlow::Node sink
where PathInjectionFlow::flow(source, sink)
select "CWE-022" as cwe,
  source.getLocation().getStartLine() as sourceLine,
  source.toString() as sourceNode,
  sink.getLocation().getStartLine() as sinkLine,
  sink.toString() as sinkNode
