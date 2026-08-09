/**
 * @name CPG taint CWE-089 (upstream SqlInjectionFlow)
 * @description Per-CWE taint evidence reusing CodeQL's own SqlInjectionFlow.
 *              Carries a `file` column (source file basename) so slice_builder can
 *              scope the TAINT VERDICT to the sliced source file.
 * @kind table
 * @id lauyy32/cpg/taint-cwe-089
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.security.dataflow.SqlInjectionQuery

from DataFlow::Node source, DataFlow::Node sink
where SqlInjectionFlow::flow(source, sink)
select "CWE-089" as cwe,
  source.getLocation().getFile().getBaseName() as file,
  source.getLocation().getStartLine() as sourceLine,
  source.toString() as sourceNode,
  sink.getLocation().getStartLine() as sinkLine,
  sink.toString() as sinkNode,
  source.getLocation().getFile().getAbsolutePath() as abs_path
