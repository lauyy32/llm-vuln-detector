/**
 * @name CPG taint CWE-094 (upstream CodeInjectionFlow)
 * @description Per-CWE taint evidence reusing CodeQL's own CodeInjectionFlow.
 *              Carries a `file` column (source file basename) so slice_builder can
 *              scope the TAINT VERDICT to the sliced source file.
 * @kind table
 * @id lauyy32/cpg/taint-cwe-094
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.security.dataflow.CodeInjectionQuery

from DataFlow::Node source, DataFlow::Node sink
where CodeInjectionFlow::flow(source, sink)
select "CWE-094" as cwe,
  source.getLocation().getFile().getBaseName() as file,
  source.getLocation().getStartLine() as sourceLine,
  source.toString() as sourceNode,
  sink.getLocation().getStartLine() as sinkLine,
  sink.toString() as sinkNode,
  source.getLocation().getFile().getAbsolutePath() as abs_path
