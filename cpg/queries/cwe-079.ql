/**
 * @name CPG taint CWE-079 (upstream ReflectedXssFlow)
 * @description Per-CWE taint evidence reusing CodeQL's own ReflectedXssFlow. Output is
 *              normalised to (cwe, file, sourceLine, sourceNode, sinkLine, sinkNode) and
 *              aggregated by pipeline.py into taint.csv. The `file` column (source's file
 *              basename) lets slice_builder scope the TAINT VERDICT to the function's own
 *              source file.
 * @kind table
 * @id lauyy32/cpg/taint-cwe-079
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.security.dataflow.ReflectedXssQuery

from DataFlow::Node source, DataFlow::Node sink
where ReflectedXssFlow::flow(source, sink)
select "CWE-079" as cwe,
  source.getLocation().getFile().getBaseName() as file,
  source.getLocation().getStartLine() as sourceLine,
  source.toString() as sourceNode,
  sink.getLocation().getStartLine() as sinkLine,
  sink.toString() as sinkNode,
  source.getLocation().getFile().getAbsolutePath() as abs_path
