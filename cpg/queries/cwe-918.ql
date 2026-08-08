/**
 * @name CPG taint CWE-918 (upstream FullServerSideRequestForgeryFlow)
 * @description Per-CWE taint evidence reusing CodeQL's own FullServerSideRequestForgeryFlow
 *              (the canonical py/full-ssrf detection: attacker has full control of the
 *              outbound request URL). Output is normalised to
 *              (cwe, file, sourceLine, sourceNode, sinkLine, sinkNode) and aggregated by
 *              pipeline.py into taint.csv. The `file` column (source's file basename)
 *              lets slice_builder scope the TAINT VERDICT to the function's own source file.
 * @kind table
 * @id lauyy32/cpg/taint-cwe-918
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.security.dataflow.ServerSideRequestForgeryQuery

from DataFlow::Node source, DataFlow::Node sink
where FullServerSideRequestForgeryFlow::flow(source, sink)
select "CWE-918" as cwe,
  source.getLocation().getFile().getBaseName() as file,
  source.getLocation().getStartLine() as sourceLine,
  source.toString() as sourceNode,
  sink.getLocation().getStartLine() as sinkLine,
  sink.toString() as sinkNode
