/**
 * @name CPG taint path (untrusted input -> SQL execution)
 * @description Source-to-sink taint paths. This is the "evidence" slice: it tells the
 *              LLM which untrusted value actually reaches a dangerous sink, which is the
 *              piece of context a request-only detector can never observe.
 * @kind table
 * @id lauyy32/cpg/taint
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * Demo configuration for the smoke-test sample.
 *
 * Deliberately heuristic (method-name based) so that it works on a standalone
 * snippet without framework modelling. Real CVE corpora will swap this for the
 * upstream `py/sql-injection` configuration plus per-CWE configurations.
 */
module DemoSqliConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.(DataFlow::MethodCallNode).getMethodName() = "get"
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() in ["execute", "executemany", "executescript"] and
      sink = call.getArg(0)
    )
  }
}

module DemoSqliFlow = TaintTracking::Global<DemoSqliConfig>;

from DataFlow::Node source, DataFlow::Node sink
where DemoSqliFlow::flow(source, sink)
select source.getLocation().getStartLine() as sourceLine,
  source.toString() as sourceNode,
  sink.getLocation().getStartLine() as sinkLine,
  sink.toString() as sinkNode
