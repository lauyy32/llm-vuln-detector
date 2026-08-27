/**
 * @name CPG taint CWE-918 (custom source + upstream SSRF flow)
 * @description Server-Side Request Forgery evidence. Reuses CodeQL's own
 *              FullServerSideRequestForgeryFlow (with its concrete outbound-HTTP
 *              sinks) but registers the corpus CVEs' custom entry-point sources
 *              (any parameter named url / uri / path / url_str / endpoint /
 *              target) as additional taint sources via
 *              ServerSideRequestForgery::Source subclassing. Output:
 *              (cwe, file, sourceLine, sourceNode, sinkLine, sinkNode, abs_path).
 * @kind table
 * @id lauyy32/cpg/taint-cwe-918
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.security.dataflow.ServerSideRequestForgeryCustomizations
import semmle.python.security.dataflow.ServerSideRequestForgeryQuery

/** A parameter named like a URL/URI fed to an HTTP call, as a taint source. */
class CpgSsrfSource extends ServerSideRequestForgery::Source {
  CpgSsrfSource() {
    exists(DataFlow::ParameterNode pn |
      pn = this and
      (pn.getParameter().getName() = "url" or
       pn.getParameter().getName() = "uri" or
       pn.getParameter().getName() = "path" or
       pn.getParameter().getName() = "url_str" or
       pn.getParameter().getName() = "endpoint" or
       pn.getParameter().getName() = "target")
    )
  }
}

from DataFlow::Node source, DataFlow::Node sink
where FullServerSideRequestForgeryFlow::flow(source, sink)
select "CWE-918" as cwe,
  source.getLocation().getFile().getBaseName() as file,
  source.getLocation().getStartLine() as sourceLine,
  source.toString() as sourceNode,
  sink.getLocation().getStartLine() as sinkLine,
  sink.toString() as sinkNode,
  source.getLocation().getFile().getAbsolutePath() as abs_path
