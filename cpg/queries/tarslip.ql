/**
 * TarSlip（CWE-022）污点流：tarfile.open 的非硬编码归档 -> extractall/extract 不安全提取。
 *
 * 复用上游官方 TarSlipFlow（source=tarfile.open 动态路径，sink=extractall/extract 调用，
 * sanitizer=路径检查守卫），与 taint.ql（PathInjection）互补——PathInjection 只认 open 类
 * sink，TarSlip 的 sink 是 tar 成员提取，二者覆盖不同的 CWE-022 子类。
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.security.dataflow.TarSlipQuery

from DataFlow::Node source, DataFlow::Node sink
where TarSlipFlow::flow(source, sink)
select "CWE-022" as cwe, source.getLocation().getFile().getBaseName() as file,
  source.getLocation().getStartLine() as sourceLine, source.toString() as sourceNode,
  sink.getLocation().getStartLine() as sinkLine, sink.toString() as sinkNode,
  sink.getLocation().getFile().getAbsolutePath() as abs_path
