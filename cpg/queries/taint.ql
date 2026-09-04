/**
 * @name CPG taint CWE-022 (custom source + upstream PathInjection flow)
 * @description Path-traversal evidence. Reuses CodeQL's own PathInjectionFlow
 *              (with its concrete file-access sinks) but registers the corpus
 *              CVEs' custom entry-point sources (any parameter named path /
 *              filepath / filename / file_path) as additional taint sources via
 *              PathInjection::Source subclassing. Output:
 *              (cwe, file, sourceLine, sourceNode, sinkLine, sinkNode, abs_path).
 * @kind table
 * @id lauyy32/cpg/taint-cwe-022
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.security.dataflow.PathInjectionCustomizations
import semmle.python.security.dataflow.PathInjectionQuery

/** 辅助目录（文档/测试/CI 脚本）——工具脚本的合法文件操作不是漏洞，排除误标。 */
private predicate isAuxFile(DataFlow::Node n) {
  exists(string p |
    p = n.getLocation().getFile().getAbsolutePath() and
    (p.matches("%/docs/%") or p.matches("%/tests/%") or p.matches("%/test/%") or
     p.matches("%/.github/%") or p.matches("%/examples/%") or p.matches("%/scripts/%"))
  )
}

/** A parameter named like a filesystem path, as a taint source. */
class CpgPathSource extends PathInjection::Source {
  CpgPathSource() {
    exists(DataFlow::ParameterNode pn |
      pn = this and
      (pn.getParameter().getName() = "path" or
       pn.getParameter().getName() = "filepath" or
       pn.getParameter().getName() = "filename" or
       pn.getParameter().getName() = "file_path" or
       pn.getParameter().getName() = "candidate" or
       pn.getParameter().getName() = "directory" or
       pn.getParameter().getName() = "abs_path") and
      not isAuxFile(pn)
    )
  }
}

/**
 * D5-A (OPEN #25, 2026-09-03) · 通用净化器谓词（corpus-level，stdlib 路径规范化）。
 * `os.path.{realpath,abspath,normpath,basename,dirname,relpath}` 对路径做规范化，
 * 可消除路径遍历（CWE-022）的 source→sink 连通——属 CodeQL 既有 PathInjection 框架的
 * Sanitizer 扩展点，全语料统一适用，无 per-CVE 调参、无标签泄漏。
 * 目的：实测「引入 isSanitizer 能否突破随机」。预期对残 7（项目自定义净化器 /
 * 守卫 / 删 monkeypatch）无效——它们的 fixed 版本不调用 stdlib 规范化，故 vuln 与
 * fixed 流集仍相同，双标与 BA/MCC 不变。
 */
class CpgPathSanitizer extends PathInjection::Sanitizer, DataFlow::CallCfgNode {
  CpgPathSanitizer() {
    this.getFunction().(DataFlow::AttrRead).getAttributeName() in
      ["realpath", "abspath", "normpath", "basename", "dirname", "relpath", "secure_filename"]
  }
}

from DataFlow::Node source, DataFlow::Node sink
where PathInjectionFlow::flow(source, sink)
select "CWE-022" as cwe,
  source.getLocation().getFile().getBaseName() as file,
  source.getLocation().getStartLine() as sourceLine,
  source.toString() as sourceNode,
  sink.getLocation().getStartLine() as sinkLine,
  sink.toString() as sinkNode,
  source.getLocation().getFile().getAbsolutePath() as abs_path
