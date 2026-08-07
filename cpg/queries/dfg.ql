/**
 * @name CPG DFG edges (SSA def-use)
 * @description Data-flow edges in the classical CPG sense: definition -> use for each
 *              SSA variable, plus phi edges where branches merge.
 *
 *              Deliberately NOT built on `TaintTracking::localTaintStep`. That library
 *              pulls in the full framework-modelling / type-tracking stack, which costs
 *              minutes of evaluation even on a 30-line file and is a poor fit for a
 *              per-sample extraction pass. Transitive source-to-sink reasoning is the
 *              job of taint.ql; the DFG here is the structural graph.
 * @kind table
 * @id lauyy32/cpg/dfg
 */

import python
import CpgTarget

from Function f, string edge, string var, ControlFlowNode a, ControlFlowNode b
where
  isTargetFunction(f) and
  a.getScope() = f and
  (
    exists(SsaVariable v |
      var = v.getId() and
      a = v.getDefinition() and
      b = v.getAUse() and
      edge = "def-use"
    )
    or
    exists(SsaVariable phi, SsaVariable input |
      input = phi.getAPhiInput() and
      var = phi.getId() and
      a = input.getDefinition() and
      b = phi.getDefinition() and
      edge = "phi"
    )
  )
select f.getName() as func,
  var as variable,
  edge as edgeKind,
  a.getLocation().getStartLine() as fromLine,
  a.toString() as fromNode,
  b.getLocation().getStartLine() as toLine,
  b.toString() as toNode
