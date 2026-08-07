/**
 * @name CPG CFG edges
 * @description Control-flow successor edges, labelled with the branch condition when applicable.
 * @kind table
 * @id lauyy32/cpg/cfg
 */

import python
import CpgTarget

from Function f, ControlFlowNode n, ControlFlowNode succ, string edge
where
  isTargetFunction(f) and
  n.getScope() = f and
  succ = n.getASuccessor() and
  (
    n.getATrueSuccessor() = succ and edge = "true"
    or
    n.getAFalseSuccessor() = succ and edge = "false"
    or
    not n.getATrueSuccessor() = succ and
    not n.getAFalseSuccessor() = succ and
    edge = "next"
  )
select f.getName() as func,
  n.getLocation().getStartLine() as fromLine,
  n.toString() as fromNode,
  edge as edgeKind,
  succ.getLocation().getStartLine() as toLine,
  succ.toString() as toNode
