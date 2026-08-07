/**
 * @name CPG AST edges
 * @description Parent -> child edges of the abstract syntax tree, one row per edge.
 * @kind table
 * @id lauyy32/cpg/ast
 */

import python
import CpgTarget

from Function f, AstNode parent, AstNode child
where
  isTargetFunction(f) and
  parent.getScope() = f and
  child = parent.getAChildNode()
select f.getName() as func,
  parent.getLocation().getStartLine() as parentLine,
  qlKind(parent) as parentKind,
  parent.toString() as parentText,
  child.getLocation().getStartLine() as childLine,
  qlKind(child) as childKind,
  child.toString() as childText
