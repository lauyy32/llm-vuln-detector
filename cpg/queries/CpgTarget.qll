/**
 * Shared helpers for CPG slice extraction.
 *
 * The CodeQL database is built per-sample (one target file), so by default we
 * emit slices for every function that lives in the analysed source tree.
 * Filtering down to a specific vulnerable function is done downstream in the
 * Python serializer, which keeps the queries reusable across samples.
 */

import python

/** Holds if `f` is a function defined in the analysed source tree. */
predicate isTargetFunction(Function f) { exists(f.getLocation().getFile().getRelativePath()) }

/** Gets a stable, single-valued QL class label for `node`. */
bindingset[node]
string qlKind(AstNode node) { result = concat(string c | c = node.getAQlClass() | c, "|") }
