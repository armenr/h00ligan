; Go structural-tags query — patterns 0..10 are VERBATIM from tree-sitter-go
; v0.25.0 queries/tags.scm; pattern 11 is a documented h00ligan-engine AUGMENTATION.
;
; Provenance:
;   upstream: https://github.com/tree-sitter/tree-sitter-go
;   tag:      v0.25.0 (matches the `tree-sitter-go = "0.25.0"` crate dep)
;   source:   raw.githubusercontent.com/tree-sitter/tree-sitter-go/v0.25.0/queries/tags.scm
;   fetched:  2026-07-13 (WU-0023 P3a)
;
; AUGMENTATION (pattern 11): the upstream `var_declaration (var_spec …)` pattern
; (pattern 9) only matches a SINGLE `var x = …` — the grammar nests grouped
; `var ( a…; b… )` specs inside a `var_spec_list`, so pattern 9 silently misses
; every grouped-block package var (measured: 14 real package vars on partyline).
; `const_declaration` has NO `const_spec_list` (its specs are direct children in
; both forms), so pattern 10 already covers grouped consts — only `var` needs the
; extra pattern. Pattern 11 matches ONLY `var_spec`s inside a `var_spec_list`, so
; it is DISJOINT from pattern 9 (a var_spec is either a direct child of
; var_declaration OR inside a var_spec_list, never both) — no double-count.
;
; DO NOT reorder: `go.rs` dispatches by `match.pattern_index` against the pattern
; ORDER below (ADR-0024 §D / P3a MUST-FIX #1). The `go_query_pattern_shape_is_stable`
; unit test asserts the pattern count + the @definition captures the dispatch relies on.
;
; Pattern index → GoExtractor handling (0-based, in file order):
;   0  function_declaration  @definition.function  -> Function (parent=None)
;   1  method_declaration    @definition.method    -> Function (parent=receiver)
;   2  call_expression       @reference.call       -> SKIP
;   3  type_spec             @definition.type      -> Struct/Trait (by underlying)
;   4  (type_identifier)     @reference.type       -> SKIP
;   5  package_clause        @name (bare)          -> SKIP (see go.rs rationale)
;   6  type_declaration/interface_type @name (bare) -> SKIP (redundant with 3)
;   7  type_declaration/struct_type    @name (bare) -> SKIP (redundant with 3)
;   8  import_declaration    @name (bare)          -> SKIP
;   9  var_declaration       @name (bare)          -> Static (single `var x`; top-level only)
;   10 const_declaration     @name (bare)          -> Const   (top-level only)
;   11 var_spec_list         @name (bare)  [AUGMENT]-> Static (grouped `var (…)`; top-level only)

(
  (comment)* @doc
  .
  (function_declaration
    name: (identifier) @name) @definition.function
  (#strip! @doc "^//\\s*")
  (#set-adjacent! @doc @definition.function)
)

(
  (comment)* @doc
  .
  (method_declaration
    name: (field_identifier) @name) @definition.method
  (#strip! @doc "^//\\s*")
  (#set-adjacent! @doc @definition.method)
)

(call_expression
  function: [
    (identifier) @name
    (parenthesized_expression (identifier) @name)
    (selector_expression field: (field_identifier) @name)
    (parenthesized_expression (selector_expression field: (field_identifier) @name))
  ]) @reference.call

(type_spec
  name: (type_identifier) @name) @definition.type

(type_identifier) @name @reference.type

(package_clause "package" (package_identifier) @name)

(type_declaration (type_spec name: (type_identifier) @name type: (interface_type)))

(type_declaration (type_spec name: (type_identifier) @name type: (struct_type)))

(import_declaration (import_spec) @name)

(var_declaration (var_spec name: (identifier) @name))

(const_declaration (const_spec name: (identifier) @name))

; [AUGMENT — not upstream] grouped `var ( a…; b… )` specs nest under a
; var_spec_list; pattern 9 above only sees a direct (single-`var`) var_spec.
(var_spec_list (var_spec name: (identifier) @name))
