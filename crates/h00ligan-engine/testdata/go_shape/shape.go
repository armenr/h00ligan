// Package shape is a hand-verified golden fixture for the WU-0023 P3a Go
// structural extractor. Its top-level (parent=None) identifier NAME SET and
// per-kind counts are asserted, byte-for-byte, by
// `go.rs::golden_fixture_set_and_kind_equality` through the SAME
// extract_directory + build_graph path the partyline measurement uses.
//
// Any drift in the extractor's visibility / kind / top-level-filter logic breaks
// the set-equality assertion — this is the non-vacuous reproducible guard. Do
// NOT "fix" the deliberately-odd shapes below (function-local decls, a blank
// var, a type alias); each proves one extractor rule.
package shape

import "fmt"

// Alpha is an exported function (-> Function, Public).
func Alpha() int { return 1 }

// beta is unexported and holds function-local var/const that MUST be rejected by
// the top-level (package-scope) filter — they are not package-scope identifiers.
func beta() int {
	var local = 3
	const localConst = 4
	return local + localConst
}

// Widget is an exported struct (-> Struct, Public).
type Widget struct {
	Name string
}

// gadget is an unexported struct (-> Struct, Private).
type gadget struct{}

// Clocker is an exported interface (-> Trait, Public).
type Clocker interface {
	Tick() int
}

// Meter is a DEFINED type `type X Y` (underlying float64) -> Struct per the
// charter kind-map (not an alias; see Handle below).
type Meter float64

// Handle is a type ALIAS `type X = Y`. It parses as a distinct `type_alias`
// grammar node with NO pattern in the vendored tags.scm, so it is INVISIBLE at
// this floor (MUST-FIX #2) — it must be ABSENT from the extracted set. This is a
// recorded LEAK, and its absence here is the non-vacuous proof of that leak.
type Handle = int

// Tick is an exported method on *Widget (-> nested, parent=Widget).
func (w *Widget) Tick() int { return len(w.Name) }

// reset is an unexported method on Widget (-> nested, parent=Widget).
func (w Widget) reset() { w.Name = "" }

// MaxN is an exported package const.
const MaxN = 10

// lowConst is an unexported package const.
const lowConst = 2

// A grouped/iota const block: First exported, second unexported — both captured.
const (
	First = iota
	second
)

// Registry is an exported package var.
var Registry = fmt.Sprintf("registry-%d", MaxN)

// cache is an unexported package var.
var cache int

// A grouped `var ( … )` block — its specs nest under a var_spec_list, which the
// verbatim upstream pattern misses; the go.scm AUGMENT pattern (11) captures
// them. GroupedVar exported, groupedVar unexported — both MUST appear.
var (
	GroupedVar = 1
	groupedVar = 2
)

// A blank package var — the `_` name MUST be skipped.
var _ = "ignored"
