package common

import (
	"reflect"
	"testing"
)

// ---- 기본 프리미티브 동작들 ----

func TestInitAndGet_Primitives(t *testing.T) {
	n := MakeNullable(13)
	v, ok := n.Get()
	if !ok {
		t.Fatalf("MakeNullable should be valid")
	}
	if v != 13 {
		t.Fatalf("MakeNullable value = %v, want 13", v)
	}

	// zero value type but valid
	ns := MakeNullable[string]("")
	sv, sok := ns.Get()
	if !sok || sv != "" {
		t.Fatalf("MakeNullable for empty string: got(%q,%v), want('',true)", sv, sok)
	}

	// default zero-value Nullable (zero struct) is invalid
	var z Nullable[int]
	if z.IsValid() {
		t.Fatalf("zero-value Nullable should be invalid")
	}
	if got, ok := z.Get(); ok || got != 0 {
		t.Fatalf("zero-value Get() = (%v,%v), want (0,false)", got, ok)
	}
}

func TestSetClear_Immutability(t *testing.T) {
	orig := MakeNullable(1)

	// Set returns a new value; orig must remain unchanged
	mod := orig.Set(2)
	if v, _ := orig.Get(); v != 1 {
		t.Fatalf("orig changed after Set: got %v want 1", v)
	}
	if v, _ := mod.Get(); v != 2 {
		t.Fatalf("mod value after Set = %v want 2", v)
	}

	// Clear returns new value and clears Value to zero
	c := mod.Clear()
	if c.IsValid() {
		t.Fatalf("cleared Nullable should be invalid")
	}
	if v, _ := c.Get(); v != 0 {
		t.Fatalf("cleared Nullable value should be zero, got %v", v)
	}
	// original mod still should be unchanged (valid)
	if !mod.IsValid() {
		t.Fatalf("mod unexpectedly changed after Clear")
	}
}

func TestChaining(t *testing.T) {
	// chaining should work because methods return new Nullable values
	v, ok := MakeNullable(1).Clear().Set(12).Get()
	if !ok || v != 12 {
		t.Fatalf("chaining Set/Clear failed: got (%v,%v), want (12,true)", v, ok)
	}
}

// ---- IfValidGet / IfNullSet behavior ----

func TestIfValidGet_Fallbacks(t *testing.T) {
	n := MakeNullable(42)
	if got := n.IfValidGet(-1); got != 42 {
		t.Fatalf("IfValidGet(valid) = %v, want 42", got)
	}

	inv := Nullable[int]{} // invalid
	if got := inv.IfValidGet(99); got != 99 {
		t.Fatalf("IfValidGet(invalid) = %v, want 99", got)
	}
}

func TestIfNullSet_Behavior(t *testing.T) {
	// IfNullSet on invalid should set and return new valid Nullable
	n := Nullable[int]{} // invalid
	n2 := n.IfNullSet(7)
	if !n2.IsValid() {
		t.Fatalf("IfNullSet on invalid should produce valid result")
	}
	if v, _ := n2.Get(); v != 7 {
		t.Fatalf("IfNullSet set wrong value: got %v want 7", v)
	}

	// IfNullSet on already valid should NOT overwrite
	n3 := MakeNullable(10)
	n4 := n3.IfNullSet(99)
	if v, _ := n4.Get(); v != 10 {
		t.Fatalf("IfNullSet should not overwrite valid: got %v want 10", v)
	}
	// also ensure original not mutated
	if v, _ := n3.Get(); v != 10 {
		t.Fatalf("original mutated unexpectedly: got %v want 10", v)
	}
}

// ---- 합성 타입(구조체, slice, map, pointer) 엣지 케이스 ----

func TestComposite_Types(t *testing.T) {
	type S struct {
		A int
		B string
	}

	// struct value
	ns := MakeNullable[S](S{A: 1, B: "x"})
	if v, ok := ns.Get(); !ok || v.A != 1 || v.B != "x" {
		t.Fatalf("struct Get invalid: got (%v,%v)", v, ok)
	}

	// slice nil vs non-nil
	var nilSlice []int
	nslice := MakeNullable[[]int](nilSlice) // valid + nil slice
	if v, ok := nslice.Get(); !ok || v != nil {
		t.Fatalf("slice nil but valid: got (%#v,%v)", v, ok)
	}
	// make invalid and confirm fallback
	nsliceInvalid := nslice.Clear()
	def := []int{9}
	got := nsliceInvalid.IfValidGet(def)
	if !reflect.DeepEqual(got, def) {
		t.Fatalf("IfValidGet on invalid slice returned %#v, want %#v", got, def)
	}

	// map nil
	var nilMap map[string]int
	nmap := MakeNullable[map[string]int](nilMap)
	if v, ok := nmap.Get(); !ok || v != nil {
		t.Fatalf("map nil but valid: got (%#v,%v)", v, ok)
	}
	nmapInvalid := nmap.Clear()
	defMap := map[string]int{"x": 1}
	if got := nmapInvalid.IfValidGet(defMap); !reflect.DeepEqual(got, defMap) {
		t.Fatalf("IfValidGet on invalid map returned %#v, want %#v", got, defMap)
	}

	// pointer type
	var p *int
	np := MakeNullable[*int](p) // valid + nil pointer
	if v, ok := np.Get(); !ok || v != nil {
		t.Fatalf("pointer nil but valid: got (%v,%v)", v, ok)
	}
	val := 55
	np2 := MakeNullable[*int](&val)
	if v, ok := np2.Get(); !ok || *v != 55 {
		t.Fatalf("pointer non-nil: got (%v,%v), want (&55,true)", v, ok)
	}
}

// ---- zero value vs valid/invalid 분리 ----

func TestZeroValueDistinction(t *testing.T) {
	// int zero but valid
	n0 := MakeNullable(0)
	if v, ok := n0.Get(); !ok || v != 0 {
		t.Fatalf("zero int but valid: got (%v,%v), want (0,true)", v, ok)
	}
	if got := n0.IfValidGet(999); got != 0 {
		t.Fatalf("IfValidGet(valid zero) = %v, want 0", got)
	}

	// string zero but invalid
	ni := Nullable[string]{}
	if v := ni.IfValidGet("fallback"); v != "fallback" {
		t.Fatalf("IfValidGet(invalid string) = %q, want 'fallback'", v)
	}
}

// ---- immutability / value-receiver 특성 테스트 ----

func TestValueReceiver_DoesNotMutateOriginal(t *testing.T) {
	a := MakeNullable(1)
	b := a.Set(2)  // b is new value
	c := a.Clear() // c is another new value

	if v, _ := a.Get(); v != 1 {
		t.Fatalf("a should remain 1, got %v", v)
	}
	if v, _ := b.Get(); v != 2 {
		t.Fatalf("b should be 2, got %v", v)
	}
	if ok := c.IsValid(); ok {
		t.Fatalf("c should be invalid after Clear")
	}
}

// ---- some example-like tests to ensure documentation usage ----

func TestExampleLike_ChainingAndDefaults(t *testing.T) {
	// chain usage
	res, ok := MakeNullable(1).Set(8).IfNullSet(9).Get()
	if !ok || res != 8 {
		t.Fatalf("chain usage gave (%v,%v), want (8,true)", res, ok)
	}
	// Starting invalid
	zero := Nullable[int]{}
	got := zero.IfValidGet(123)
	if got != 123 {
		t.Fatalf("IfValidGet on zero gave %v want 123", got)
	}
}
