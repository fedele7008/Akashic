package common

type Nullable[T any] struct {
	Value T
	Valid bool
}

func (n Nullable[T]) Get() (val T, ok bool) {
	ok = n.Valid
	val = ternary(n.Valid, n.Value, func() T { var v T; return v }())
	return
}

func (n Nullable[T]) Set(val T) Nullable[T] {
	n.Valid = true
	n.Value = val
	return n
}

func (n Nullable[T]) Clear() Nullable[T] {
	n.Valid = false
	var v T
	n.Value = v
	return n
}

func (n Nullable[T]) IsValid() bool {
	return n.Valid
}

func (n Nullable[T]) IfValidGet(fallback T) T {
	return ternary(n.Valid, n.Value, fallback)
}

func (n Nullable[T]) IfNullSet(val T) Nullable[T] {
	if n.Valid {
		return n
	}
	return n.Set(val)
}

func MakeNullable[T any](val T) Nullable[T] {
	return Nullable[T]{}.Set(val)
}
