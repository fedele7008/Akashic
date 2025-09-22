package common

func Ternary[T any](cond bool, caseTrue, caseFalse T) T {
	if cond {
		return caseTrue
	}
	return caseFalse
}
