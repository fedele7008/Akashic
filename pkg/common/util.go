package common

func ternary[T any](cond bool, caseTrue, caseFalse T) T {
	if cond {
		return caseTrue
	}
	return caseFalse
}
