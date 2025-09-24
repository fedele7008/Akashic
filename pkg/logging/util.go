package logging

func ifZero[T ~int](value, defaultValue T) T {
	if value == 0 {
		return defaultValue
	}
	return value
}
