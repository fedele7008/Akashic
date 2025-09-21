package logger

import (
	"akashic/akashic/pkg/common"
	"fmt"

	"github.com/araddon/dateparse"
)

func ifZero[T ~int](value, defaultValue T) T {
	if value == 0 {
		return defaultValue
	}
	return value
}

func parseToUnixNano(ts string) (common.Nullable[string], error) {
	t, err := dateparse.ParseAny(ts)
	if err != nil {
		return common.EmptyNullable[string](), err
	}
	return common.MakeNullable(fmt.Sprintf("%d", t.UnixNano())), nil
}
