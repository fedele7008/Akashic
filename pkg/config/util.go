package config

import (
	"fmt"
	"os"
)

func (m *ConfigManager) VerbosePrintlnf(format string, args ...any) {
	if m.verbose {
		fmt.Fprintf(os.Stderr, "[VERBOSE] "+format+"\n", args...)
	}
}
