package common

type AkashicApp interface {
	VerbosePrintlnf(format string, args ...any)
	GetVerbose() bool
	SetVerbose(v bool)
}
