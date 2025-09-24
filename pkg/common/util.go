package common

import (
	"os/exec"
	"strings"
)

func Ternary[T any](cond bool, caseTrue, caseFalse T) T {
	if cond {
		return caseTrue
	}
	return caseFalse
}

func GetGitInfo() (branch, commit string, err error) {
	branchCmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	branchOut, outputErr := branchCmd.Output()
	if outputErr != nil {
		return "", "", outputErr
	}
	branch = strings.TrimSpace(string(branchOut))

	commitCmd := exec.Command("git", "rev-parse", "HEAD")
	commitOut, outputErr := commitCmd.Output()
	if outputErr != nil {
		return "", "", outputErr
	}
	commit = strings.TrimSpace(string(commitOut))

	return branch, commit, nil
}
