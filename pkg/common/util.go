package common

import (
	"encoding/json"
	"os/exec"
	"strings"

	"go.yaml.in/yaml/v3"
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

func ConvJsonToYaml(jsonData []byte) (string, error) {
	var data any
	err := json.Unmarshal(jsonData, &data)
	if err != nil {
		return "", err
	}

	yamlData, err := yaml.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(yamlData), nil
}

func ConvJsonToPrettyJson(jsonData []byte) (string, error) {
	var data any
	err := json.Unmarshal(jsonData, &data)
	if err != nil {
		return "", err
	}

	prettyJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}

	return string(prettyJSON), nil
}
