package core

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// PromptPasswordOpts controls PromptPassword behavior.
type PromptPasswordOpts struct {
	Prompt        string // first prompt, e.g. "Password: "
	ConfirmPrompt string // second prompt for confirmation; "" disables confirmation
	StdinSource   bool   // if true, read from stdin (no echo control); for piped input
}

// PromptPassword reads a password from the user without echoing it to the
// terminal. When ConfirmPrompt is non-empty, prompts twice and rejects if
// the two entries differ.
//
// When StdinSource is true (e.g. `--password-stdin` flag), reads a single
// line from stdin and skips the confirmation step. This is the script-
// friendly path: `echo "$PASSWD" | akashic-cli ... --password-stdin`.
//
// Errors:
//   - terminal not available + StdinSource not set → returns clear error
//   - confirmation mismatch → returns "passwords do not match"
//   - empty password → returns "password cannot be empty"
func PromptPassword(opts PromptPasswordOpts) (string, error) {
	if opts.StdinSource {
		return readLineFromStdin()
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("stdin is not a terminal; pass --password-stdin to read from a pipe")
	}

	pw, err := promptOnce(opts.Prompt, fd)
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	if opts.ConfirmPrompt != "" {
		confirm, err := promptOnce(opts.ConfirmPrompt, fd)
		if err != nil {
			return "", err
		}
		if pw != confirm {
			return "", fmt.Errorf("passwords do not match")
		}
	}
	return pw, nil
}

func promptOnce(prompt string, fd int) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	bytes, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr) // newline (ReadPassword swallows the user's RET)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(bytes), nil
}

func readLineFromStdin() (string, error) {
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", fmt.Errorf("empty password from stdin")
	}
	return line, nil
}
