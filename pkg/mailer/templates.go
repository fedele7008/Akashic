package mailer

import (
	"bytes"
	"embed"
	"fmt"
	htmltmpl "html/template"
	texttmpl "text/template"
)

// Email templates live in pkg/mailer/templates/ and ship as
// embed.FS — same pattern as auth-server's web templates. Each
// logical email has two files (foo.html.tmpl + foo.txt.tmpl); we
// render both into a Message ready to hand to a Mailer.
//
// Why html/template + text/template separately: html/template
// auto-escapes HTML contexts (preventing XSS in operator-injected
// fields like display name), text/template doesn't. Using the
// wrong one for the wrong body would either escape literal "<"
// in the text body (ugly) or fail to escape in HTML (XSS).

//go:embed templates/*.html.tmpl templates/*.txt.tmpl
var templateFS embed.FS

// Render parses the named html+text template pair from the embedded
// FS, executes them with `data`, and returns a Message with the
// rendered subject/HTML/text. Subject is rendered from the FIRST
// non-empty line of the .txt.tmpl prefixed with `Subject: ` — same
// convention as Go's built-in mail templates. Anything after the
// blank-line separator is the body.
//
// `data` is whatever the caller wants the template to interpolate.
// Templates use `.FieldName` syntax; missing fields render as the
// zero value (no error), so callers can pass partially-filled
// structs without breaking the render.
func Render(name string, data any) (Message, error) {
	textRaw, err := templateFS.ReadFile("templates/" + name + ".txt.tmpl")
	if err != nil {
		return Message{}, fmt.Errorf("read text template %q: %w", name, err)
	}
	htmlRaw, err := templateFS.ReadFile("templates/" + name + ".html.tmpl")
	if err != nil {
		return Message{}, fmt.Errorf("read html template %q: %w", name, err)
	}

	textTmpl, err := texttmpl.New(name + ".txt").Parse(string(textRaw))
	if err != nil {
		return Message{}, fmt.Errorf("parse text template %q: %w", name, err)
	}
	htmlTmpl, err := htmltmpl.New(name + ".html").Parse(string(htmlRaw))
	if err != nil {
		return Message{}, fmt.Errorf("parse html template %q: %w", name, err)
	}

	var textBuf bytes.Buffer
	if err := textTmpl.Execute(&textBuf, data); err != nil {
		return Message{}, fmt.Errorf("execute text template %q: %w", name, err)
	}
	var htmlBuf bytes.Buffer
	if err := htmlTmpl.Execute(&htmlBuf, data); err != nil {
		return Message{}, fmt.Errorf("execute html template %q: %w", name, err)
	}

	subject, body := splitSubjectBody(textBuf.String())
	return Message{
		Subject: subject,
		Text:    body,
		HTML:    htmlBuf.String(),
	}, nil
}

// splitSubjectBody peels the leading `Subject: ...\n\n` block off
// a rendered text template. The convention keeps subject + body in
// one source file so templates are easier to maintain (no separate
// subject string to forget when editing).
//
// If the template doesn't follow the convention (no leading
// `Subject: ` line), we fall back to "(no subject)" — defensive,
// but a missing subject would already be a surprising template
// authoring mistake.
func splitSubjectBody(rendered string) (subject, body string) {
	const prefix = "Subject: "
	if len(rendered) < len(prefix) || rendered[:len(prefix)] != prefix {
		return "(no subject)", rendered
	}
	rest := rendered[len(prefix):]
	// Subject is everything until the first \n; body is everything
	// after the *blank* line (\n\n). If the template doesn't have
	// the blank line, treat all-after-first-\n as body.
	for i := 0; i < len(rest); i++ {
		if rest[i] == '\n' {
			subject = rest[:i]
			body = trimLeadingBlankLine(rest[i+1:])
			return subject, body
		}
	}
	return rest, ""
}

func trimLeadingBlankLine(s string) string {
	if len(s) > 0 && s[0] == '\n' {
		return s[1:]
	}
	return s
}
