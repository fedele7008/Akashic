package mailer

import (
	"context"
	"fmt"

	"github.com/sendgrid/sendgrid-go"
	sgmail "github.com/sendgrid/sendgrid-go/helpers/mail"
)

// sendgridMailer is the production mailer backed by SendGrid's HTTP
// API. We chose SendGrid (over plain SMTP) because:
//   - Most operators choose a transactional provider anyway, and
//     SendGrid's free tier covers most small-tenant workloads
//   - The Go SDK handles retries, rate limiting, and structured
//     error responses without us reimplementing them
//   - Switching providers later (Postmark, Resend, AWS SES) is a
//     drop-in replacement at the `Mailer` interface, not a rewrite
//
// We deliberately don't expose template substitution at this
// layer — callers pass already-rendered HTML+text. Templates live
// in pkg/server/auth/web/email/ and are loaded as html/template
// + text/template by the calling handler.
type sendgridMailer struct {
	client    *sendgrid.Client
	fromEmail string
	fromName  string
}

func newSendGridMailer(apiKey, fromEmail, fromName string) *sendgridMailer {
	return &sendgridMailer{
		client:    sendgrid.NewSendClient(apiKey),
		fromEmail: fromEmail,
		fromName:  fromName,
	}
}

func (m *sendgridMailer) IsConfigured() bool { return true }

func (m *sendgridMailer) Send(ctx context.Context, msg Message) error {
	if msg.To == "" || msg.Subject == "" || msg.HTML == "" {
		return fmt.Errorf("mailer: missing required Message field (to/subject/html)")
	}
	from := sgmail.NewEmail(m.fromName, m.fromEmail)
	to := sgmail.NewEmail("", msg.To)
	// SendGrid's helper builds the multi-part body for us when text
	// + html are both supplied. Empty plainText is allowed but
	// strongly suboptimal for deliverability — the constructor
	// uses a single empty alternative which spam filters dislike.
	plainText := msg.Text
	if plainText == "" {
		plainText = stripTagsApprox(msg.HTML)
	}
	mail := sgmail.NewSingleEmail(from, msg.Subject, to, plainText, msg.HTML)

	// SendGrid's SDK doesn't natively honor context cancellation —
	// its `Send` call is a blocking HTTP roundtrip without a hook.
	// We wrap in a goroutine + select so a cancelled context returns
	// promptly even if SendGrid is hanging. The actual HTTP call
	// keeps running in the background; we accept the leaked goroutine
	// rather than holding up the parent (this is a transactional
	// mail send, not a tight loop).
	type result struct {
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		resp, err := m.client.Send(mail)
		if err != nil {
			resultCh <- result{err: fmt.Errorf("sendgrid send: %w", err)}
			return
		}
		// SendGrid returns 2xx on success, 4xx/5xx on failure with
		// an error body. The SDK doesn't classify automatically;
		// we do it here so callers get a typed Go error.
		if resp.StatusCode >= 400 {
			resultCh <- result{err: fmt.Errorf("sendgrid status %d: %s",
				resp.StatusCode, resp.Body)}
			return
		}
		resultCh <- result{err: nil}
	}()
	select {
	case r := <-resultCh:
		return r.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// stripTagsApprox is a *very* lazy HTML→text converter for fallback
// when the caller doesn't supply a Message.Text. Better than empty
// (anti-spam) but worse than a properly-formatted plain-text
// counterpart that the caller authored. Templates SHOULD ship
// matching .html.tmpl + .txt.tmpl pairs and avoid this path.
//
// The approximation is intentional: we don't pull in an HTML parser
// for what's a fallback-only hint. The output may include extra
// whitespace and stripped formatting; that's acceptable for the
// "spam filter sees something other than empty" goal.
func stripTagsApprox(html string) string {
	out := make([]byte, 0, len(html))
	inTag := false
	for i := 0; i < len(html); i++ {
		c := html[i]
		switch {
		case c == '<':
			inTag = true
		case c == '>':
			inTag = false
		case !inTag:
			out = append(out, c)
		}
	}
	return string(out)
}
