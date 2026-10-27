package dispatcher

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/secret"
)

// ErrMailAttachmentUnsupported: mail_mode=api has no attachment field.
var ErrMailAttachmentUnsupported = errors.New("mail: mail_mode=api cannot send attachments")

type MailClient struct {
	Secrets secret.SecretProvider
}

// SendEmail sends a plain-text message. headers carries optional extra RFC 5322
// headers (e.g. List-Unsubscribe / List-Unsubscribe-Post for RFC 8058); pass
// nil for none. Header names are validated against RFC 5322 field-name syntax,
// keel-controlled/structural names are rejected, and any header whose full
// `Name: value` line would exceed the 998-octet limit is rejected — SendEmail
// fails loudly rather than emitting a malformed or truncated header.
func (m *MailClient) SendEmail(ctx context.Context, subject string, body string, recipients []string, headers map[string]string) error {
	if err := validateHeaders(headers); err != nil {
		return err
	}
	if config.Config().MailMode == "api" {
		return m.postMailAPI(ctx, subject, body, recipients, false, headers)
	}
	return m.sendSMTP(ctx, subject, recipients, headers, "text/plain", body, "", nil)
}

// SendEmailHTML sends an HTML message with an optional PDF attachment.
func (m *MailClient) SendEmailHTML(ctx context.Context, subject string, htmlBody string, recipients []string, attachmentName string, attachmentData []byte) error {
	if config.Config().MailMode == "api" {
		if len(attachmentData) > 0 {
			return ErrMailAttachmentUnsupported
		}
		return m.postMailAPI(ctx, subject, htmlBody, recipients, true, nil)
	}
	return m.sendSMTP(ctx, subject, recipients, nil, "text/html", htmlBody, attachmentName, attachmentData)
}

// protectedHeaders are names keel sets itself or that are structurally/security
// sensitive; a caller cannot override them via the headers map (would produce
// duplicate/spoofed headers). Compared case-insensitively.
var protectedHeaders = map[string]struct{}{
	"from": {}, "sender": {}, "to": {}, "cc": {}, "bcc": {}, "subject": {},
	"date": {}, "message-id": {}, "mime-version": {}, "content-type": {},
	"content-transfer-encoding": {}, "dkim-signature": {}, "received": {},
	"return-path": {},
	"resent-from": {}, "resent-sender": {}, "resent-to": {}, "resent-cc": {},
	"resent-bcc": {}, "resent-date": {}, "resent-message-id": {},
}

// validateHeaders enforces RFC 5322 field-name syntax (ftext: printable ASCII
// 33–126 except ':'), rejects protected names, forbids C0 control bytes and DEL
// in values (tab allowed), and bounds each line to 998 octets (name + ": " +
// value). Returns an error on the first violation.
func validateHeaders(headers map[string]string) error {
	for name, value := range headers {
		if name == "" {
			return fmt.Errorf("mail: empty header name")
		}
		for i := 0; i < len(name); i++ {
			if c := name[i]; c < 33 || c > 126 || c == ':' {
				return fmt.Errorf("mail: invalid header name %q (bad byte at %d)", name, i)
			}
		}
		if _, bad := protectedHeaders[strings.ToLower(name)]; bad {
			return fmt.Errorf("mail: header %q is reserved and cannot be set by a caller", name)
		}
		for i := 0; i < len(value); i++ {
			if c := value[i]; (c < 0x20 && c != '\t') || c == 0x7f {
				return fmt.Errorf("mail: header %q value contains a control byte at %d", name, i)
			}
		}
		if len(name)+2+len(value) > 998 {
			return fmt.Errorf("mail: header %q line exceeds the 998-octet limit", name)
		}
	}
	return nil
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

func (m *MailClient) sendSMTP(ctx context.Context, subject string, recipients []string, headers map[string]string, contentType, body, attachmentName string, attachment []byte) error {
	sender, err := mail.ParseAddress(config.Config().SmtpFrom)
	if err != nil {
		return fmt.Errorf("smtp: smtp_from: %w", err)
	}
	to, envelope, err := smtpRecipients(recipients)
	if err != nil {
		return err
	}
	msg, err := buildMessage(sender, to, subject, headers, contentType, body, attachmentName, attachment)
	if err != nil {
		return err
	}
	pass, err := m.Secrets.GetSecret(ctx, "smtp_pass")
	if err != nil {
		return fmt.Errorf("failed to get SMTP password: %w", err)
	}
	host := config.Config().SmtpHost
	return sendSMTPWithStartTLS(ctx, host+":"+strconv.Itoa(config.Config().SmtpPort), host, config.Config().SmtpUser,
		strings.TrimSpace(pass), sender.Address, envelope, msg)
}

func smtpRecipients(recipients []string) (header, envelope []string, err error) {
	recipients = scrubRecipients(recipients)
	if len(recipients) == 0 {
		return nil, nil, fmt.Errorf("smtp: no valid recipients")
	}
	header, envelope = make([]string, len(recipients)), make([]string, len(recipients))
	for i, rcpt := range recipients {
		address, err := mail.ParseAddress(rcpt)
		if err != nil {
			return nil, nil, fmt.Errorf("smtp: invalid recipient %q: %w", rcpt, err)
		}
		header[i], envelope[i] = address.String(), address.Address
	}
	return header, envelope, nil
}

// buildMessage writes an RFC 5322 message: an RFC 2047 subject, Date, a
// Message-ID in the sender's domain, a quoted-printable body and, with an
// attachment, a multipart/mixed body whose filename uses RFC 2231.
func buildMessage(sender *mail.Address, rcpts []string, subject string, headers map[string]string, contentType, body, attachmentName string, attachment []byte) ([]byte, error) {
	_, domain, ok := strings.Cut(sender.Address, "@")
	if !ok || domain == "" {
		return nil, fmt.Errorf("smtp: smtp_from %q has no domain for the Message-ID", sender.Address)
	}
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\n",
		sender, strings.Join(rcpts, ",\r\n "), encodeHeader(scrubMailHeader(subject)), time.Now().Format(time.RFC1123Z), rand.Text(), domain)
	for k, v := range headers {
		fmt.Fprintf(&msg, "%s: %s\r\n", k, v)
	}
	if len(attachment) == 0 {
		fmt.Fprintf(&msg, "Content-Type: %s; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", contentType)
		if err := writeQuotedPrintable(&msg, body); err != nil {
			return nil, err
		}
		return msg.Bytes(), nil
	}
	if attachmentName = scrubMailHeader(attachmentName); attachmentName == "" {
		return nil, fmt.Errorf("smtp: attachment has no name")
	}
	contentDisposition := mime.FormatMediaType("attachment", map[string]string{"filename": attachmentName})
	if contentDisposition == "" {
		return nil, fmt.Errorf("smtp: invalid attachment name")
	}
	parts := multipart.NewWriter(&msg)
	fmt.Fprintf(&msg, "Content-Type: multipart/mixed; boundary=%s\r\n\r\n", parts.Boundary())
	part, err := parts.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {contentType + "; charset=UTF-8"},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, err
	}
	if err := writeQuotedPrintable(part, body); err != nil {
		return nil, err
	}
	part, err = parts.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"application/pdf"},
		"Content-Disposition":       {contentDisposition},
		"Content-Transfer-Encoding": {"base64"},
	})
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(attachment)
	for len(encoded) > 76 {
		io.WriteString(part, encoded[:76]+"\r\n")
		encoded = encoded[76:]
	}
	io.WriteString(part, encoded+"\r\n")
	if err := parts.Close(); err != nil {
		return nil, err
	}
	return msg.Bytes(), nil
}

// encodeHeader RFC 2047-encodes a non-ASCII value, folding between encoded-words.
func encodeHeader(v string) string {
	return strings.ReplaceAll(mime.QEncoding.Encode("utf-8", v), "?= =?", "?=\r\n =?")
}

func writeQuotedPrintable(w io.Writer, body string) error {
	qp := quotedprintable.NewWriter(w)
	if _, err := io.WriteString(qp, body); err != nil {
		return err
	}
	return qp.Close()
}

// sendSMTPWithStartTLS requires STARTTLS before authenticating: smtp.SendMail
// falls back to plaintext and would leak the credentials. Cancelling ctx, or the
// smtp_deadline, aborts the exchange.
func sendSMTPWithStartTLS(ctx context.Context, addr, host, user, pass, from string, recipients []string, msg []byte) (err error) {
	conn, err := (&net.Dialer{Timeout: config.Config().SmtpDialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp: dial %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(config.Config().SmtpDeadline))
	defer context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })()
	defer func() {
		if err != nil && ctx.Err() != nil {
			err = fmt.Errorf("%w: %w", ctx.Err(), err)
		}
	}()
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp: new client %s: %w", addr, err)
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
	if err := c.Auth(smtp.PlainAuth("", user, pass, host)); err != nil {
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
	// DATA acceptance commits delivery; a QUIT failure must not trigger a resend.
	_ = c.Quit()
	return nil
}

// --- API mode ---

// postMailAPI delivers a message to keel's REST API.
//   - Validates that smtp_host is a bare host[:port] (no scheme,
//     no path), then constructs the URL via net/url so an operator
//     copy-paste like `https://mail.example.com/api` doesn't
//     produce `https://https://mail.example.com/api/api/send`.
//     A port is allowed (e.g. `mail.example.com:9443`) for backends
//     that don't run on :443 — e.g. when the mail backend shares a
//     host with another service that owns :443.
//   - Drains the response body on non-2xx so the connection is released to the keep-alive pool.
//   - Routes through common.HTTPClient() — the process-wide client
//     with a 30s timeout — instead of constructing a one-shot.
func (m *MailClient) postMailAPI(ctx context.Context, subject string, body string, recipients []string, htmlMode bool, headers map[string]string) error {
	apiKey, err := m.Secrets.GetSecret(ctx, "smtp_pass")
	if err != nil {
		return fmt.Errorf("failed to get mail API key: %w", err)
	}
	host := strings.TrimSpace(config.Config().SmtpHost)
	if host == "" {
		return fmt.Errorf("smtp_host not configured")
	}
	if strings.Contains(host, "/") {
		return fmt.Errorf("mail api: smtp_host must be a bare host[:port] (no scheme or path), got %q", host)
	}
	endpoint := (&url.URL{Scheme: "https", Host: host, Path: "/api/send"}).String()

	// Optional extra headers (e.g. List-Unsubscribe) are scrubbed and forwarded
	// as a "headers" object; the mail backend places them on the outbound
	// message. Omitted from the payload when empty for backward compatibility.
	var hdrOut map[string]string
	if len(headers) > 0 {
		hdrOut = make(map[string]string, len(headers))
		for k, v := range headers {
			if k = scrubMailHeader(k); k != "" {
				hdrOut[k] = scrubMailHeader(v)
			}
		}
	}
	payloadMap := map[string]any{
		"from":    config.Config().SmtpFrom,
		"to":      recipients,
		"subject": subject,
		"body":    body,
		"html":    htmlMode,
	}
	if hdrOut != nil {
		payloadMap["headers"] = hdrOut
	}
	payload, err := json.Marshal(payloadMap)
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

	// An RFC 7807 mail backend returns errors as 200 OK +
	// `application/problem+json` body — checking only StatusCode would
	// let "Invalid API key" and "Token not authorized to send from X"
	// pass as success. Inspect the content-type before declaring victory.
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/problem+json") {
		var pj struct {
			Code   int    `json:"Code"`
			Title  string `json:"Title"`
			Detail string `json:"Detail"`
		}
		body, _ := io.ReadAll(resp.Body)
		if jerr := json.Unmarshal(body, &pj); jerr == nil && (pj.Code >= 400 || pj.Title != "") {
			detail := pj.Detail
			if detail == "" {
				detail = pj.Title
			}
			return fmt.Errorf("mail API rejected request: %d %s", pj.Code, detail)
		}
		// Couldn't decode the problem document — surface raw status +
		// a snippet so the log isn't empty.
		snippet := string(body)
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return fmt.Errorf("mail API returned problem+json (status %d): %s", resp.StatusCode, snippet)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("mail API returned status %d", resp.StatusCode)
	}
	return nil
}
