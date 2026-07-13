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
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/secret"
)

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
	switch common.Config().MailMode {
	case "api":
		return m.sendViaAPI(ctx, subject, body, recipients, headers)
	default:
		return m.sendViaSMTP(ctx, subject, body, recipients, headers)
	}
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

func (m *MailClient) SendEmailHTML(ctx context.Context, subject string, htmlBody string, recipients []string, attachmentName string, attachmentData []byte) error {
	switch common.Config().MailMode {
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

func (m *MailClient) sendViaSMTP(ctx context.Context, subject string, body string, recipients []string, headers map[string]string) error {
	if len(recipients) == 0 {
		return fmt.Errorf("smtp: no recipients")
	}
	smtpPass, err := m.Secrets.GetSecret(ctx, "smtp_pass")
	if err != nil {
		return fmt.Errorf("failed to get SMTP password: %w", err)
	}
	from := scrubMailHeader(common.Config().SmtpFrom)
	host := common.Config().SmtpHost
	port := common.Config().SmtpPort
	addr := host + ":" + strconv.Itoa(port)

	cleanRcpts := scrubRecipients(recipients)
	if len(cleanRcpts) == 0 {
		return fmt.Errorf("smtp: no valid recipients")
	}
	cleanSubject := scrubMailHeader(subject)
	// Header names + values are scrubbed; the body is left intact (CRLF inside
	// the body is part of the RFC 5322 wire format and must NOT be
	// stripped) but separated from the headers by an explicit blank
	// line. SMTP envelope recipients use cleanRcpts so spoofed RCPT TO
	// values are rejected before the server accepts the message.
	var hdr strings.Builder
	fmt.Fprintf(&hdr, "From: %s\r\nTo: %s\r\nSubject: %s\r\n", from, strings.Join(cleanRcpts, ", "), cleanSubject)
	for k, v := range headers {
		if k = scrubMailHeader(k); k != "" {
			fmt.Fprintf(&hdr, "%s: %s\r\n", k, scrubMailHeader(v))
		}
	}
	msg := hdr.String() + "\r\n" + body
	pass := strings.TrimSpace(smtpPass)
	return sendSMTPWithStartTLS(addr, host, common.Config().SmtpUser, pass, from, cleanRcpts, []byte(msg))
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
	// Bounded dial + overall deadline so a peer that accepts the TCP connection
	// but stalls on the greeting/STARTTLS/DATA can't block the worker tick
	// indefinitely (a synchronous dispatch would otherwise wedge the loop).
	conn, err := net.DialTimeout("tcp", addr, common.Config().SmtpDialTimeout)
	if err != nil {
		return fmt.Errorf("smtp: dial %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(common.Config().SmtpDeadline))
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
	from := scrubMailHeader(common.Config().SmtpFrom)
	host := common.Config().SmtpHost
	port := common.Config().SmtpPort
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
	return sendSMTPWithStartTLS(addr, host, common.Config().SmtpUser, pass, from, cleanRcpts, msg)
}

// --- API mode ---

func (m *MailClient) sendViaAPI(ctx context.Context, subject string, body string, recipients []string, headers map[string]string) error {
	return m.postMailAPI(ctx, subject, body, recipients, false, headers)
}

func (m *MailClient) sendHTMLViaAPI(ctx context.Context, subject string, htmlBody string, recipients []string) error {
	return m.postMailAPI(ctx, subject, htmlBody, recipients, true, nil)
}

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
	host := strings.TrimSpace(common.Config().SmtpHost)
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
	payloadMap := map[string]interface{}{
		"from":    common.Config().SmtpFrom,
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
