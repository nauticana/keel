package dispatcher

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/config"
)

func parseMessage(t *testing.T, raw []byte) *mail.Message {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("message does not parse: %v\n%s", err, raw)
	}
	return msg
}

func TestBuildMessagePlain(t *testing.T) {
	sender := &mail.Address{Name: "Kéel", Address: "no-reply@mail.example.com"}
	raw, err := buildMessage(sender, []string{"a@x.test", "b@x.test"}, "Grüße\r\nBcc: evil@x.test", map[string]string{"List-Unsubscribe": "<https://x.test/u>"},
		"text/plain", "Größe: "+strings.Repeat("x", 100)+"\n", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := parseMessage(t, raw)
	h := msg.Header
	if subject, err := new(mime.WordDecoder).DecodeHeader(h.Get("Subject")); err != nil || subject != "GrüßeBcc: evil@x.test" || h.Get("Bcc") != "" {
		t.Errorf("subject = %q %v, raw %q", subject, err, h.Get("Subject"))
	}
	if from, err := h.AddressList("From"); err != nil || from[0].Name != "Kéel" {
		t.Errorf("from = %v %v", from, err)
	}
	if to, err := h.AddressList("To"); err != nil || len(to) != 2 || to[1].Address != "b@x.test" {
		t.Errorf("folded To = %v %v", to, err)
	}
	if _, err := h.Date(); err != nil {
		t.Errorf("Date: %v", err)
	}
	if id := h.Get("Message-Id"); !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@mail.example.com>") {
		t.Errorf("Message-ID = %q", id)
	}
	if h.Get("Content-Transfer-Encoding") != "quoted-printable" || h.Get("List-Unsubscribe") != "<https://x.test/u>" {
		t.Errorf("headers = %v", h)
	}
	body, _ := io.ReadAll(msg.Body)
	for _, line := range strings.Split(string(body), "\r\n") {
		if len(line) > 76 {
			t.Errorf("body line of %d octets", len(line))
		}
	}
	if !strings.Contains(string(body), "Gr=C3=B6=C3=9Fe") {
		t.Errorf("body is not quoted-printable: %q", body)
	}
}

func TestBuildMessageAttachment(t *testing.T) {
	sender := &mail.Address{Address: "no-reply@mail.example.com"}
	raw, err := buildMessage(sender, []string{"a@x.test"}, "Invoice", nil, "text/html", "<p>hi</p>", "Fatura Ağustos.pdf", []byte("%PDF-1.7"))
	if err != nil {
		t.Fatal(err)
	}
	msg := parseMessage(t, raw)
	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	reader := multipart.NewReader(msg.Body, params["boundary"])
	if _, err := reader.NextPart(); err != nil {
		t.Fatal(err)
	}
	att, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if att.FileName() != "Fatura Ağustos.pdf" || !strings.Contains(att.Header.Get("Content-Disposition"), "filename*=utf-8''") {
		t.Errorf("attachment = %q, disposition %q", att.FileName(), att.Header.Get("Content-Disposition"))
	}
	if _, err := reader.NextPart(); err != io.EOF {
		t.Errorf("the multipart body is not closed: %v", err)
	}
	if _, err := buildMessage(sender, []string{"a@x.test"}, "x", nil, "text/html", "", "", []byte("x")); err == nil {
		t.Error("an attachment without a name must be refused")
	}
	if _, err := buildMessage(&mail.Address{Address: "nodomain"}, []string{"a@x.test"}, "x", nil, "text/plain", "", "", nil); err == nil {
		t.Error("a sender without a domain must be refused")
	}
}

func TestSMTPRecipientsSeparateHeaderAndEnvelope(t *testing.T) {
	header, envelope, err := smtpRecipients([]string{"Jane Doe <jane@example.com>"})
	if err != nil {
		t.Fatal(err)
	}
	if header[0] != `"Jane Doe" <jane@example.com>` || envelope[0] != "jane@example.com" {
		t.Errorf("header %q, envelope %q", header, envelope)
	}
	if _, _, err := smtpRecipients([]string{"jane@example.com, bob@example.com"}); err == nil {
		t.Error("a recipient that is not one address must be refused")
	}
}

func TestSendEmailHTMLRefusesAttachmentInAPIMode(t *testing.T) {
	saved := config.Config().MailMode
	t.Cleanup(func() { config.Config().MailMode = saved })
	config.Config().MailMode = "api"
	err := (&MailClient{}).SendEmailHTML(context.Background(), "s", "<p>b</p>", []string{"a@x.test"}, "a.pdf", []byte("x"))
	if !errors.Is(err, ErrMailAttachmentUnsupported) {
		t.Errorf("err = %v", err)
	}
}

func TestSMTPExchangeStopsOnCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if conn, err := ln.Accept(); err == nil {
			defer conn.Close()
			time.Sleep(10 * time.Second) // never greets
		}
	}()
	savedDial, savedDeadline := config.Config().SmtpDialTimeout, config.Config().SmtpDeadline
	t.Cleanup(func() { config.Config().SmtpDialTimeout, config.Config().SmtpDeadline = savedDial, savedDeadline })
	config.Config().SmtpDialTimeout, config.Config().SmtpDeadline = time.Second, time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = sendSMTPWithStartTLS(ctx, ln.Addr().String(), "localhost", "u", "p", "f@x.test", []string{"a@x.test"}, nil)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Errorf("err = %v after %v", err, time.Since(start))
	}
}
