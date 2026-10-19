package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

// otpUsers is the slice of user.UserService the OTP register path touches.
type otpUsers struct {
	user.UserService
	byEmail   map[string]*model.UserSession
	created   []string
	verified  []int
	lookupErr error
	createErr error
}

func (u *otpUsers) GetUserByEmail(email string) (*model.UserSession, error) {
	if u.lookupErr != nil {
		return nil, u.lookupErr
	}
	if s, ok := u.byEmail[email]; ok {
		return s, nil
	}
	return nil, user.ErrNoAccount
}
func (u *otpUsers) GetOrCreateUserByEmail(email, _ string, _ *user.SignupConsent) (*model.UserSession, bool, error) {
	if s, ok := u.byEmail[email]; ok {
		return s, false, nil
	}
	if u.createErr != nil {
		return nil, false, u.createErr
	}
	s := &model.UserSession{Id: 7, PartnerId: 1, Email: email}
	u.byEmail[email] = s
	u.created = append(u.created, email)
	return s, true, nil
}
func (u *otpUsers) GetUserById(id int) (*model.UserSession, error) {
	for _, s := range u.byEmail {
		if s.Id == id {
			return s, nil
		}
	}
	return nil, errors.New("not found")
}
func (u *otpUsers) NormalizePhone(in, _ string) (string, error) { return in, nil }
func (u *otpUsers) MarkEmailVerified(id int, _ string) error {
	u.verified = append(u.verified, id)
	return nil
}
func (u *otpUsers) CheckSignInMethod(int, string) error          { return nil }
func (u *otpUsers) CreateJWT(*model.UserSession) (string, error) { return "jwt", nil }
func (u *otpUsers) CreateRefreshToken(*model.UserSession, user.SessionDevice) (string, error) {
	return "refresh", nil
}
func (u *otpUsers) GetUserMenu(int) ([]model.UserMenu, error) { return nil, nil }

type sentOTPs struct{ sent []port.NotificationRequest }

func (n *sentOTPs) Send(_ context.Context, req port.NotificationRequest) error {
	n.sent = append(n.sent, req)
	return nil
}

type humanStub struct{ err error }

func (h humanStub) Verify(_ context.Context, token, _ string) error {
	if token == "" {
		return port.ErrChallengeRequired
	}
	return h.err
}

func newOTPHandler(t *testing.T, human port.HumanVerifier) (*OTPHandler, *otpUsers, *sentOTPs) {
	t.Helper()
	c := config.Config()
	ttl, perContact := c.OTPTTLSeconds, c.OTPSendPerContact
	c.OTPTTLSeconds, c.OTPSendPerContact = 300, 3
	t.Cleanup(func() { c.OTPTTLSeconds, c.OTPSendPerContact = ttl, perContact })
	mem := cache.NewMemoryCacheService()
	t.Cleanup(func() { mem.Close() })
	users := &otpUsers{byEmail: map[string]*model.UserSession{}}
	sent := &sentOTPs{}
	return &OTPHandler{AbstractHandler: AbstractHandler{UserService: users}, NotificationSvc: sent, Cache: mem, Human: human}, users, sent
}

func postOTP(h http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return w
}

func dataField(t *testing.T, w *httptest.ResponseRecorder, key string) any {
	t.Helper()
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
	return resp.Data[key]
}

var otpCodeRE = regexp.MustCompile(`\b[1-9][0-9]{5}\b`)

func sendRegister(t *testing.T, h *OTPHandler, email, challenge string) (token string, w *httptest.ResponseRecorder) {
	t.Helper()
	w = postOTP(h.SendOTP, "/public/otp/send", `{"contact":"`+email+`","contactType":"email","purpose":"register","challengeToken":"`+challenge+`","consents":{"privacy_policy":true}}`)
	if w.Code == http.StatusOK {
		token, _ = dataField(t, w, "otpToken").(string)
	}
	return token, w
}

func TestSendOTPRegisterRefusesWithoutHumanProof(t *testing.T) {
	h, users, sent := newOTPHandler(t, humanStub{})
	if _, w := sendRegister(t, h, "ada@acme.example", ""); w.Code != http.StatusForbidden {
		t.Fatalf("no token = %d %s", w.Code, w.Body.String())
	}
	h.Human = humanStub{err: port.ErrChallengeFailed}
	if _, w := sendRegister(t, h, "ada@acme.example", "bot"); w.Code != http.StatusForbidden {
		t.Fatalf("failed challenge = %d %s", w.Code, w.Body.String())
	}
	h.Human = humanStub{err: port.ErrChallengeUnavailable}
	if _, w := sendRegister(t, h, "ada@acme.example", "tok"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("provider down = %d %s", w.Code, w.Body.String())
	}
	if len(sent.sent) != 0 || len(users.created) != 0 {
		t.Fatalf("sent %d, created %v", len(sent.sent), users.created)
	}
}

func TestSendOTPLoginNeedsNoHumanProof(t *testing.T) {
	h, _, sent := newOTPHandler(t, humanStub{err: port.ErrChallengeFailed})
	w := postOTP(h.SendOTP, "/public/otp/send", `{"contact":"nobody@acme.example","contactType":"email","purpose":"login"}`)
	if w.Code != http.StatusOK || len(sent.sent) != 0 {
		t.Fatalf("login = %d %s, sent %d", w.Code, w.Body.String(), len(sent.sent))
	}
}

func TestOTPRegisterCreatesAccountOnlyWhenCodeIsProven(t *testing.T) {
	h, users, sent := newOTPHandler(t, humanStub{})
	token, w := sendRegister(t, h, "ada@acme.example", "tok")
	if w.Code != http.StatusOK || token == "" {
		t.Fatalf("send = %d %s", w.Code, w.Body.String())
	}
	if len(users.created) != 0 {
		t.Fatalf("account created before verification: %v", users.created)
	}
	if len(sent.sent) != 1 || sent.sent[0].To != "ada@acme.example" || sent.sent[0].UserID != 0 {
		t.Fatalf("dispatch = %+v", sent.sent)
	}
	code := otpCodeRE.FindString(sent.sent[0].Body)

	if w := postOTP(h.VerifyOTP, "/public/otp/verify", `{"otpToken":"`+token+`","code":"000000"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code = %d", w.Code)
	}
	w = postOTP(h.VerifyOTP, "/public/otp/verify", `{"otpToken":"`+token+`","code":"`+code+`"}`)
	if w.Code != http.StatusOK || dataField(t, w, "token") != "jwt" || dataField(t, w, "isNewUser") != true {
		t.Fatalf("verify = %d %s", w.Code, w.Body.String())
	}
	if len(users.created) != 1 || users.created[0] != "ada@acme.example" || len(users.verified) != 1 || users.verified[0] != 7 {
		t.Fatalf("created %v verified %v", users.created, users.verified)
	}
	if w := postOTP(h.VerifyOTP, "/public/otp/verify", `{"otpToken":"`+token+`","code":"`+code+`"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("replay = %d", w.Code)
	}
}

func TestOTPRegisterGuessCapDropsThePendingSignup(t *testing.T) {
	h, users, sent := newOTPHandler(t, humanStub{})
	token, _ := sendRegister(t, h, "ada@acme.example", "tok")
	code := otpCodeRE.FindString(sent.sent[0].Body)
	for i := 0; i < 5; i++ {
		postOTP(h.VerifyOTP, "/public/otp/verify", `{"otpToken":"`+token+`","code":"000000"}`)
	}
	if w := postOTP(h.VerifyOTP, "/public/otp/verify", `{"otpToken":"`+token+`","code":"`+code+`"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("after cap = %d", w.Code)
	}
	if len(users.created) != 0 {
		t.Fatalf("created %v", users.created)
	}
}

func TestResendOTPPendingSignupIsCapped(t *testing.T) {
	h, _, sent := newOTPHandler(t, humanStub{})
	token, _ := sendRegister(t, h, "ada@acme.example", "tok")
	first := otpCodeRE.FindString(sent.sent[0].Body)
	for i := 0; i < 2; i++ {
		if w := postOTP(h.ResendOTP, "/public/otp/resend", `{"otpToken":"`+token+`"}`); w.Code != http.StatusOK {
			t.Fatalf("resend %d = %d %s", i, w.Code, w.Body.String())
		}
	}
	if w := postOTP(h.ResendOTP, "/public/otp/resend", `{"otpToken":"`+token+`"}`); w.Code != http.StatusTooManyRequests {
		t.Fatalf("fourth send = %d", w.Code)
	}
	if len(sent.sent) != 3 || sent.sent[2].To != "ada@acme.example" {
		t.Fatalf("sent = %+v", sent.sent)
	}
	latest := otpCodeRE.FindString(sent.sent[2].Body)
	if w := postOTP(h.VerifyOTP, "/public/otp/verify", `{"otpToken":"`+token+`","code":"`+first+`"}`); w.Code != http.StatusUnauthorized && first != latest {
		t.Fatalf("stale code = %d", w.Code)
	}
	if w := postOTP(h.VerifyOTP, "/public/otp/verify", `{"otpToken":"`+token+`","code":"`+latest+`"}`); w.Code != http.StatusOK {
		t.Fatalf("latest code = %d %s", w.Code, w.Body.String())
	}
}

func TestSendOTPLookupFailureIsNotASignup(t *testing.T) {
	h, _, sent := newOTPHandler(t, humanStub{})
	h.UserService.(*otpUsers).lookupErr = errors.New("pq: connection refused")
	if _, w := sendRegister(t, h, "ada@acme.example", "tok"); w.Code != http.StatusInternalServerError {
		t.Fatalf("register = %d %s", w.Code, w.Body.String())
	}
	w := postOTP(h.SendOTP, "/public/otp/send", `{"contact":"ada@acme.example","contactType":"email","purpose":"login"}`)
	if w.Code != http.StatusInternalServerError || len(sent.sent) != 0 {
		t.Fatalf("login = %d %s, sent %d", w.Code, w.Body.String(), len(sent.sent))
	}
}

func TestOTPRegisterKeepsThePendingSignupWhenCreationFails(t *testing.T) {
	h, users, sent := newOTPHandler(t, humanStub{})
	token, _ := sendRegister(t, h, "ada@acme.example", "tok")
	code := otpCodeRE.FindString(sent.sent[0].Body)
	users.createErr = errors.New("pq: connection refused")
	if w := postOTP(h.VerifyOTP, "/public/otp/verify", `{"otpToken":"`+token+`","code":"`+code+`"}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("failed creation = %d %s", w.Code, w.Body.String())
	}
	users.createErr = nil
	if w := postOTP(h.VerifyOTP, "/public/otp/verify", `{"otpToken":"`+token+`","code":"`+code+`"}`); w.Code != http.StatusOK {
		t.Fatalf("retry = %d %s", w.Code, w.Body.String())
	}
	if len(users.created) != 1 {
		t.Fatalf("created %v", users.created)
	}
}

func TestSendOTPRegisterKnownContactSignsIn(t *testing.T) {
	h, users, sent := newOTPHandler(t, humanStub{})
	users.byEmail["ada@acme.example"] = &model.UserSession{Id: 3, Email: "ada@acme.example"}
	generated := false
	users.UserService = otpGenerator{onGenerate: func() { generated = true }}
	token, w := sendRegister(t, h, "ada@acme.example", "tok")
	if w.Code != http.StatusOK || token == "" || !generated {
		t.Fatalf("send = %d %s generated=%v", w.Code, w.Body.String(), generated)
	}
	if len(users.created) != 0 || len(sent.sent) != 1 || sent.sent[0].UserID != 3 || sent.sent[0].To != "" {
		t.Fatalf("created %v sent %+v", users.created, sent.sent)
	}
}

// otpGenerator stands in for the persisted user_otp row of an existing account.
type otpGenerator struct {
	user.UserService
	onGenerate func()
}

func (g otpGenerator) GenerateOTP(int, string) (string, error) {
	g.onGenerate()
	return "123456", nil
}
