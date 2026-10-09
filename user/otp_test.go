package user

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/nauticana/keel/model"
)

type otpStore struct {
	mu          sync.Mutex
	active      bool
	code        string
	attempts    int
	reads       int
	readsReady  chan struct{}
	releaseRead chan struct{}
	consumeErr  error
	readers     int // concurrent reads to hold before releasing them
}

func (s *otpStore) GenID() int64 { return 0 }

func (s *otpStore) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	switch name {
	case qVerifyOTP:
		s.mu.Lock()
		active := s.active
		code := s.code
		if active && s.readsReady != nil {
			s.reads++
			if s.reads == s.readers {
				close(s.readsReady)
			}
		}
		s.mu.Unlock()
		if active && s.releaseRead != nil {
			<-s.releaseRead
		}
		if active {
			return &model.QueryResult{Rows: [][]any{{int64(1), code, int32(0)}}}, nil
		}
		return &model.QueryResult{}, nil
	case qUserPolicies:
		return &model.QueryResult{}, nil
	case qClaimOTPAttempt:
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.active || s.attempts >= args[1].(int) {
			return &model.QueryResult{}, nil
		}
		s.attempts++
		return &model.QueryResult{Rows: [][]any{{int64(1)}}}, nil
	case qConsumeOTPByID:
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.consumeErr != nil {
			return nil, s.consumeErr
		}
		if s.active && args[1] == s.code {
			s.active = false
			return &model.QueryResult{Rows: [][]any{{int64(1)}}}, nil
		}
		return &model.QueryResult{}, nil
	default:
		return &model.QueryResult{}, nil
	}
}

func TestVerifyOTPConsumesCodeOnceUnderConcurrency(t *testing.T) {
	store := &otpStore{
		active:      true,
		code:        "654321",
		readsReady:  make(chan struct{}),
		releaseRead: make(chan struct{}),
		readers:     2,
	}
	svc := &LocalUserService{queryService: store}
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- svc.VerifyOTP(7, OTPPurposeReauth, "654321") }()
	}
	<-store.readsReady
	close(store.releaseRead)

	succeeded := 0
	for range 2 {
		if err := <-results; err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful concurrent verifications = %d, want 1", succeeded)
	}
}

func TestVerifyOTPFailsWhenConsumptionFails(t *testing.T) {
	store := &otpStore{active: true, code: "654321", consumeErr: errors.New("database down")}
	svc := &LocalUserService{queryService: store}
	if err := svc.VerifyOTP(7, OTPPurposeReauth, "654321"); err == nil {
		t.Fatal("verification succeeded without consuming the code")
	}
}

func TestVerifyOTPCapsConcurrentGuesses(t *testing.T) {
	const guesses = 12
	store := &otpStore{
		active:      true,
		code:        "654321",
		readsReady:  make(chan struct{}),
		releaseRead: make(chan struct{}),
		readers:     guesses,
	}
	svc := &LocalUserService{queryService: store}
	done := make(chan error, guesses)
	for range guesses {
		go func() { done <- svc.VerifyOTP(7, OTPPurposeReauth, "000000") }()
	}
	<-store.readsReady
	close(store.releaseRead)
	for range guesses {
		<-done
	}
	if store.attempts != 5 {
		t.Fatalf("attempts compared = %d, want the cap of 5", store.attempts)
	}
	store.readsReady, store.releaseRead = nil, nil
	if err := svc.VerifyOTP(7, OTPPurposeReauth, "654321"); err == nil {
		t.Fatal("the right code was accepted after the cap was spent")
	}
}
