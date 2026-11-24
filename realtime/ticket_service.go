package realtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/common"
)

var ErrTicket = errors.New("realtime: connection ticket is invalid, used or expired")

var errTicketInput = errors.New("realtime: a cache, a user and a positive ticket ttl are required")

const (
	ticketPrefix = "ws_ticket:"
	ticketUsed   = "used"
)

// TicketService mints single-use tickets that authenticate one WebSocket
// handshake. Cache must be shared when several processes serve sockets; only
// ticket hashes are stored, and a lost entry only costs the client a new ticket.
type TicketService struct {
	Cache cache.CacheService
}

func (s *TicketService) Mint(ctx context.Context, userID int, ttl time.Duration) (string, error) {
	if s.Cache == nil || userID <= 0 || ttl <= 0 {
		return "", errTicketInput
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	ticket := hex.EncodeToString(raw[:])
	return ticket, s.Cache.Set(ctx, ticketPrefix+common.Sha256Hex(ticket), strconv.Itoa(userID), ttl)
}

// Redeem consumes ticket and returns its user, or ErrTicket. The used mark
// outlives the ticket by ttl, so a concurrent redemption cannot win twice.
func (s *TicketService) Redeem(ctx context.Context, ticket string, ttl time.Duration) (int, error) {
	if s.Cache == nil || ttl <= 0 {
		return 0, errTicketInput
	}
	if len(ticket) != 64 {
		return 0, ErrTicket
	}
	key := ticketPrefix + common.Sha256Hex(ticket)
	value, err := s.Cache.Get(ctx, key)
	if errors.Is(err, cache.ErrCacheMiss) {
		return 0, ErrTicket
	}
	if err != nil {
		return 0, err
	}
	userID, err := strconv.Atoi(value)
	if err != nil || userID <= 0 {
		return 0, ErrTicket
	}
	won, err := s.Cache.CompareAndSet(ctx, key, value, ticketUsed, ttl)
	if err != nil {
		return 0, err
	}
	if !won {
		return 0, ErrTicket
	}
	return userID, nil
}
