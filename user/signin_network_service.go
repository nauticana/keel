package user

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/port"
)

// ErrSignInNetworkLockout refuses networks that would shut out the caller.
var ErrSignInNetworkLockout = errors.New("user: the sign-in networks must include your current address")

const (
	qClearSignInNetworks = "clear_signin_networks"
	qAddSignInNetwork    = "add_signin_network"
)

var signInNetworkQueries = map[string]string{
	qClearSignInNetworks: `DELETE FROM partner_signin_network WHERE partner_id = ?`,
	qAddSignInNetwork:    `INSERT INTO partner_signin_network (partner_id, cidr) VALUES (?, ?)`,
}

// SignInNetworkService keeps the networks a partner's users may sign in from;
// LocalUserService enforces them at sign-in and refresh.
type SignInNetworkService struct {
	DB port.DatabaseRepository
}

// Replace sets the partner's sign-in networks to cidrs, a CSV of CIDRs or
// addresses; empty allows any address. callerIP, the trusted address of the
// administrator, must stay admitted.
func (s *SignInNetworkService) Replace(ctx context.Context, partnerID int64, cidrs, callerIP string) (err error) {
	if partnerID <= 0 {
		return fmt.Errorf("user: sign-in networks need a partner")
	}
	nets, err := common.ParseCIDRList(cidrs)
	if err != nil {
		return err
	}
	if len(nets) > 0 && !common.CIDRListAllows(nets, callerIP) {
		return ErrSignInNetworkLockout
	}
	tx, err := s.DB.BeginTx(ctx, signInNetworkQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			err = errors.Join(err, data.RollbackDetached(tx))
		}
	}()
	if _, err := tx.Query(ctx, qClearSignInNetworks, partnerID); err != nil {
		return err
	}
	var stored []string
	for _, n := range nets {
		cidr := n.String()
		if slices.Contains(stored, cidr) {
			continue
		}
		stored = append(stored, cidr)
		if _, err := tx.Query(ctx, qAddSignInNetwork, partnerID, cidr); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}
