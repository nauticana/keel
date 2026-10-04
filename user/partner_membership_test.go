package user

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Every session builder must pick the same current partner, or a multi-partner
// user switches partners between login and refresh.
func TestSessionQueriesUseCurrentPartnerJoin(t *testing.T) {
	for _, name := range []string{qPartnerUserByid, qPartnerUserByEmail, qGetRefreshToken, qUserByPhone, qUserBySocial} {
		sql := LocalUserQueries[name]
		if !strings.Contains(sql, sessionPartnerJoin) {
			t.Errorf("%s does not use sessionPartnerJoin", name)
		}
		if strings.Contains(sql, "JOIN partner_user p ON") || strings.Contains(sql, ", partner_user p") {
			t.Errorf("%s joins partner_user directly: %s", name, sql)
		}
	}
	for _, want := range []string{"pu.endda IS NULL OR pu.endda > CURRENT_TIMESTAMP", "pu.begda <= CURRENT_TIMESTAMP", "ORDER BY pu.begda, pu.partner_id", "LIMIT 1"} {
		if !strings.Contains(sessionPartnerJoin, want) {
			t.Errorf("sessionPartnerJoin lacks %q", want)
		}
	}
	if !strings.Contains(LocalUserQueries[qListPartners], "ORDER BY begda, partner_id") {
		t.Error("ListPartners must order like sessionPartnerJoin")
	}
}

func TestListPartners(t *testing.T) {
	store := newMemStore(7)
	began := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	ends := began.AddDate(1, 0, 0)
	store.partners = map[int][][]any{7: {{int64(11), began, nil}, {int64(12), began, ends}}}
	got, err := newLocalUserService(t, store).ListPartners(7)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].PartnerID != 11 || got[0].Endda != nil || got[1].PartnerID != 12 || !got[1].Endda.Equal(ends) || !got[1].Begda.Equal(began) {
		t.Fatalf("ListPartners = %+v", got)
	}

	if none, err := newLocalUserService(t, store).ListPartners(8); err != nil || len(none) != 0 {
		t.Fatalf("no memberships: %v, %v", none, err)
	}

	store.failQuery[qListPartners] = errDatabaseDown
	if _, err := newLocalUserService(t, store).ListPartners(7); !errors.Is(err, errDatabaseDown) {
		t.Fatalf("err = %v, want database error", err)
	}
}
