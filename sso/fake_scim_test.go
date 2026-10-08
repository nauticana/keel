package sso

import (
	"time"

	"github.com/nauticana/keel/model"
)

// scimStore models the provisioning tables.
type scimStore struct {
	tokens  map[string][2]int64 // hash -> id, partner
	revoked map[int64]bool
	users   map[int]*scimRow
	groups  map[int64]*groupRow
	members map[int64]map[int]bool
	nextID  int64
}

type scimRow struct {
	partner    int64
	userName   string
	externalID string
	active     bool
}

type groupRow struct {
	partner      int64
	name, extern string
}

func newSCIMStore() *scimStore {
	return &scimStore{tokens: map[string][2]int64{}, revoked: map[int64]bool{}, users: map[int]*scimRow{},
		groups: map[int64]*groupRow{}, members: map[int64]map[int]bool{}, nextID: 500}
}

func asInt(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	}
	return 0
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (s *scimStore) query(name string, args []any) (*model.QueryResult, bool) {
	r := func(out ...[]any) (*model.QueryResult, bool) { return &model.QueryResult{Rows: out}, true }
	now := time.Now()
	switch name {
	case qActiveSCIMUsers:
		var out [][]any
		for id, u := range s.users {
			if u.partner == args[0].(int64) && u.active {
				out = append(out, []any{int64(id)})
			}
		}
		return r(out...)
	case qLockSCIMTokens:
		return r([]any{args[0]})
	case qActiveTokens:
		n := 0
		for _, t := range s.tokens {
			if t[1] == args[0].(int64) && !s.revoked[t[0]] {
				n++
			}
		}
		return r([]any{int64(n)})
	case qInsertToken:
		s.nextID++
		s.tokens[args[2].(string)] = [2]int64{s.nextID, args[0].(int64)}
		return r([]any{s.nextID})
	case qTokenByHash:
		if t, ok := s.tokens[args[0].(string)]; ok && !s.revoked[t[0]] {
			return r([]any{t[0], t[1]})
		}
		return r()
	case qTouchToken:
		return r()
	case qRevokeToken:
		for _, t := range s.tokens {
			if t[0] == args[1].(int64) && t[1] == args[0].(int64) && !s.revoked[t[0]] {
				s.revoked[t[0]] = true
				return r([]any{t[0]})
			}
		}
		return r()
	case qSCIMUser:
		if u := s.users[asInt(args[1])]; u != nil && u.partner == args[0].(int64) {
			return r(s.userRow(asInt(args[1]), u))
		}
		return r()
	case qSCIMUsers, qSCIMUserCount:
		var out [][]any
		for id, u := range s.users {
			if u.partner == args[0].(int64) && (str(args[1]) == "" || u.userName == args[1]) && (str(args[3]) == "" || u.externalID == args[3]) {
				out = append(out, s.userRow(id, u))
			}
		}
		if name == qSCIMUserCount {
			return r([]any{int64(len(out))})
		}
		return r(out...)
	case qSCIMUserGroups:
		var out [][]any
		for gid, m := range s.members {
			if m[asInt(args[1])] && s.groups[gid] != nil {
				out = append(out, []any{gid, s.groups[gid].name, s.groups[gid].extern})
			}
		}
		return r(out...)
	case qSCIMUserConflict:
		for id, u := range s.users {
			if u.partner == args[0].(int64) && id != asInt(args[1]) && (u.userName == args[2] || (str(args[3]) != "" && u.externalID == args[3])) {
				return r([]any{id})
			}
		}
		return r()
	case qInsertSCIMUser:
		s.users[asInt(args[1])] = &scimRow{partner: args[0].(int64), userName: args[2].(string), externalID: str(args[3]), active: args[4].(bool)}
		return r()
	case qUpdateSCIMUser:
		u := s.users[asInt(args[4])]
		u.userName, u.externalID, u.active = args[0].(string), str(args[1]), args[2].(bool)
		return r()
	case qDeleteSCIMUser:
		delete(s.users, asInt(args[1]))
		for _, m := range s.members {
			delete(m, asInt(args[1]))
		}
		return r()
	case qSCIMGroup:
		if g := s.groups[args[1].(int64)]; g != nil && g.partner == args[0].(int64) {
			return r([]any{args[1].(int64), g.extern, g.name, now, now})
		}
		return r()
	case qSCIMGroups, qSCIMGroupCount:
		var out [][]any
		for id, g := range s.groups {
			if g.partner == args[0].(int64) && (str(args[1]) == "" || g.name == args[1]) && (str(args[3]) == "" || g.extern == args[3]) {
				out = append(out, []any{id, g.extern, g.name, now, now})
			}
		}
		if name == qSCIMGroupCount {
			return r([]any{int64(len(out))})
		}
		return r(out...)
	case qSCIMGroupMembers:
		var out [][]any
		for uid := range s.members[args[1].(int64)] {
			out = append(out, []any{int64(uid), s.users[uid].userName})
		}
		return r(out...)
	case qSCIMGroupMemberCount:
		return r([]any{int64(len(s.members[args[1].(int64)]))})
	case qSCIMGroupConflict:
		for id, g := range s.groups {
			if g.partner == args[0].(int64) && id != args[1].(int64) && (g.name == args[2] || (str(args[3]) != "" && g.extern == args[3])) {
				return r([]any{id})
			}
		}
		return r()
	case qInsertSCIMGroup:
		s.nextID++
		s.groups[s.nextID] = &groupRow{partner: args[0].(int64), name: args[1].(string), extern: str(args[2])}
		s.members[s.nextID] = map[int]bool{}
		return r([]any{s.nextID})
	case qUpdateSCIMGroup:
		g := s.groups[args[3].(int64)]
		g.name, g.extern = args[0].(string), str(args[1])
		return r()
	case qDeleteSCIMGroup:
		delete(s.groups, args[1].(int64))
		delete(s.members, args[1].(int64))
		return r()
	case qAddGroupMember:
		s.members[args[1].(int64)][asInt(args[2])] = true
		return r()
	case qRemoveGroupMember:
		delete(s.members[args[1].(int64)], asInt(args[2]))
		return r()
	case qRemoveAllMembers:
		var out [][]any
		for uid := range s.members[args[1].(int64)] {
			out = append(out, []any{int64(uid)})
		}
		s.members[args[1].(int64)] = map[int]bool{}
		return r(out...)
	}
	return nil, false
}

func (s *scimStore) userRow(id int, u *scimRow) []any {
	return []any{int64(id), u.externalID, u.userName, u.active, time.Now(), time.Now(), "Ada", "Lovelace", u.userName}
}
