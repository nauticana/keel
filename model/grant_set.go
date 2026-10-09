package model

// GrantSet holds a principal's active action grants. The zero value allows
// nothing.
type GrantSet struct {
	limits map[[2]string]map[string]bool
}

// Add records one grant row. Multiple roles granting the same limit preserve
// bypassScope when any matching row sets it.
func (s *GrantSet) Add(object, action, lowLimit string, bypassScope bool) {
	if s.limits == nil {
		s.limits = make(map[[2]string]map[string]bool)
	}
	key := [2]string{object, action}
	if s.limits[key] == nil {
		s.limits[key] = make(map[string]bool)
	}
	s.limits[key][lowLimit] = s.limits[key][lowLimit] || bypassScope
}

// Allows returns (allowed, ownScope) for object, action and scope: a grant for
// exactly scope is owner-wide (ownScope=false), a '*' grant is row-scoped
// unless it bypasses scope, and no other low_limit matches.
func (s GrantSet) Allows(object, action, scope string) (bool, bool) {
	if object == "" || action == "" {
		return false, false
	}
	limits := s.limits[[2]string{object, action}]
	if _, ok := limits[scope]; ok {
		return true, false
	}
	if bypass, ok := limits["*"]; ok {
		return true, !bypass
	}
	return false, false
}
