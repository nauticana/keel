package document

import (
	"fmt"
	"strings"
)

const maxSubjectKey = 200

// Subject is what a document is about: a member of the partner (UserID), an
// application record (SubjectKey, an opaque identifier of at most 200
// characters), or the partner itself (the zero Subject). Versions, the
// single approved document and the group lock are per partner, subject and type.
type Subject struct {
	UserID     int64
	SubjectKey string
}

func (s Subject) normalized() (Subject, error) {
	s.SubjectKey = strings.TrimSpace(s.SubjectKey)
	if s.UserID < 0 || (s.UserID != 0 && s.SubjectKey != "") || len(s.SubjectKey) > maxSubjectKey {
		return s, fmt.Errorf("%w: a subject is a member or a record key of at most %d characters", ErrInvalidUpload, maxSubjectKey)
	}
	return s, nil
}

// userArg and keyArg are the subject's nullable column values.
func (s Subject) userArg() any { return nullableID(s.UserID) }
func (s Subject) keyArg() any {
	if s.SubjectKey == "" {
		return nil
	}
	return s.SubjectKey
}
