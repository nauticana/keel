package user

import "strings"

// MaxMemberSearch bounds the name search of Members, in characters.
const MaxMemberSearch = 100

var memberLikeEscaper = strings.NewReplacer("!", "!!", "%", "!%", "_", "!_")

// Member is a current member of a partner as a colleague picker shows it.
type Member struct {
	UserID int64  `json:"userId"`
	Name   string `json:"name"`
}
