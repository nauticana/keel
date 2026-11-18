package service

// IssuedAPIKey is a minted key; Key is its only plaintext copy.
type IssuedAPIKey struct {
	ID     int64  `json:"id"`
	Key    string `json:"api_key"`
	Prefix string `json:"key_prefix"`
}
