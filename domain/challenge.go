package domain

import "time"

// Challenge is an issued challenge. Token is the secret to publish (DNS, HTTP)
// or deliver (email code); keel stores only its hash. For an email code, the
// caller sends Token to Recipient and never returns it to the client.
type Challenge struct {
	Method      string    `json:"method"`
	DomainURL   string    `json:"domainUrl"`
	DomainName  string    `json:"domainName"`
	Token       string    `json:"-"`
	Recipient   string    `json:"recipient,omitempty"`
	ExpiresAt   time.Time `json:"expiresAt"`
	RecordName  string    `json:"recordName,omitempty"`  // DNS TXT owner name
	RecordValue string    `json:"recordValue,omitempty"` // DNS TXT value
	FileURL     string    `json:"fileUrl,omitempty"`     // where the host serves the file
	FileBody    string    `json:"fileBody,omitempty"`    // what the file contains
}
