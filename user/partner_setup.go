package user

import (
	"encoding/json"
	"math"
	"strings"

	"github.com/nauticana/keel/domain"
	"github.com/nauticana/keel/model"
)

// PartnerSetup is the business part of a signup. Extra carries the
// application's own fields to OnPartnerTx.
type PartnerSetup struct {
	PartnerCaption string  `json:"partnerCaption"`
	Address        string  `json:"address"`
	City           string  `json:"city"`
	State          string  `json:"state"`
	Zipcode        string  `json:"zipcode"`
	Country        string  `json:"country"`
	Phone          string  `json:"phone"`
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
	DomainURL      string  `json:"domainUrl"`
	PlanID         string  `json:"planId"`
	// Chosen offer (PERIOD_TYPE codes) from the plan's subscription_plan_price
	// rows; none selects the cheapest.
	BillingCycle string          `json:"billingCycle,omitempty"`
	TermType     string          `json:"termType,omitempty"`
	TermCount    int             `json:"termCount,omitempty"`
	Extra        json.RawMessage `json:"extra,omitempty"`
}

func (p *PartnerSetup) empty() bool {
	return p.PartnerCaption == "" && p.Address == "" && p.City == "" && p.State == "" && p.Zipcode == "" &&
		p.Country == "" && p.Phone == "" && p.Latitude == 0 && p.Longitude == 0 && p.DomainURL == "" &&
		p.PlanID == "" && p.BillingCycle == "" && p.TermType == "" && p.TermCount == 0 && len(p.Extra) == 0
}

// host returns the normalized partner domain, "" for none.
func (p *PartnerSetup) host() (string, error) {
	if strings.TrimSpace(p.DomainURL) == "" {
		return "", nil
	}
	if h := domain.HostFromURL(p.DomainURL); h != "" {
		return h, nil
	}
	return "", model.NewBadRequest("domainUrl is not a valid host")
}

func (p *PartnerSetup) validate() error {
	switch {
	case strings.TrimSpace(p.PartnerCaption) == "":
		return model.NewBadRequest("partnerCaption is required")
	case math.IsNaN(p.Latitude) || math.Abs(p.Latitude) > 90 || math.IsNaN(p.Longitude) || math.Abs(p.Longitude) > 180:
		return model.NewBadRequest("latitude or longitude is out of range")
	case p.TermCount < 0:
		return model.NewBadRequest("termCount must not be negative")
	}
	_, err := p.host()
	return err
}
