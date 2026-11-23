package handler

import (
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

// BusinessPartnerActionHandler serves the create table action of
// business_partner: an operator creates a partner with no member or plan.
type BusinessPartnerActionHandler struct {
	AbstractHandler
	DB       port.DatabaseRepository
	Register *user.RegistrationService
}

// Routes mounts business_partner/create under prefix, gated by
// BUSINESS_PARTNER CREATE.
func (h *BusinessPartnerActionHandler) Routes(prefix string) map[string]func(http.ResponseWriter, *http.Request) {
	return map[string]func(http.ResponseWriter, *http.Request){
		TableActionPath(prefix, "business_partner", "create"): WrapTableAction(
			h.DB, h.UserService, "BUSINESS_PARTNER", "CREATE", "business_partner", h.create),
	}
}

func (h *BusinessPartnerActionHandler) create(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Caption   string  `json:"caption"`
		Address   string  `json:"address"`
		City      string  `json:"city"`
		State     string  `json:"state"`
		Zipcode   string  `json:"zipcode"`
		Country   string  `json:"country"`
		Phone     string  `json:"phone"`
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
	}
	if _, ok := h.ReadAuthRequest(w, r, &req); !ok {
		return
	}
	partnerID, err := h.Register.CreatePartnerFor(r.Context(), &user.PartnerSetup{
		PartnerCaption: req.Caption, Address: req.Address, City: req.City, State: req.State, Zipcode: req.Zipcode,
		Country: req.Country, Phone: req.Phone, Latitude: req.Latitude, Longitude: req.Longitude,
	})
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusCreated, map[string]int64{"id": partnerID})
}
