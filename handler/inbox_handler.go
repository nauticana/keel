package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/dispatcher"
	"github.com/nauticana/keel/port"
)

// InboxHandler serves the caller's own notification inbox.
type InboxHandler struct {
	AbstractHandler
	Inbox port.NotificationInbox
}

func (h *InboxHandler) GetAuthRoutes() map[string]func(w http.ResponseWriter, r *http.Request) {
	return map[string]func(w http.ResponseWriter, r *http.Request){
		common.RestPrefix + "/notifications":               h.List,
		common.RestPrefix + "/notifications/mark_read":     h.MarkRead,
		common.RestPrefix + "/notifications/mark_all_read": h.MarkAllRead,
	}
}

// List: GET ?before=<id>&limit=<n> → port.InboxPage, newest first.
func (h *InboxHandler) List(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	before, limit := int64(0), 0
	var err error
	if v := r.URL.Query().Get("before"); v != "" {
		if before, err = strconv.ParseInt(v, 10, 64); err != nil || before < 0 {
			h.WriteError(w, http.StatusBadRequest, "Bad Request", "before must be a message id")
			return
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit <= 0 {
			h.WriteError(w, http.StatusBadRequest, "Bad Request", "limit must be a positive integer")
			return
		}
	}
	page, err := h.Inbox.List(r.Context(), session.Id, before, limit)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, page)
}

// MarkRead: POST {"id": "<message id>"}.
func (h *InboxHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		ID int64 `json:"id,string"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if err := h.Inbox.MarkRead(r.Context(), session.Id, req.ID); err != nil {
		if errors.Is(err, dispatcher.ErrInboxMessageNotFound) {
			h.WriteError(w, http.StatusNotFound, "Not Found", "message not found")
			return
		}
		h.WriteServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *InboxHandler) MarkAllRead(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	session, ok := h.RequireSession(w, r)
	if !ok {
		return
	}
	if err := h.Inbox.MarkAllRead(r.Context(), session.Id); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
