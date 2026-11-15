package handler

import (
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/service"
)

func init() {
	RegisterErrorCode(common.ErrUnauthenticated, http.StatusUnauthorized, "unauthenticated")
	RegisterErrorCode(common.ErrCallerIdentityConflict, http.StatusUnauthorized, "caller_identity_conflict")
	RegisterErrorCode(service.ErrForbidden, http.StatusForbidden, "forbidden")
	RegisterErrorCode(service.ErrNotFound, http.StatusNotFound, "not_found")
}
