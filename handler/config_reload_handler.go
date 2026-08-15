package handler

import (
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
)

// ReloadConfig is the inner handler for the application_config_flag RELOAD table
// action: it re-runs the app's config load via config.ReloadFunc and swaps
// config.Config(). Mount it behind WrapTableAction with the RELOAD grant:
//
//	mux[prefix+"/pubapi/table_action/application_config_flag/reload"] =
//	    handler.WrapTableAction(db, userSvc, "APPLICATION_CONFIG_FLAG", "RELOAD",
//	        "application_config_flag", handler.ReloadConfig)
//
// main must set config.ReloadFunc for this to do anything (see package config).
func ReloadConfig(w http.ResponseWriter, r *http.Request) {
	if config.ReloadFunc == nil {
		common.WriteJSONError(w, http.StatusNotImplemented, "config reload not supported")
		return
	}
	if err := config.ReloadFunc(r.Context()); err != nil {
		common.WriteJSONError(w, http.StatusInternalServerError, "config reload failed")
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}
