package port

import "net/http"

type WebSocketHub interface {
	HandleUpgrade(w http.ResponseWriter, r *http.Request, userID int)
	Broadcast(channel string, message []byte)
	SendToUser(userID int, message []byte) error
}
