package port

import "context"

type LoginProvider interface {
	GetLoginUrl() string
	GetLoginData(ctx context.Context, code string) (string, error)
}
