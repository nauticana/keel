package service

import "context"

// fakePlainTx is a transaction that cannot bind another query catalog.
type fakePlainTx struct{ *quotaFakeQS }

func (fakePlainTx) Commit(context.Context) error   { return nil }
func (fakePlainTx) Rollback(context.Context) error { return nil }
