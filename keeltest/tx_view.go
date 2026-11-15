package keeltest

import "github.com/nauticana/keel/port"

// TxView is the transaction view Database hands to RunInTx; it has no tables.
type TxView struct{ Queries *Queries }

func (v TxView) Table(string) port.TableService                   { return nil }
func (v TxView) QueryService(map[string]string) port.QueryService { return v.Queries }

var _ port.TxQueryView = TxView{}
