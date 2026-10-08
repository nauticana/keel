package handler

import (
	"encoding/json"
	"errors"
	"io"
)

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("more than one JSON value")
}
