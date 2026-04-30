package logger

import (
	"fmt"

	"github.com/nauticana/keel/common"
)

func NewApplicationLogger(caption string) (ApplicationLogger, error) {
	var l ApplicationLogger
	switch *common.LogType {
	case "local":
		l = &LoggerFile{}
	case "gcp":
		l = &LoggerGcp{}
	case "aws":
		l = &LoggerAWS{}
	default:
		return nil, fmt.Errorf("unknown log_type: %s", *common.LogType)
	}
	if err := l.Initialize(*common.LogRoot, caption); err != nil {
		return nil, err
	}
	return l, nil
}
