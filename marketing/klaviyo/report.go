package klaviyo

import "time"

const (
	StatConversionValue = "conversion_value"
	StatConversions     = "conversions"
	StatRecipients      = "recipients"

	ChannelEmail = "email"
	ChannelSMS   = "sms"
)

// ValuesQuery asks a flow or campaign values report for statistics attributed
// to ConversionMetricID over Timeframe.
type ValuesQuery struct {
	Statistics         []string
	Timeframe          Timeframe
	ConversionMetricID string
	Filter             string
}

// Timeframe is either a relative Key such as "last_30_days" or a Start and End.
type Timeframe struct {
	Key   string
	Start time.Time
	End   time.Time
}

// ValuesResult is one report row. Statistics hold the decimal text Klaviyo
// sent, never a float: conversion_value is money in the account currency, to be
// summed exactly or converted with common.ParseMinorUnits at the currency's exponent.
type ValuesResult struct {
	Groupings  map[string]string
	Statistics map[string]string
}
