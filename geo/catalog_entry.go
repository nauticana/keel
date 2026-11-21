package geo

// CatalogEntry is a country or state code with its caption.
type CatalogEntry struct {
	Code    string `json:"code"`
	Caption string `json:"caption"`
}

// CurrencyEntry is a currency code with its caption and minor-unit exponent.
type CurrencyEntry struct {
	Code     string `json:"code"`
	Caption  string `json:"caption"`
	Exponent int16  `json:"exponent"`
}
