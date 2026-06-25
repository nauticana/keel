package dispatcher

import "testing"

func TestToE164(t *testing.T) {
	tests := []struct {
		name    string
		phone   string
		country string
		want    string
		wantErr bool
	}{
		{"national + country", "9493946318", "US", "+19493946318", false},
		{"formatted national", "(949) 394-6318", "US", "+19493946318", false},
		{"already e164, no region", "+19493946318", "", "+19493946318", false},
		{"already e164, region ignored + lowercased", "+19493946318", "us", "+19493946318", false},
		{"national without region fails", "9493946318", "", "", true},
		{"empty phone fails", "", "US", "", true},
		{"too short to be valid fails", "12", "US", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ToE164(tt.phone, tt.country)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ToE164(%q, %q) = %q, want error", tt.phone, tt.country, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ToE164(%q, %q) unexpected error: %v", tt.phone, tt.country, err)
			}
			if got != tt.want {
				t.Errorf("ToE164(%q, %q) = %q, want %q", tt.phone, tt.country, got, tt.want)
			}
		})
	}
}
