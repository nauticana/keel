package domain

import "slices"

// Method codes of the domain_verification_method catalog.
const (
	MethodEmailCode       = "EC"
	MethodVerifiedEmail   = "VE"
	MethodGoogleHD        = "GH"
	MethodGoogleMX        = "GM"
	MethodHTTPFile        = "HF"
	MethodDNSTXT          = "DT"
	MethodGoogleSite      = "GS"
	MethodGoogleBusiness  = "GB"
	MethodGoogleWorkspace = "GW"
	MethodMicrosoftEntra  = "ME"
)

// identityMethods prove control of a domain strongly enough to route sign-in
// to a tenant's identity provider. At most one partner holds current evidence
// by these methods for a domain.
var identityMethods = []string{MethodDNSTXT, MethodGoogleWorkspace, MethodMicrosoftEntra}

var challengeMethods = []string{MethodEmailCode, MethodDNSTXT, MethodHTTPFile}

var grantMethods = []string{MethodGoogleSite, MethodGoogleBusiness, MethodGoogleWorkspace, MethodMicrosoftEntra}

// IdentityMethods returns the methods subject to cross-partner exclusivity.
func IdentityMethods() []string { return slices.Clone(identityMethods) }

func isIdentityMethod(m string) bool  { return slices.Contains(identityMethods, m) }
func isChallengeMethod(m string) bool { return slices.Contains(challengeMethods, m) }
