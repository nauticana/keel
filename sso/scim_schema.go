package sso

// SCIMSchema is a Schema resource (RFC 7643 §7).
type SCIMSchema struct {
	Schemas     []string        `json:"schemas"`
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Attributes  []SCIMAttribute `json:"attributes"`
	Meta        *SCIMMeta       `json:"meta"`
}

// SCIMAttribute describes one attribute of a SCIMSchema.
type SCIMAttribute struct {
	Name            string          `json:"name"`
	Type            string          `json:"type"`
	MultiValued     bool            `json:"multiValued"`
	Description     string          `json:"description,omitempty"`
	Required        bool            `json:"required"`
	CaseExact       bool            `json:"caseExact"`
	CanonicalValues []string        `json:"canonicalValues,omitempty"`
	Mutability      string          `json:"mutability"`
	Returned        string          `json:"returned"`
	Uniqueness      string          `json:"uniqueness"`
	SubAttributes   []SCIMAttribute `json:"subAttributes,omitempty"`
}

func scimString(name, mutability string, required, caseExact bool, uniqueness, description string) SCIMAttribute {
	return SCIMAttribute{Name: name, Type: "string", Required: required, CaseExact: caseExact, Mutability: mutability,
		Returned: "default", Uniqueness: uniqueness, Description: description}
}

// SCIMSchemas describes the User and Group attributes keel keeps, each time
// as a fresh value the caller may complete with meta.location.
func SCIMSchemas() []SCIMSchema {
	ref := func(description string, valueMutability string) []SCIMAttribute {
		return []SCIMAttribute{
			scimString("value", valueMutability, false, false, "none", description),
			scimString("display", "readOnly", false, false, "none", "Display name of the referenced resource."),
		}
	}
	user := []SCIMAttribute{
		scimString("userName", "readWrite", true, false, "server", "Unique identifier of the user, compared without case."),
		scimString("externalId", "readWrite", false, true, "server", "Identifier of the user in the directory."),
		{Name: "name", Type: "complex", Mutability: "readWrite", Returned: "default", Uniqueness: "none",
			SubAttributes: []SCIMAttribute{
				scimString("givenName", "readWrite", false, false, "none", "Given name, at most 80 characters."),
				scimString("familyName", "readWrite", false, false, "none", "Family name, at most 80 characters."),
			}},
		scimString("displayName", "readOnly", false, false, "none", "Given and family name."),
		{Name: "emails", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none",
			Description: "keel keeps one address: the primary, else the first.",
			SubAttributes: []SCIMAttribute{
				scimString("value", "readWrite", false, false, "none", "Address inside a domain the organization holds."),
				{Name: "type", Type: "string", CanonicalValues: []string{"work", "home", "other"}, Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
				{Name: "primary", Type: "boolean", Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
			}},
		{Name: "active", Type: "boolean", Mutability: "readWrite", Returned: "default", Uniqueness: "none",
			Description: "False ends the user's membership, roles and sessions."},
		{Name: "groups", Type: "complex", MultiValued: true, Mutability: "readOnly", Returned: "default", Uniqueness: "none",
			SubAttributes: ref("Identifier of a group the user belongs to.", "readOnly")},
	}
	group := []SCIMAttribute{
		scimString("displayName", "readWrite", true, false, "server", "Unique name of the group, compared without case."),
		scimString("externalId", "readWrite", false, true, "server", "Identifier of the group in the directory."),
		{Name: "members", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none",
			SubAttributes: ref("Identifier of a provisioned member user.", "immutable")},
	}
	return []SCIMSchema{
		{Schemas: []string{SchemaSchema}, ID: SchemaUser, Name: "User", Description: "User account", Attributes: user,
			Meta: &SCIMMeta{ResourceType: "Schema"}},
		{Schemas: []string{SchemaSchema}, ID: SchemaGroup, Name: "Group", Description: "Group", Attributes: group,
			Meta: &SCIMMeta{ResourceType: "Schema"}},
	}
}
