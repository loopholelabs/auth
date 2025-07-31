package storage

import "fmt"

// ResourceIdentifier represents access to a particular resource
type ResourceIdentifier struct {
	OrganizationIdentifier string `json:"organization_identifier"`
	Kind                   string `json:"kind"`
	Identifier             string `json:"identifier"`
}

// Equals returns whether two ResourceIdentifiers are equivalent to one another
func (a *ResourceIdentifier) Equals(o ResourceIdentifier) bool {
	return a.Kind == o.Kind && a.OrganizationIdentifier == o.OrganizationIdentifier && a.Identifier == o.Identifier
}

// String returns the string representation of a ResourceIdentifier
func (a *ResourceIdentifier) String() string {
	return fmt.Sprintf("rid::%s::%s/%s", a.OrganizationIdentifier, a.Kind, a.Identifier)
}
