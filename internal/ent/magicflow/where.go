// Code generated by ent, DO NOT EDIT.

package magicflow

import (
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/loopholelabs/auth/internal/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldID), id))
	})
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		v := make([]any, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.In(s.C(FieldID), v...))
	})
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		v := make([]any, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.NotIn(s.C(FieldID), v...))
	})
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldID), id))
	})
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldID), id))
	})
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldID), id))
	})
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldID), id))
	})
}

// CreatedAt applies equality check predicate on the "created_at" field. It's identical to CreatedAtEQ.
func CreatedAt(v time.Time) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldCreatedAt), v))
	})
}

// Email applies equality check predicate on the "email" field. It's identical to EmailEQ.
func Email(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldEmail), v))
	})
}

// IPAddress applies equality check predicate on the "ip_address" field. It's identical to IPAddressEQ.
func IPAddress(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldIPAddress), v))
	})
}

// Secret applies equality check predicate on the "secret" field. It's identical to SecretEQ.
func Secret(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldSecret), v))
	})
}

// NextURL applies equality check predicate on the "next_url" field. It's identical to NextURLEQ.
func NextURL(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldNextURL), v))
	})
}

// Organization applies equality check predicate on the "organization" field. It's identical to OrganizationEQ.
func Organization(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldOrganization), v))
	})
}

// DeviceIdentifier applies equality check predicate on the "device_identifier" field. It's identical to DeviceIdentifierEQ.
func DeviceIdentifier(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDeviceIdentifier), v))
	})
}

// CreatedAtEQ applies the EQ predicate on the "created_at" field.
func CreatedAtEQ(v time.Time) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtNEQ applies the NEQ predicate on the "created_at" field.
func CreatedAtNEQ(v time.Time) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtIn applies the In predicate on the "created_at" field.
func CreatedAtIn(vs ...time.Time) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldCreatedAt), v...))
	})
}

// CreatedAtNotIn applies the NotIn predicate on the "created_at" field.
func CreatedAtNotIn(vs ...time.Time) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldCreatedAt), v...))
	})
}

// CreatedAtGT applies the GT predicate on the "created_at" field.
func CreatedAtGT(v time.Time) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtGTE applies the GTE predicate on the "created_at" field.
func CreatedAtGTE(v time.Time) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtLT applies the LT predicate on the "created_at" field.
func CreatedAtLT(v time.Time) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtLTE applies the LTE predicate on the "created_at" field.
func CreatedAtLTE(v time.Time) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldCreatedAt), v))
	})
}

// EmailEQ applies the EQ predicate on the "email" field.
func EmailEQ(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldEmail), v))
	})
}

// EmailNEQ applies the NEQ predicate on the "email" field.
func EmailNEQ(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldEmail), v))
	})
}

// EmailIn applies the In predicate on the "email" field.
func EmailIn(vs ...string) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldEmail), v...))
	})
}

// EmailNotIn applies the NotIn predicate on the "email" field.
func EmailNotIn(vs ...string) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldEmail), v...))
	})
}

// EmailGT applies the GT predicate on the "email" field.
func EmailGT(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldEmail), v))
	})
}

// EmailGTE applies the GTE predicate on the "email" field.
func EmailGTE(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldEmail), v))
	})
}

// EmailLT applies the LT predicate on the "email" field.
func EmailLT(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldEmail), v))
	})
}

// EmailLTE applies the LTE predicate on the "email" field.
func EmailLTE(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldEmail), v))
	})
}

// EmailContains applies the Contains predicate on the "email" field.
func EmailContains(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldEmail), v))
	})
}

// EmailHasPrefix applies the HasPrefix predicate on the "email" field.
func EmailHasPrefix(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldEmail), v))
	})
}

// EmailHasSuffix applies the HasSuffix predicate on the "email" field.
func EmailHasSuffix(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldEmail), v))
	})
}

// EmailEqualFold applies the EqualFold predicate on the "email" field.
func EmailEqualFold(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldEmail), v))
	})
}

// EmailContainsFold applies the ContainsFold predicate on the "email" field.
func EmailContainsFold(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldEmail), v))
	})
}

// IPAddressEQ applies the EQ predicate on the "ip_address" field.
func IPAddressEQ(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldIPAddress), v))
	})
}

// IPAddressNEQ applies the NEQ predicate on the "ip_address" field.
func IPAddressNEQ(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldIPAddress), v))
	})
}

// IPAddressIn applies the In predicate on the "ip_address" field.
func IPAddressIn(vs ...string) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldIPAddress), v...))
	})
}

// IPAddressNotIn applies the NotIn predicate on the "ip_address" field.
func IPAddressNotIn(vs ...string) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldIPAddress), v...))
	})
}

// IPAddressGT applies the GT predicate on the "ip_address" field.
func IPAddressGT(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldIPAddress), v))
	})
}

// IPAddressGTE applies the GTE predicate on the "ip_address" field.
func IPAddressGTE(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldIPAddress), v))
	})
}

// IPAddressLT applies the LT predicate on the "ip_address" field.
func IPAddressLT(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldIPAddress), v))
	})
}

// IPAddressLTE applies the LTE predicate on the "ip_address" field.
func IPAddressLTE(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldIPAddress), v))
	})
}

// IPAddressContains applies the Contains predicate on the "ip_address" field.
func IPAddressContains(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldIPAddress), v))
	})
}

// IPAddressHasPrefix applies the HasPrefix predicate on the "ip_address" field.
func IPAddressHasPrefix(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldIPAddress), v))
	})
}

// IPAddressHasSuffix applies the HasSuffix predicate on the "ip_address" field.
func IPAddressHasSuffix(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldIPAddress), v))
	})
}

// IPAddressEqualFold applies the EqualFold predicate on the "ip_address" field.
func IPAddressEqualFold(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldIPAddress), v))
	})
}

// IPAddressContainsFold applies the ContainsFold predicate on the "ip_address" field.
func IPAddressContainsFold(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldIPAddress), v))
	})
}

// SecretEQ applies the EQ predicate on the "secret" field.
func SecretEQ(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldSecret), v))
	})
}

// SecretNEQ applies the NEQ predicate on the "secret" field.
func SecretNEQ(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldSecret), v))
	})
}

// SecretIn applies the In predicate on the "secret" field.
func SecretIn(vs ...string) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldSecret), v...))
	})
}

// SecretNotIn applies the NotIn predicate on the "secret" field.
func SecretNotIn(vs ...string) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldSecret), v...))
	})
}

// SecretGT applies the GT predicate on the "secret" field.
func SecretGT(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldSecret), v))
	})
}

// SecretGTE applies the GTE predicate on the "secret" field.
func SecretGTE(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldSecret), v))
	})
}

// SecretLT applies the LT predicate on the "secret" field.
func SecretLT(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldSecret), v))
	})
}

// SecretLTE applies the LTE predicate on the "secret" field.
func SecretLTE(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldSecret), v))
	})
}

// SecretContains applies the Contains predicate on the "secret" field.
func SecretContains(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldSecret), v))
	})
}

// SecretHasPrefix applies the HasPrefix predicate on the "secret" field.
func SecretHasPrefix(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldSecret), v))
	})
}

// SecretHasSuffix applies the HasSuffix predicate on the "secret" field.
func SecretHasSuffix(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldSecret), v))
	})
}

// SecretEqualFold applies the EqualFold predicate on the "secret" field.
func SecretEqualFold(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldSecret), v))
	})
}

// SecretContainsFold applies the ContainsFold predicate on the "secret" field.
func SecretContainsFold(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldSecret), v))
	})
}

// NextURLEQ applies the EQ predicate on the "next_url" field.
func NextURLEQ(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldNextURL), v))
	})
}

// NextURLNEQ applies the NEQ predicate on the "next_url" field.
func NextURLNEQ(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldNextURL), v))
	})
}

// NextURLIn applies the In predicate on the "next_url" field.
func NextURLIn(vs ...string) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldNextURL), v...))
	})
}

// NextURLNotIn applies the NotIn predicate on the "next_url" field.
func NextURLNotIn(vs ...string) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldNextURL), v...))
	})
}

// NextURLGT applies the GT predicate on the "next_url" field.
func NextURLGT(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldNextURL), v))
	})
}

// NextURLGTE applies the GTE predicate on the "next_url" field.
func NextURLGTE(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldNextURL), v))
	})
}

// NextURLLT applies the LT predicate on the "next_url" field.
func NextURLLT(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldNextURL), v))
	})
}

// NextURLLTE applies the LTE predicate on the "next_url" field.
func NextURLLTE(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldNextURL), v))
	})
}

// NextURLContains applies the Contains predicate on the "next_url" field.
func NextURLContains(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldNextURL), v))
	})
}

// NextURLHasPrefix applies the HasPrefix predicate on the "next_url" field.
func NextURLHasPrefix(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldNextURL), v))
	})
}

// NextURLHasSuffix applies the HasSuffix predicate on the "next_url" field.
func NextURLHasSuffix(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldNextURL), v))
	})
}

// NextURLEqualFold applies the EqualFold predicate on the "next_url" field.
func NextURLEqualFold(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldNextURL), v))
	})
}

// NextURLContainsFold applies the ContainsFold predicate on the "next_url" field.
func NextURLContainsFold(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldNextURL), v))
	})
}

// OrganizationEQ applies the EQ predicate on the "organization" field.
func OrganizationEQ(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldOrganization), v))
	})
}

// OrganizationNEQ applies the NEQ predicate on the "organization" field.
func OrganizationNEQ(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldOrganization), v))
	})
}

// OrganizationIn applies the In predicate on the "organization" field.
func OrganizationIn(vs ...string) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldOrganization), v...))
	})
}

// OrganizationNotIn applies the NotIn predicate on the "organization" field.
func OrganizationNotIn(vs ...string) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldOrganization), v...))
	})
}

// OrganizationGT applies the GT predicate on the "organization" field.
func OrganizationGT(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldOrganization), v))
	})
}

// OrganizationGTE applies the GTE predicate on the "organization" field.
func OrganizationGTE(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldOrganization), v))
	})
}

// OrganizationLT applies the LT predicate on the "organization" field.
func OrganizationLT(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldOrganization), v))
	})
}

// OrganizationLTE applies the LTE predicate on the "organization" field.
func OrganizationLTE(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldOrganization), v))
	})
}

// OrganizationContains applies the Contains predicate on the "organization" field.
func OrganizationContains(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldOrganization), v))
	})
}

// OrganizationHasPrefix applies the HasPrefix predicate on the "organization" field.
func OrganizationHasPrefix(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldOrganization), v))
	})
}

// OrganizationHasSuffix applies the HasSuffix predicate on the "organization" field.
func OrganizationHasSuffix(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldOrganization), v))
	})
}

// OrganizationIsNil applies the IsNil predicate on the "organization" field.
func OrganizationIsNil() predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.IsNull(s.C(FieldOrganization)))
	})
}

// OrganizationNotNil applies the NotNil predicate on the "organization" field.
func OrganizationNotNil() predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NotNull(s.C(FieldOrganization)))
	})
}

// OrganizationEqualFold applies the EqualFold predicate on the "organization" field.
func OrganizationEqualFold(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldOrganization), v))
	})
}

// OrganizationContainsFold applies the ContainsFold predicate on the "organization" field.
func OrganizationContainsFold(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldOrganization), v))
	})
}

// DeviceIdentifierEQ applies the EQ predicate on the "device_identifier" field.
func DeviceIdentifierEQ(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierNEQ applies the NEQ predicate on the "device_identifier" field.
func DeviceIdentifierNEQ(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierIn applies the In predicate on the "device_identifier" field.
func DeviceIdentifierIn(vs ...string) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldDeviceIdentifier), v...))
	})
}

// DeviceIdentifierNotIn applies the NotIn predicate on the "device_identifier" field.
func DeviceIdentifierNotIn(vs ...string) predicate.MagicFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldDeviceIdentifier), v...))
	})
}

// DeviceIdentifierGT applies the GT predicate on the "device_identifier" field.
func DeviceIdentifierGT(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierGTE applies the GTE predicate on the "device_identifier" field.
func DeviceIdentifierGTE(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierLT applies the LT predicate on the "device_identifier" field.
func DeviceIdentifierLT(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierLTE applies the LTE predicate on the "device_identifier" field.
func DeviceIdentifierLTE(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierContains applies the Contains predicate on the "device_identifier" field.
func DeviceIdentifierContains(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierHasPrefix applies the HasPrefix predicate on the "device_identifier" field.
func DeviceIdentifierHasPrefix(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierHasSuffix applies the HasSuffix predicate on the "device_identifier" field.
func DeviceIdentifierHasSuffix(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierIsNil applies the IsNil predicate on the "device_identifier" field.
func DeviceIdentifierIsNil() predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.IsNull(s.C(FieldDeviceIdentifier)))
	})
}

// DeviceIdentifierNotNil applies the NotNil predicate on the "device_identifier" field.
func DeviceIdentifierNotNil() predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.NotNull(s.C(FieldDeviceIdentifier)))
	})
}

// DeviceIdentifierEqualFold applies the EqualFold predicate on the "device_identifier" field.
func DeviceIdentifierEqualFold(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierContainsFold applies the ContainsFold predicate on the "device_identifier" field.
func DeviceIdentifierContainsFold(v string) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldDeviceIdentifier), v))
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.MagicFlow) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.MagicFlow) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for i, p := range predicates {
			if i > 0 {
				s1.Or()
			}
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Not applies the not operator on the given predicate.
func Not(p predicate.MagicFlow) predicate.MagicFlow {
	return predicate.MagicFlow(func(s *sql.Selector) {
		p(s.Not())
	})
}
