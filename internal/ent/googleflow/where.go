// Code generated by ent, DO NOT EDIT.

package googleflow

import (
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/loopholelabs/auth/internal/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldID), id))
	})
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		v := make([]any, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.In(s.C(FieldID), v...))
	})
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		v := make([]any, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.NotIn(s.C(FieldID), v...))
	})
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldID), id))
	})
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldID), id))
	})
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldID), id))
	})
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldID), id))
	})
}

// CreatedAt applies equality check predicate on the "created_at" field. It's identical to CreatedAtEQ.
func CreatedAt(v time.Time) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldCreatedAt), v))
	})
}

// State applies equality check predicate on the "state" field. It's identical to StateEQ.
func State(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldState), v))
	})
}

// Verifier applies equality check predicate on the "verifier" field. It's identical to VerifierEQ.
func Verifier(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldVerifier), v))
	})
}

// Challenge applies equality check predicate on the "challenge" field. It's identical to ChallengeEQ.
func Challenge(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldChallenge), v))
	})
}

// NextURL applies equality check predicate on the "next_url" field. It's identical to NextURLEQ.
func NextURL(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldNextURL), v))
	})
}

// Organization applies equality check predicate on the "organization" field. It's identical to OrganizationEQ.
func Organization(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldOrganization), v))
	})
}

// DeviceIdentifier applies equality check predicate on the "device_identifier" field. It's identical to DeviceIdentifierEQ.
func DeviceIdentifier(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDeviceIdentifier), v))
	})
}

// CreatedAtEQ applies the EQ predicate on the "created_at" field.
func CreatedAtEQ(v time.Time) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtNEQ applies the NEQ predicate on the "created_at" field.
func CreatedAtNEQ(v time.Time) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtIn applies the In predicate on the "created_at" field.
func CreatedAtIn(vs ...time.Time) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldCreatedAt), v...))
	})
}

// CreatedAtNotIn applies the NotIn predicate on the "created_at" field.
func CreatedAtNotIn(vs ...time.Time) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldCreatedAt), v...))
	})
}

// CreatedAtGT applies the GT predicate on the "created_at" field.
func CreatedAtGT(v time.Time) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtGTE applies the GTE predicate on the "created_at" field.
func CreatedAtGTE(v time.Time) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtLT applies the LT predicate on the "created_at" field.
func CreatedAtLT(v time.Time) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldCreatedAt), v))
	})
}

// CreatedAtLTE applies the LTE predicate on the "created_at" field.
func CreatedAtLTE(v time.Time) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldCreatedAt), v))
	})
}

// StateEQ applies the EQ predicate on the "state" field.
func StateEQ(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldState), v))
	})
}

// StateNEQ applies the NEQ predicate on the "state" field.
func StateNEQ(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldState), v))
	})
}

// StateIn applies the In predicate on the "state" field.
func StateIn(vs ...string) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldState), v...))
	})
}

// StateNotIn applies the NotIn predicate on the "state" field.
func StateNotIn(vs ...string) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldState), v...))
	})
}

// StateGT applies the GT predicate on the "state" field.
func StateGT(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldState), v))
	})
}

// StateGTE applies the GTE predicate on the "state" field.
func StateGTE(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldState), v))
	})
}

// StateLT applies the LT predicate on the "state" field.
func StateLT(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldState), v))
	})
}

// StateLTE applies the LTE predicate on the "state" field.
func StateLTE(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldState), v))
	})
}

// StateContains applies the Contains predicate on the "state" field.
func StateContains(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldState), v))
	})
}

// StateHasPrefix applies the HasPrefix predicate on the "state" field.
func StateHasPrefix(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldState), v))
	})
}

// StateHasSuffix applies the HasSuffix predicate on the "state" field.
func StateHasSuffix(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldState), v))
	})
}

// StateEqualFold applies the EqualFold predicate on the "state" field.
func StateEqualFold(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldState), v))
	})
}

// StateContainsFold applies the ContainsFold predicate on the "state" field.
func StateContainsFold(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldState), v))
	})
}

// VerifierEQ applies the EQ predicate on the "verifier" field.
func VerifierEQ(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldVerifier), v))
	})
}

// VerifierNEQ applies the NEQ predicate on the "verifier" field.
func VerifierNEQ(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldVerifier), v))
	})
}

// VerifierIn applies the In predicate on the "verifier" field.
func VerifierIn(vs ...string) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldVerifier), v...))
	})
}

// VerifierNotIn applies the NotIn predicate on the "verifier" field.
func VerifierNotIn(vs ...string) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldVerifier), v...))
	})
}

// VerifierGT applies the GT predicate on the "verifier" field.
func VerifierGT(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldVerifier), v))
	})
}

// VerifierGTE applies the GTE predicate on the "verifier" field.
func VerifierGTE(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldVerifier), v))
	})
}

// VerifierLT applies the LT predicate on the "verifier" field.
func VerifierLT(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldVerifier), v))
	})
}

// VerifierLTE applies the LTE predicate on the "verifier" field.
func VerifierLTE(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldVerifier), v))
	})
}

// VerifierContains applies the Contains predicate on the "verifier" field.
func VerifierContains(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldVerifier), v))
	})
}

// VerifierHasPrefix applies the HasPrefix predicate on the "verifier" field.
func VerifierHasPrefix(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldVerifier), v))
	})
}

// VerifierHasSuffix applies the HasSuffix predicate on the "verifier" field.
func VerifierHasSuffix(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldVerifier), v))
	})
}

// VerifierEqualFold applies the EqualFold predicate on the "verifier" field.
func VerifierEqualFold(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldVerifier), v))
	})
}

// VerifierContainsFold applies the ContainsFold predicate on the "verifier" field.
func VerifierContainsFold(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldVerifier), v))
	})
}

// ChallengeEQ applies the EQ predicate on the "challenge" field.
func ChallengeEQ(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldChallenge), v))
	})
}

// ChallengeNEQ applies the NEQ predicate on the "challenge" field.
func ChallengeNEQ(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldChallenge), v))
	})
}

// ChallengeIn applies the In predicate on the "challenge" field.
func ChallengeIn(vs ...string) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldChallenge), v...))
	})
}

// ChallengeNotIn applies the NotIn predicate on the "challenge" field.
func ChallengeNotIn(vs ...string) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldChallenge), v...))
	})
}

// ChallengeGT applies the GT predicate on the "challenge" field.
func ChallengeGT(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldChallenge), v))
	})
}

// ChallengeGTE applies the GTE predicate on the "challenge" field.
func ChallengeGTE(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldChallenge), v))
	})
}

// ChallengeLT applies the LT predicate on the "challenge" field.
func ChallengeLT(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldChallenge), v))
	})
}

// ChallengeLTE applies the LTE predicate on the "challenge" field.
func ChallengeLTE(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldChallenge), v))
	})
}

// ChallengeContains applies the Contains predicate on the "challenge" field.
func ChallengeContains(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldChallenge), v))
	})
}

// ChallengeHasPrefix applies the HasPrefix predicate on the "challenge" field.
func ChallengeHasPrefix(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldChallenge), v))
	})
}

// ChallengeHasSuffix applies the HasSuffix predicate on the "challenge" field.
func ChallengeHasSuffix(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldChallenge), v))
	})
}

// ChallengeEqualFold applies the EqualFold predicate on the "challenge" field.
func ChallengeEqualFold(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldChallenge), v))
	})
}

// ChallengeContainsFold applies the ContainsFold predicate on the "challenge" field.
func ChallengeContainsFold(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldChallenge), v))
	})
}

// NextURLEQ applies the EQ predicate on the "next_url" field.
func NextURLEQ(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldNextURL), v))
	})
}

// NextURLNEQ applies the NEQ predicate on the "next_url" field.
func NextURLNEQ(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldNextURL), v))
	})
}

// NextURLIn applies the In predicate on the "next_url" field.
func NextURLIn(vs ...string) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldNextURL), v...))
	})
}

// NextURLNotIn applies the NotIn predicate on the "next_url" field.
func NextURLNotIn(vs ...string) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldNextURL), v...))
	})
}

// NextURLGT applies the GT predicate on the "next_url" field.
func NextURLGT(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldNextURL), v))
	})
}

// NextURLGTE applies the GTE predicate on the "next_url" field.
func NextURLGTE(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldNextURL), v))
	})
}

// NextURLLT applies the LT predicate on the "next_url" field.
func NextURLLT(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldNextURL), v))
	})
}

// NextURLLTE applies the LTE predicate on the "next_url" field.
func NextURLLTE(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldNextURL), v))
	})
}

// NextURLContains applies the Contains predicate on the "next_url" field.
func NextURLContains(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldNextURL), v))
	})
}

// NextURLHasPrefix applies the HasPrefix predicate on the "next_url" field.
func NextURLHasPrefix(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldNextURL), v))
	})
}

// NextURLHasSuffix applies the HasSuffix predicate on the "next_url" field.
func NextURLHasSuffix(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldNextURL), v))
	})
}

// NextURLEqualFold applies the EqualFold predicate on the "next_url" field.
func NextURLEqualFold(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldNextURL), v))
	})
}

// NextURLContainsFold applies the ContainsFold predicate on the "next_url" field.
func NextURLContainsFold(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldNextURL), v))
	})
}

// OrganizationEQ applies the EQ predicate on the "organization" field.
func OrganizationEQ(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldOrganization), v))
	})
}

// OrganizationNEQ applies the NEQ predicate on the "organization" field.
func OrganizationNEQ(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldOrganization), v))
	})
}

// OrganizationIn applies the In predicate on the "organization" field.
func OrganizationIn(vs ...string) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldOrganization), v...))
	})
}

// OrganizationNotIn applies the NotIn predicate on the "organization" field.
func OrganizationNotIn(vs ...string) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldOrganization), v...))
	})
}

// OrganizationGT applies the GT predicate on the "organization" field.
func OrganizationGT(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldOrganization), v))
	})
}

// OrganizationGTE applies the GTE predicate on the "organization" field.
func OrganizationGTE(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldOrganization), v))
	})
}

// OrganizationLT applies the LT predicate on the "organization" field.
func OrganizationLT(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldOrganization), v))
	})
}

// OrganizationLTE applies the LTE predicate on the "organization" field.
func OrganizationLTE(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldOrganization), v))
	})
}

// OrganizationContains applies the Contains predicate on the "organization" field.
func OrganizationContains(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldOrganization), v))
	})
}

// OrganizationHasPrefix applies the HasPrefix predicate on the "organization" field.
func OrganizationHasPrefix(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldOrganization), v))
	})
}

// OrganizationHasSuffix applies the HasSuffix predicate on the "organization" field.
func OrganizationHasSuffix(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldOrganization), v))
	})
}

// OrganizationIsNil applies the IsNil predicate on the "organization" field.
func OrganizationIsNil() predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.IsNull(s.C(FieldOrganization)))
	})
}

// OrganizationNotNil applies the NotNil predicate on the "organization" field.
func OrganizationNotNil() predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NotNull(s.C(FieldOrganization)))
	})
}

// OrganizationEqualFold applies the EqualFold predicate on the "organization" field.
func OrganizationEqualFold(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldOrganization), v))
	})
}

// OrganizationContainsFold applies the ContainsFold predicate on the "organization" field.
func OrganizationContainsFold(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldOrganization), v))
	})
}

// DeviceIdentifierEQ applies the EQ predicate on the "device_identifier" field.
func DeviceIdentifierEQ(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierNEQ applies the NEQ predicate on the "device_identifier" field.
func DeviceIdentifierNEQ(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierIn applies the In predicate on the "device_identifier" field.
func DeviceIdentifierIn(vs ...string) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldDeviceIdentifier), v...))
	})
}

// DeviceIdentifierNotIn applies the NotIn predicate on the "device_identifier" field.
func DeviceIdentifierNotIn(vs ...string) predicate.GoogleFlow {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldDeviceIdentifier), v...))
	})
}

// DeviceIdentifierGT applies the GT predicate on the "device_identifier" field.
func DeviceIdentifierGT(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierGTE applies the GTE predicate on the "device_identifier" field.
func DeviceIdentifierGTE(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierLT applies the LT predicate on the "device_identifier" field.
func DeviceIdentifierLT(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierLTE applies the LTE predicate on the "device_identifier" field.
func DeviceIdentifierLTE(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierContains applies the Contains predicate on the "device_identifier" field.
func DeviceIdentifierContains(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierHasPrefix applies the HasPrefix predicate on the "device_identifier" field.
func DeviceIdentifierHasPrefix(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierHasSuffix applies the HasSuffix predicate on the "device_identifier" field.
func DeviceIdentifierHasSuffix(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierIsNil applies the IsNil predicate on the "device_identifier" field.
func DeviceIdentifierIsNil() predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.IsNull(s.C(FieldDeviceIdentifier)))
	})
}

// DeviceIdentifierNotNil applies the NotNil predicate on the "device_identifier" field.
func DeviceIdentifierNotNil() predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.NotNull(s.C(FieldDeviceIdentifier)))
	})
}

// DeviceIdentifierEqualFold applies the EqualFold predicate on the "device_identifier" field.
func DeviceIdentifierEqualFold(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldDeviceIdentifier), v))
	})
}

// DeviceIdentifierContainsFold applies the ContainsFold predicate on the "device_identifier" field.
func DeviceIdentifierContainsFold(v string) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldDeviceIdentifier), v))
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.GoogleFlow) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.GoogleFlow) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
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
func Not(p predicate.GoogleFlow) predicate.GoogleFlow {
	return predicate.GoogleFlow(func(s *sql.Selector) {
		p(s.Not())
	})
}
