//SPDX-License-Identifier: Apache-2.0

package mailer

import (
	"bytes"
	"errors"
	"html/template"
	"net/mail"
	"strings"
)

var (
	ErrEmptyEmailAddress              = errors.New("empty email address")
	ErrInvalidEmailAddressCharacters  = errors.New("email address contains invalid characters")
	ErrTemplateDoesNotUseAllVariables = errors.New("template does not use all variables")
)

// ValidateEmail checks if an email address is valid
func ValidateEmail(email string) error {
	if email == "" {
		return errors.Join(ErrInvalidEmail, ErrEmptyEmailAddress)
	}

	addr, err := mail.ParseAddress(email)
	if err != nil {
		return errors.Join(ErrInvalidEmail, err)
	}

	// Ensure the address doesn't contain dangerous characters that could lead to header injection
	if strings.ContainsAny(addr.Address, "\r\n") {
		return errors.Join(ErrInvalidEmail, ErrInvalidEmailAddressCharacters)
	}

	return nil
}

// ValidateMagicLinkTemplate validates that a template contains all required variables
func ValidateMagicLinkTemplate(tmpl *template.Template) error {
	// Test data to check if template executes properly
	testData := struct {
		RecipientEmail string
		MagicLinkURL   string
		ExpiresIn      string
		AppName        string
	}{
		RecipientEmail: "test@example.com",
		MagicLinkURL:   "https://example.com/auth/verify?token=test",
		ExpiresIn:      "30 minutes",
		AppName:        "TestApp",
	}

	// Try to execute the template with test data
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, testData); err != nil {
		return errors.Join(ErrTemplateMissingVars, err)
	}

	// Check that the output contains the required variables
	output := buf.String()
	requiredStrings := []string{
		testData.RecipientEmail,
		testData.MagicLinkURL,
		testData.ExpiresIn,
		testData.AppName,
	}

	for _, required := range requiredStrings {
		if !strings.Contains(output, required) {
			return errors.Join(ErrTemplateMissingVars, ErrTemplateDoesNotUseAllVariables)
		}
	}

	return nil
}
