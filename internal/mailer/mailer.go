//SPDX-License-Identifier: Apache-2.0

package mailer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/wneessen/go-mail"
)

var _ Mailer = (*Client)(nil)

var (
	ErrMissingConfig        = errors.New("missing required configuration")
	ErrTemplateNotFound     = errors.New("template file not found")
	ErrTemplateParseFailed  = errors.New("failed to parse template")
	ErrTemplateMissingVars  = errors.New("template missing required variables")
	ErrSMTPConnectionFailed = errors.New("failed to connect to SMTP server")
	ErrInvalidEmail         = errors.New("invalid email address")
	ErrSendFailed           = errors.New("failed to send email")
)

type Mailer interface {
	SendMagicLink(ctx context.Context, email Email, magicLinkURL string, expiresIn time.Duration) error
	TestConnection(ctx context.Context) error
}

// Config holds the configuration for the mailer client
type Config struct {
	// SMTP Configuration
	SMTPHost     string // SMTP server hostname
	SMTPPort     int    // SMTP server port (typically 587)
	SMTPUsername string // SMTP authentication username
	SMTPPassword string // SMTP authentication password

	// Sender Information
	FromEmail string // Sender email address
	FromName  string // Sender display name

	// Application Information
	AppName string // Application name for templates

	// Template Configuration
	MagicLinkTemplatePath string // Path to magic link HTML template file
}

// Email represents an email to be sent
type Email struct {
	To  string   // Recipient email address
	CC  []string // CC recipients
	BCC []string // BCC recipients
}

// Client is the mailer client
type Client struct {
	client    *mail.Client
	fromEmail string
	fromName  string
	appName   string

	magicLinkTemplate *template.Template
}

func New(config Config) (Mailer, error) {
	// Validate required configuration fields
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	// Validate sender email
	if err := ValidateEmail(config.FromEmail); err != nil {
		return nil, errors.Join(ErrMissingConfig,
			fmt.Errorf("invalid from email: %w", err))
	}

	// Load and parse magic link template
	magicLinkTemplate, err := loadAndParseTemplate(config.MagicLinkTemplatePath)
	if err != nil {
		return nil, err
	}

	// Validate the template has required variables
	if err = ValidateMagicLinkTemplate(magicLinkTemplate); err != nil {
		return nil, err
	}

	c, err := mail.NewClient(config.SMTPHost, mail.WithPort(config.SMTPPort), mail.WithUsername(config.SMTPUsername), mail.WithPassword(config.SMTPPassword), mail.WithSMTPAuth(mail.SMTPAuthPlain), mail.WithTLSPolicy(mail.TLSOpportunistic))
	if err != nil {
		return nil, err
	}

	client := &Client{
		client:            c,
		fromEmail:         config.FromEmail,
		fromName:          config.FromName,
		appName:           config.AppName,
		magicLinkTemplate: magicLinkTemplate,
	}

	return client, nil
}

// SendMagicLink sends a magic link email to the specified recipient
func (c *Client) SendMagicLink(ctx context.Context, email Email, magicLinkURL string, expiresIn time.Duration) error {
	// Validate recipient email
	if err := ValidateEmail(email.To); err != nil {
		return err
	}

	// Validate CC emails if provided
	for _, cc := range email.CC {
		if err := ValidateEmail(cc); err != nil {
			return errors.Join(ErrInvalidEmail,
				fmt.Errorf("invalid CC email %s: %w", cc, err))
		}
	}

	// Validate BCC emails if provided
	for _, bcc := range email.BCC {
		if err := ValidateEmail(bcc); err != nil {
			return errors.Join(ErrInvalidEmail,
				fmt.Errorf("invalid BCC email %s: %w", bcc, err))
		}
	}

	// Format expiration duration
	expiresInFormatted := FormatDuration(expiresIn)

	// Prepare template data
	data := struct {
		RecipientEmail string
		MagicLinkURL   string
		ExpiresIn      string
		AppName        string
	}{
		RecipientEmail: email.To,
		MagicLinkURL:   magicLinkURL,
		ExpiresIn:      expiresInFormatted,
		AppName:        c.appName,
	}

	// Execute template
	var htmlBuf bytes.Buffer
	if err := c.magicLinkTemplate.Execute(&htmlBuf, data); err != nil {
		return errors.Join(ErrSendFailed,
			fmt.Errorf("failed to execute template: %w", err))
	}

	// Generate plain text version
	plainText := generatePlainText(data)

	// Create email message
	m := mail.NewMsg()
	err := m.To(email.To)
	if err != nil {
		return errors.Join(ErrSendFailed, fmt.Errorf("failed to set `to` field: %w", err))
	}
	err = m.FromFormat(c.fromName, c.fromEmail)
	if err != nil {
		return errors.Join(ErrSendFailed, fmt.Errorf("failed to set `from` field: %w", err))
	}

	// Add CC recipients if provided
	if len(email.CC) > 0 {
		err = m.Cc(email.CC...)
		if err != nil {
			return errors.Join(ErrSendFailed, fmt.Errorf("failed to set `cc` field: %w", err))
		}
	}

	// Add BCC recipients if provided
	if len(email.BCC) > 0 {
		err = m.Bcc(email.BCC...)
		if err != nil {
			return errors.Join(ErrSendFailed, fmt.Errorf("failed to set `bcc` field: %w", err))
		}
	}

	m.Subject(fmt.Sprintf("Sign in to %s", c.appName))
	m.SetBodyString("text/html", htmlBuf.String())
	m.AddAlternativeString("text/plain", plainText)

	err = c.client.DialAndSendWithContext(ctx, m)
	if err != nil {
		return errors.Join(ErrSendFailed, err)
	}

	return nil
}

// TestConnection tests the SMTP connection
func (c *Client) TestConnection(ctx context.Context) error {
	err := c.client.DialWithContext(ctx)
	if err != nil {
		return errors.Join(ErrSMTPConnectionFailed, err)
	}

	return nil
}

// validateConfig validates the configuration
func validateConfig(cfg Config) error {
	var missingFields []string

	if cfg.SMTPHost == "" {
		missingFields = append(missingFields, "SMTPHost")
	}
	if cfg.SMTPPort == 0 {
		missingFields = append(missingFields, "SMTPPort")
	}
	if cfg.SMTPUsername == "" {
		missingFields = append(missingFields, "SMTPUsername")
	}
	if cfg.SMTPPassword == "" {
		missingFields = append(missingFields, "SMTPPassword")
	}
	if cfg.FromEmail == "" {
		missingFields = append(missingFields, "FromEmail")
	}
	if cfg.FromName == "" {
		missingFields = append(missingFields, "FromName")
	}
	if cfg.AppName == "" {
		missingFields = append(missingFields, "AppName")
	}
	if cfg.MagicLinkTemplatePath == "" {
		missingFields = append(missingFields, "MagicLinkTemplatePath")
	}

	if len(missingFields) > 0 {
		return errors.Join(ErrMissingConfig,
			fmt.Errorf("missing required fields: %s", strings.Join(missingFields, ", ")))
	}

	return nil
}

// loadAndParseTemplate loads and parses a template from file
func loadAndParseTemplate(path string) (*template.Template, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, errors.Join(ErrTemplateNotFound,
			fmt.Errorf("template file not found at %s", path))
	}

	// Read template file
	templateContent, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Join(ErrTemplateNotFound, err)
	}

	// Parse template
	tmpl, err := template.New("magiclink").Parse(string(templateContent))
	if err != nil {
		return nil, errors.Join(ErrTemplateParseFailed, err)
	}

	return tmpl, nil
}

// generatePlainText generates a plain text version of the email
func generatePlainText(data struct {
	RecipientEmail string
	MagicLinkURL   string
	ExpiresIn      string
	AppName        string
}) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Sign in to %s\n\n", data.AppName))
	sb.WriteString(fmt.Sprintf("A sign-in link was requested for %s.\n\n", data.RecipientEmail))
	sb.WriteString("Click the link below to sign in:\n")
	sb.WriteString(fmt.Sprintf("%s\n\n", data.MagicLinkURL))
	sb.WriteString(fmt.Sprintf("This link will expire in %s.\n\n", data.ExpiresIn))
	sb.WriteString("If you didn't request this, you can safely ignore this email.\n")

	return sb.String()
}
