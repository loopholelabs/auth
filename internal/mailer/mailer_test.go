//SPDX-License-Identifier: Apache-2.0

package mailer

import (
	"context"
	"html/template"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var _ Mailer = (*mockMailer)(nil)

// mockMailer is a mock implementation for testing
type mockMailer struct{}

func (m *mockMailer) SendMagicLink(_ context.Context, _ Email, _ string, _ time.Duration) error {
	return nil
}

func (m *mockMailer) TestConnection(_ context.Context) error {
	return nil
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{"30 seconds", 30 * time.Second, "30 seconds"},
		{"1 second", 1 * time.Second, "1 second"},
		{"45 seconds", 45 * time.Second, "45 seconds"},
		{"1 minute", 1 * time.Minute, "1 minute"},
		{"30 minutes", 30 * time.Minute, "30 minutes"},
		{"59 minutes", 59 * time.Minute, "59 minutes"},
		{"1 hour", 1 * time.Hour, "1 hour"},
		{"2 hours", 2 * time.Hour, "2 hours"},
		{"23 hours", 23 * time.Hour, "23 hours"},
		{"1 day", 24 * time.Hour, "1 day"},
		{"2 days", 48 * time.Hour, "2 days"},
		{"7 days", 7 * 24 * time.Hour, "7 days"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatDuration(tt.duration)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
		errType error
	}{
		{"Valid email", "test@example.com", false, nil},
		{"Valid email with name", "Test User <test@example.com>", false, nil},
		{"Valid email with plus", "test+tag@example.com", false, nil},
		{"Valid email with dots", "test.user@example.com", false, nil},
		{"Empty email", "", true, ErrInvalidEmail},
		{"Invalid format", "notanemail", true, ErrInvalidEmail},
		{"Missing domain", "test@", true, ErrInvalidEmail},
		{"Missing local part", "@example.com", true, ErrInvalidEmail},
		{"With newline", "test@example.com\n", true, ErrInvalidEmail},
		{"With carriage return", "test@example.com\r", true, ErrInvalidEmail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if tt.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.errType)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateMagicLinkTemplate(t *testing.T) {
	t.Run("Valid template with all variables", func(t *testing.T) {
		tmplContent := `
		Hello {{.RecipientEmail}},
		Click here: {{.MagicLinkURL}}
		Expires in: {{.ExpiresIn}}
		From: {{.AppName}}
		`
		tmpl, err := template.New("test").Parse(tmplContent)
		require.NoError(t, err)

		err = ValidateMagicLinkTemplate(tmpl)
		require.NoError(t, err)
	})

	t.Run("Template missing RecipientEmail", func(t *testing.T) {
		tmplContent := `
		Hello User,
		Click here: {{.MagicLinkURL}}
		Expires in: {{.ExpiresIn}}
		From: {{.AppName}}
		`
		tmpl, err := template.New("test").Parse(tmplContent)
		require.NoError(t, err)

		err = ValidateMagicLinkTemplate(tmpl)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrTemplateMissingVars)
	})

	t.Run("Template missing MagicLinkURL", func(t *testing.T) {
		tmplContent := `
		Hello {{.RecipientEmail}},
		Expires in: {{.ExpiresIn}}
		From: {{.AppName}}
		`
		tmpl, err := template.New("test").Parse(tmplContent)
		require.NoError(t, err)

		err = ValidateMagicLinkTemplate(tmpl)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrTemplateMissingVars)
	})

	t.Run("Template with syntax error", func(t *testing.T) {
		tmplContent := `
		Hello {{.RecipientEmail}},
		Click here: {{.MagicLinkURL
		`
		_, err := template.New("test").Parse(tmplContent)
		require.Error(t, err) // Parse should fail
	})

	t.Run("Template with wrong variable names", func(t *testing.T) {
		tmplContent := `
		Hello {{.WrongVariable}},
		`
		tmpl, err := template.New("test").Parse(tmplContent)
		require.NoError(t, err)

		err = ValidateMagicLinkTemplate(tmpl)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrTemplateMissingVars)
	})
}

func TestNewClient(t *testing.T) {
	// Create a temporary template file for testing
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "test-template.html")

	validTemplate := `
	<!DOCTYPE html>
	<html>
	<body>
		<p>Hello {{.RecipientEmail}}</p>
		<p>Click: {{.MagicLinkURL}}</p>
		<p>Expires: {{.ExpiresIn}}</p>
		<p>App: {{.AppName}}</p>
	</body>
	</html>
	`
	err := os.WriteFile(templatePath, []byte(validTemplate), 0644)
	require.NoError(t, err)

	t.Run("Valid configuration", func(t *testing.T) {
		cfg := Config{
			SMTPHost:              "smtp.example.com",
			SMTPPort:              587,
			SMTPUsername:          "user",
			SMTPPassword:          "pass",
			FromEmail:             "noreply@example.com",
			FromName:              "Test App",
			AppName:               "TestApp",
			MagicLinkTemplatePath: templatePath,
		}

		client, err := New(cfg)
		require.NoError(t, err)
		require.NotNil(t, client)
		_client, ok := client.(*Client)
		require.True(t, ok)
		require.Equal(t, cfg.FromEmail, _client.fromEmail)
		require.Equal(t, cfg.FromName, _client.fromName)
		require.Equal(t, cfg.AppName, _client.appName)
		require.NotNil(t, _client.magicLinkTemplate)
	})

	t.Run("Missing SMTP host", func(t *testing.T) {
		cfg := Config{
			SMTPPort:              587,
			SMTPUsername:          "user",
			SMTPPassword:          "pass",
			FromEmail:             "noreply@example.com",
			FromName:              "Test App",
			AppName:               "TestApp",
			MagicLinkTemplatePath: templatePath,
		}

		client, err := New(cfg)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingConfig)
		require.Contains(t, err.Error(), "SMTPHost")
		require.Nil(t, client)
	})

	t.Run("Missing SMTP port", func(t *testing.T) {
		cfg := Config{
			SMTPHost:              "smtp.example.com",
			SMTPUsername:          "user",
			SMTPPassword:          "pass",
			FromEmail:             "noreply@example.com",
			FromName:              "Test App",
			AppName:               "TestApp",
			MagicLinkTemplatePath: templatePath,
		}

		client, err := New(cfg)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingConfig)
		require.Contains(t, err.Error(), "SMTPPort")
		require.Nil(t, client)
	})

	t.Run("Invalid from email", func(t *testing.T) {
		cfg := Config{
			SMTPHost:              "smtp.example.com",
			SMTPPort:              587,
			SMTPUsername:          "user",
			SMTPPassword:          "pass",
			FromEmail:             "notanemail",
			FromName:              "Test App",
			AppName:               "TestApp",
			MagicLinkTemplatePath: templatePath,
		}

		client, err := New(cfg)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingConfig)
		require.Contains(t, err.Error(), "invalid from email")
		require.Nil(t, client)
	})

	t.Run("Missing template file", func(t *testing.T) {
		cfg := Config{
			SMTPHost:              "smtp.example.com",
			SMTPPort:              587,
			SMTPUsername:          "user",
			SMTPPassword:          "pass",
			FromEmail:             "noreply@example.com",
			FromName:              "Test App",
			AppName:               "TestApp",
			MagicLinkTemplatePath: "/nonexistent/template.html",
		}

		client, err := New(cfg)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrTemplateNotFound)
		require.Nil(t, client)
	})

	t.Run("Invalid template content", func(t *testing.T) {
		// Create template without required variables
		invalidTemplatePath := filepath.Join(tmpDir, "invalid-template.html")
		invalidTemplate := `<html><body>No variables here</body></html>`
		err := os.WriteFile(invalidTemplatePath, []byte(invalidTemplate), 0644)
		require.NoError(t, err)

		cfg := Config{
			SMTPHost:              "smtp.example.com",
			SMTPPort:              587,
			SMTPUsername:          "user",
			SMTPPassword:          "pass",
			FromEmail:             "noreply@example.com",
			FromName:              "Test App",
			AppName:               "TestApp",
			MagicLinkTemplatePath: invalidTemplatePath,
		}

		client, err := New(cfg)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrTemplateMissingVars)
		require.Nil(t, client)
	})

	t.Run("Multiple missing fields", func(t *testing.T) {
		cfg := Config{
			FromEmail: "noreply@example.com",
		}

		client, err := New(cfg)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrMissingConfig)
		require.Contains(t, err.Error(), "SMTPHost")
		require.Contains(t, err.Error(), "SMTPPort")
		require.Contains(t, err.Error(), "SMTPUsername")
		require.Nil(t, client)
	})
}

func TestGeneratePlainText(t *testing.T) {
	data := struct {
		RecipientEmail string
		MagicLinkURL   string
		ExpiresIn      string
		AppName        string
	}{
		RecipientEmail: "user@example.com",
		MagicLinkURL:   "https://app.com/auth/verify?token=abc123",
		ExpiresIn:      "30 minutes",
		AppName:        "TestApp",
	}

	plainText := generatePlainText(data)

	// Check that all required information is present
	require.Contains(t, plainText, "Sign in to TestApp")
	require.Contains(t, plainText, "user@example.com")
	require.Contains(t, plainText, "https://app.com/auth/verify?token=abc123")
	require.Contains(t, plainText, "30 minutes")
	require.Contains(t, plainText, "ignore this email")
}

func TestSendMagicLink(t *testing.T) {
	// Create a temporary template file for testing
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "test-template.html")

	validTemplate := `
	<!DOCTYPE html>
	<html>
	<body>
		<p>Hello {{.RecipientEmail}}</p>
		<p>Click: {{.MagicLinkURL}}</p>
		<p>Expires: {{.ExpiresIn}}</p>
		<p>App: {{.AppName}}</p>
	</body>
	</html>
	`
	err := os.WriteFile(templatePath, []byte(validTemplate), 0644)
	require.NoError(t, err)

	// Create a client with mock SMTP settings
	// Note: This won't actually send emails in tests
	cfg := Config{
		SMTPHost:              "localhost",
		SMTPPort:              1025, // Non-standard port to avoid actual sending
		SMTPUsername:          "test",
		SMTPPassword:          "test",
		FromEmail:             "noreply@example.com",
		FromName:              "Test App",
		AppName:               "TestApp",
		MagicLinkTemplatePath: templatePath,
	}

	client, err := New(cfg)
	require.NoError(t, err)

	t.Run("Invalid recipient email", func(t *testing.T) {
		email := Email{
			To: "notanemail",
		}

		err := client.SendMagicLink(t.Context(), email, "https://app.com/magic", 30*time.Minute)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidEmail)
	})

	t.Run("Invalid CC email", func(t *testing.T) {
		email := Email{
			To: "valid@example.com",
			CC: []string{"invalid-cc"},
		}

		err := client.SendMagicLink(t.Context(), email, "https://app.com/magic", 30*time.Minute)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidEmail)
		require.Contains(t, err.Error(), "invalid CC email")
	})

	t.Run("Invalid BCC email", func(t *testing.T) {
		email := Email{
			To:  "valid@example.com",
			BCC: []string{"invalid-bcc"},
		}

		err := client.SendMagicLink(t.Context(), email, "https://app.com/magic", 30*time.Minute)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidEmail)
		require.Contains(t, err.Error(), "invalid BCC email")
	})

	t.Run("Valid email structure", func(t *testing.T) {
		email := Email{
			To:  "user@example.com",
			CC:  []string{"cc@example.com"},
			BCC: []string{"bcc@example.com"},
		}

		// This will fail to send due to invalid SMTP settings, but we're testing
		// the email validation and structure, not actual sending
		err := client.SendMagicLink(t.Context(), email, "https://app.com/magic", 30*time.Minute)
		// We expect a send error, not a validation error
		if err != nil {
			require.ErrorIs(t, err, ErrSendFailed)
		}
	})
}

func TestSendMagicLinkWithContext(t *testing.T) {
	// Create a temporary template file for testing
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "test-template.html")

	validTemplate := `<p>{{.RecipientEmail}} {{.MagicLinkURL}} {{.ExpiresIn}} {{.AppName}}</p>`
	err := os.WriteFile(templatePath, []byte(validTemplate), 0644)
	require.NoError(t, err)

	cfg := Config{
		SMTPHost:              "localhost",
		SMTPPort:              1025,
		SMTPUsername:          "test",
		SMTPPassword:          "test",
		FromEmail:             "noreply@example.com",
		FromName:              "Test App",
		AppName:               "TestApp",
		MagicLinkTemplatePath: templatePath,
	}

	client, err := New(cfg)
	require.NoError(t, err)

	t.Run("Context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		email := Email{
			To: "user@example.com",
		}

		err := client.SendMagicLink(ctx, email, "https://app.com/magic", 30*time.Minute)
		require.Error(t, err)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("Context timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		// Sleep to ensure timeout
		time.Sleep(10 * time.Millisecond)

		email := Email{
			To: "user@example.com",
		}

		err := client.SendMagicLink(ctx, email, "https://app.com/magic", 30*time.Minute)
		require.Error(t, err)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

func TestRealTemplateExample(t *testing.T) {
	// Test with the actual example template if it exists
	exampleTemplatePath := "./templates/magic-link.html"

	if _, err := os.Stat(exampleTemplatePath); os.IsNotExist(err) {
		t.Skip("Example template not found, skipping test")
	}

	cfg := Config{
		SMTPHost:              "smtp.example.com",
		SMTPPort:              587,
		SMTPUsername:          "user",
		SMTPPassword:          "pass",
		FromEmail:             "noreply@example.com",
		FromName:              "Test App",
		AppName:               "TestApp",
		MagicLinkTemplatePath: exampleTemplatePath,
	}

	client, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, client)

	_client, ok := client.(*Client)
	require.True(t, ok)

	// Verify the template was loaded and validated
	require.NotNil(t, _client.magicLinkTemplate)
}

// Benchmark tests
func BenchmarkFormatDuration(b *testing.B) {
	durations := []time.Duration{
		30 * time.Second,
		5 * time.Minute,
		2 * time.Hour,
		3 * 24 * time.Hour,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FormatDuration(durations[i%len(durations)])
	}
}

func BenchmarkValidateEmail(b *testing.B) {
	emails := []string{
		"test@example.com",
		"user.name+tag@example.co.uk",
		"invalid-email",
		"",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateEmail(emails[i%len(emails)])
	}
}

func BenchmarkGeneratePlainText(b *testing.B) {
	data := struct {
		RecipientEmail string
		MagicLinkURL   string
		ExpiresIn      string
		AppName        string
	}{
		RecipientEmail: "user@example.com",
		MagicLinkURL:   "https://app.com/auth/verify?token=abc123",
		ExpiresIn:      "30 minutes",
		AppName:        "TestApp",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generatePlainText(data)
	}
}
