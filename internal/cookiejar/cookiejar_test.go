//SPDX-License-Identifier: Apache-2.0

package cookiejar

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("NewWithoutOptions", func(t *testing.T) {
		jar, err := New(nil)
		require.NoError(t, err)
		require.NotNil(t, jar)
		require.NotNil(t, jar.entries)
		require.Nil(t, jar.publicSuffixList)
	})

	t.Run("NewWithOptions", func(t *testing.T) {
		psl := &mockPublicSuffixList{}
		jar, err := New(&cookiejar.Options{
			PublicSuffixList: psl,
		})
		require.NoError(t, err)
		require.NotNil(t, jar)
		require.Equal(t, psl, jar.publicSuffixList)
	})
}

func TestBasicSetAndGetCookies(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	u, err := url.Parse("https://example.com/path")
	require.NoError(t, err)

	// Set a cookie
	cookies := []*http.Cookie{
		{
			Name:  "test",
			Value: "value",
		},
	}
	jar.SetCookies(u, cookies)

	// Get the cookie back
	got := jar.Cookies(u)
	require.Len(t, got, 1)
	require.Equal(t, "test", got[0].Name)
	require.Equal(t, "value", got[0].Value)
}

func TestCookiesWithInvalidScheme(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	// Try with non-HTTP/HTTPS schemes
	schemes := []string{"ftp", "ws", "file"}
	for _, scheme := range schemes {
		u, err := url.Parse(scheme + "://example.com/path")
		require.NoError(t, err)

		cookies := []*http.Cookie{{Name: "test", Value: "value"}}
		jar.SetCookies(u, cookies)

		got := jar.Cookies(u)
		require.Empty(t, got, "scheme %s should not store cookies", scheme)
	}
}

func TestCookieExpiration(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	u, err := url.Parse("https://example.com/")
	require.NoError(t, err)

	now := time.Now()

	// Set an expired cookie
	expiredCookie := &http.Cookie{
		Name:    "expired",
		Value:   "value",
		Expires: now.Add(-time.Hour),
	}
	jar.setCookies(u, []*http.Cookie{expiredCookie}, now)

	// Cookie should not be returned
	got := jar.cookies(u, now)
	require.Empty(t, got)

	// Set a cookie that expires in the future
	futureCookie := &http.Cookie{
		Name:    "future",
		Value:   "value",
		Expires: now.Add(time.Hour),
	}
	jar.setCookies(u, []*http.Cookie{futureCookie}, now)

	// Cookie should be returned now
	got = jar.cookies(u, now)
	require.Len(t, got, 1)

	// Cookie should not be returned after expiration
	got = jar.cookies(u, now.Add(2*time.Hour))
	require.Empty(t, got)
}

func TestCookieMaxAge(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	u, err := url.Parse("https://example.com/")
	require.NoError(t, err)

	now := time.Now()

	// Test negative MaxAge (should delete cookie)
	negativeCookie := &http.Cookie{
		Name:   "negative",
		Value:  "value",
		MaxAge: -1,
	}
	jar.setCookies(u, []*http.Cookie{negativeCookie}, now)
	got := jar.cookies(u, now)
	require.Empty(t, got)

	// Test positive MaxAge
	positiveCookie := &http.Cookie{
		Name:   "positive",
		Value:  "value",
		MaxAge: 3600, // 1 hour
	}
	jar.setCookies(u, []*http.Cookie{positiveCookie}, now)

	// Should be available now
	got = jar.cookies(u, now)
	require.Len(t, got, 1)

	// Should not be available after MaxAge seconds
	got = jar.cookies(u, now.Add(2*time.Hour))
	require.Empty(t, got)

	// Test zero MaxAge (session cookie)
	sessionCookie := &http.Cookie{
		Name:   "session",
		Value:  "value",
		MaxAge: 0,
	}
	jar.setCookies(u, []*http.Cookie{sessionCookie}, now)
	got = jar.cookies(u, now)
	require.Len(t, got, 1)
}

func TestCookiePath(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	baseURL, _ := url.Parse("https://example.com/dir1/dir2/page")

	testCases := []struct {
		name       string
		cookiePath string
		requestURL string
		shouldSend bool
	}{
		{"exact match", "/dir1/dir2", "https://example.com/dir1/dir2", true},
		{"path prefix with trailing slash", "/dir1/", "https://example.com/dir1/dir2", true},
		{"path prefix without trailing slash", "/dir1", "https://example.com/dir1/dir2", true},
		{"different path", "/other", "https://example.com/dir1/dir2", false},
		{"root path", "/", "https://example.com/any/path", true},
		{"empty path defaults to parent", "", "https://example.com/dir1/dir2", true},        // defaults to /dir1
		{"path not starting with slash", "relative", "https://example.com/dir1/dir2", true}, // defaults to /dir1
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cookie := &http.Cookie{
				Name:  "test",
				Value: "value",
				Path:  tc.cookiePath,
			}
			jar.SetCookies(baseURL, []*http.Cookie{cookie})

			reqURL, _ := url.Parse(tc.requestURL)
			got := jar.Cookies(reqURL)

			if tc.shouldSend {
				require.Len(t, got, 1, "cookie should be sent for %s", tc.requestURL)
			} else {
				require.Empty(t, got, "cookie should not be sent for %s", tc.requestURL)
			}

			// Clear jar for next test
			jar.entries = make(map[string]map[string]entry)
		})
	}
}

func TestCookieDomain(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	testCases := []struct {
		name         string
		setCookieURL string
		cookieDomain string
		requestURL   string
		shouldSend   bool
		shouldStore  bool
	}{
		// Host-only cookies (no domain attribute)
		{"host-only exact match", "https://example.com", "", "https://example.com", true, true},
		{"host-only subdomain", "https://example.com", "", "https://sub.example.com", false, true},

		// Domain cookies
		{"domain exact match", "https://example.com", "example.com", "https://example.com", true, true},
		{"domain subdomain", "https://example.com", "example.com", "https://sub.example.com", true, true},
		{"domain with leading dot", "https://example.com", ".example.com", "https://sub.example.com", true, true},

		// Invalid domains
		{"different domain", "https://example.com", "other.com", "https://example.com", false, false},
		{"subdomain setting parent", "https://sub.example.com", "example.com", "https://example.com", true, true},
		{"parent setting subdomain", "https://example.com", "sub.example.com", "https://sub.example.com", false, false},

		// IP addresses
		{"IP host-only", "https://127.0.0.1", "", "https://127.0.0.1", true, true},
		{"IP with domain", "https://127.0.0.1", "127.0.0.1", "https://127.0.0.1", true, true},
		{"IP different domain", "https://127.0.0.1", "192.168.1.1", "https://127.0.0.1", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear jar
			jar.entries = make(map[string]map[string]entry)

			setURL, _ := url.Parse(tc.setCookieURL)
			cookie := &http.Cookie{
				Name:   "test",
				Value:  "value",
				Domain: tc.cookieDomain,
			}
			jar.SetCookies(setURL, []*http.Cookie{cookie})

			reqURL, _ := url.Parse(tc.requestURL)
			got := jar.Cookies(reqURL)

			if tc.shouldStore {
				if tc.shouldSend {
					require.Len(t, got, 1, "cookie should be sent")
				} else {
					require.Empty(t, got, "cookie should not be sent")
				}
			} else {
				require.Empty(t, got, "invalid cookie should not be stored")
			}
		})
	}
}

func TestCookieSecure(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	httpsURL, _ := url.Parse("https://example.com/")
	httpURL, _ := url.Parse("http://example.com/")

	// Set secure cookie
	secureCookie := &http.Cookie{
		Name:   "secure",
		Value:  "value",
		Secure: true,
	}
	jar.SetCookies(httpsURL, []*http.Cookie{secureCookie})

	// Should be sent over HTTPS
	got := jar.Cookies(httpsURL)
	require.Len(t, got, 1)

	// Should NOT be sent over HTTP
	got = jar.Cookies(httpURL)
	require.Empty(t, got)

	// Non-secure cookie should be sent over both
	nonSecureCookie := &http.Cookie{
		Name:  "nonsecure",
		Value: "value",
	}
	jar.SetCookies(httpURL, []*http.Cookie{nonSecureCookie})

	got = jar.Cookies(httpsURL)
	require.Len(t, got, 2) // both cookies

	got = jar.Cookies(httpURL)
	require.Len(t, got, 1) // only non-secure
	require.Equal(t, "nonsecure", got[0].Name)
}

func TestCookieSameSite(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	u, _ := url.Parse("https://example.com/")

	testCases := []struct {
		sameSite http.SameSite
		expected string
	}{
		{http.SameSiteDefaultMode, "SameSite"},
		{http.SameSiteStrictMode, "SameSite=Strict"},
		{http.SameSiteLaxMode, "SameSite=Lax"},
		{http.SameSiteNoneMode, ""},
	}

	for _, tc := range testCases {
		cookie := &http.Cookie{
			Name:     fmt.Sprintf("test%d", tc.sameSite),
			Value:    "value",
			SameSite: tc.sameSite,
		}
		jar.SetCookies(u, []*http.Cookie{cookie})

		// Check internal representation
		jar.mu.Lock()
		submap := jar.entries["example.com"]
		require.NotNil(t, submap)
		for _, e := range submap {
			if e.Name == cookie.Name {
				require.Equal(t, tc.expected, e.SameSite)
			}
		}
		jar.mu.Unlock()
	}
}

func TestCookieOrdering(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	u, _ := url.Parse("https://example.com/a/b/c")
	now := time.Now()

	// Set cookies with different paths and creation times
	cookies := []*http.Cookie{
		{Name: "c1", Value: "v1", Path: "/a"},
		{Name: "c2", Value: "v2", Path: "/a/b"},
		{Name: "c3", Value: "v3", Path: "/a/b/c"},
		{Name: "c4", Value: "v4", Path: "/a/b"},
	}

	// Set cookies with slight delays to ensure different creation times
	for i, cookie := range cookies {
		jar.setCookies(u, []*http.Cookie{cookie}, now.Add(time.Duration(i)*time.Second))
	}

	got := jar.Cookies(u)
	require.Len(t, got, 4)

	// Should be ordered by path length (longest first), then by creation time
	require.Equal(t, "c3", got[0].Name) // longest path
	require.Equal(t, "c2", got[1].Name) // second longest, created earlier
	require.Equal(t, "c4", got[2].Name) // second longest, created later
	require.Equal(t, "c1", got[3].Name) // shortest path
}

func TestCookieUpdate(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	u, _ := url.Parse("https://example.com/")

	// Set initial cookie
	cookie1 := &http.Cookie{
		Name:  "test",
		Value: "value1",
	}
	jar.SetCookies(u, []*http.Cookie{cookie1})

	// Update the cookie
	cookie2 := &http.Cookie{
		Name:  "test",
		Value: "value2",
	}
	jar.SetCookies(u, []*http.Cookie{cookie2})

	// Should have the updated value
	got := jar.Cookies(u)
	require.Len(t, got, 1)
	require.Equal(t, "value2", got[0].Value)
}

func TestCookieDeletion(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	u, _ := url.Parse("https://example.com/")

	// Set a cookie
	cookie := &http.Cookie{
		Name:  "test",
		Value: "value",
	}
	jar.SetCookies(u, []*http.Cookie{cookie})

	// Verify it exists
	got := jar.Cookies(u)
	require.Len(t, got, 1)

	// Delete by setting MaxAge to negative
	deleteCookie := &http.Cookie{
		Name:   "test",
		MaxAge: -1,
	}
	jar.SetCookies(u, []*http.Cookie{deleteCookie})

	// Should be deleted
	got = jar.Cookies(u)
	require.Empty(t, got)
}

func TestCanonicalHost(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
		hasError bool
	}{
		{"example.com", "example.com", false},
		{"EXAMPLE.COM", "example.com", false},
		{"example.com:80", "example.com", false},
		{"example.com.", "example.com", false},
		{"127.0.0.1", "127.0.0.1", false},
		{"127.0.0.1:8080", "127.0.0.1", false},
		{"[::1]", "[::1]", false},
		{"[::1]:8080", "::1", false},
		{"", "", false},
		{"example.com..", "example.com.", false},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := canonicalHost(tc.input)
			if tc.hasError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, got)
			}
		})
	}
}

func TestHasPort(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{"example.com", false},
		{"example.com:80", true},
		{"127.0.0.1", false},
		{"127.0.0.1:8080", true},
		{"[::1]", false},
		{"[::1]:8080", true},
		{"::1", false}, // IPv6 without brackets - no port
		{"[2001:db8::1]", false},
		{"[2001:db8::1]:8080", true},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			got := hasPort(tc.input)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestIsIP(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{"127.0.0.1", true},
		{"192.168.1.1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"example.com", false},
		{"", false},
		{"256.256.256.256", false},
		{"127.0.0.1.1", false},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			got := isIP(tc.input)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestDefaultPath(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"", "/"},
		{"/", "/"},
		{"/foo", "/"},
		{"/foo/", "/foo"},
		{"/foo/bar", "/foo"},
		{"/foo/bar/", "/foo/bar"},
		{"foo", "/"},
		{"foo/bar", "/"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			got := defaultPath(tc.input)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestHasDotSuffix(t *testing.T) {
	testCases := []struct {
		s        string
		suffix   string
		expected bool
	}{
		{"www.example.com", "example.com", true},
		{"example.com", "example.com", false},
		{"example.com", "com", true},
		{"example.com", "org", false},
		{"sub.sub.example.com", "example.com", true},
		{"", "com", false},
		{"com", "com", false},
		{".com", "com", true},
		{"x.com", "com", true},
	}

	for _, tc := range testCases {
		t.Run(tc.s+"/"+tc.suffix, func(t *testing.T) {
			got := hasDotSuffix(tc.s, tc.suffix)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestJarKey(t *testing.T) {
	// Test without PublicSuffixList
	testCases := []struct {
		host     string
		expected string
	}{
		{"127.0.0.1", "127.0.0.1"},
		{"example.com", "example.com"},
		{"www.example.com", "example.com"},
		{"sub.sub.example.com", "example.com"},
		{"com", "com"},
		{"localhost", "localhost"},
	}

	for _, tc := range testCases {
		t.Run("nil_psl/"+tc.host, func(t *testing.T) {
			got := jarKey(tc.host, nil)
			require.Equal(t, tc.expected, got)
		})
	}

	// Test with PublicSuffixList
	psl := &mockPublicSuffixList{
		publicSuffixes: map[string]string{
			"example.com":     "com",
			"www.example.com": "com",
			"example.co.uk":   "co.uk",
			"bbc.co.uk":       "co.uk",
			"com":             "com",
		},
	}

	testCasesWithPSL := []struct {
		host     string
		expected string
	}{
		{"example.com", "example.com"},
		{"www.example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"example.co.uk", "example.co.uk"},
		{"bbc.co.uk", "bbc.co.uk"},
		{"127.0.0.1", "127.0.0.1"},
	}

	for _, tc := range testCasesWithPSL {
		t.Run("with_psl/"+tc.host, func(t *testing.T) {
			got := jarKey(tc.host, psl)
			require.Equal(t, tc.expected, got)
		})
	}

	// Test edge cases with broken PSL
	t.Run("psl_returns_full_host", func(t *testing.T) {
		brokenPSL := &mockPublicSuffixList{
			publicSuffixes: map[string]string{
				"example.com": "example.com", // PSL returns the full host
			},
		}
		got := jarKey("example.com", brokenPSL)
		require.Equal(t, "example.com", got)
	})

	t.Run("psl_returns_invalid_suffix", func(t *testing.T) {
		brokenPSL := &mockPublicSuffixList{
			publicSuffixes: map[string]string{
				"sub.example.com": "invalid.suffix.that.is.longer", // Invalid suffix
			},
		}
		got := jarKey("sub.example.com", brokenPSL)
		require.Equal(t, "sub.example.com", got) // Falls back to host
	})
}

func TestPublicSuffixListIntegration(t *testing.T) {
	psl := &mockPublicSuffixList{
		publicSuffixes: map[string]string{
			"example.com":       "com",
			"example.co.uk":     "co.uk",
			"github.io":         "github.io",
			"example.github.io": "github.io",
		},
	}

	jar, err := New(&cookiejar.Options{PublicSuffixList: psl})
	require.NoError(t, err)

	// Test that we can't set a cookie for a public suffix
	u, _ := url.Parse("https://example.github.io")
	cookie := &http.Cookie{
		Name:   "test",
		Value:  "value",
		Domain: "github.io",
	}
	jar.SetCookies(u, []*http.Cookie{cookie})

	// Cookie should not be stored
	got := jar.Cookies(u)
	require.Empty(t, got)

	// But we can set a cookie for the exact domain when it equals the host
	cookie2 := &http.Cookie{
		Name:   "test2",
		Value:  "value2",
		Domain: "example.github.io",
	}
	jar.SetCookies(u, []*http.Cookie{cookie2})

	got = jar.Cookies(u)
	require.Len(t, got, 1)
}

func TestEntryMethods(t *testing.T) {
	t.Run("id", func(t *testing.T) {
		e := entry{
			Name:   "test",
			Domain: "example.com",
			Path:   "/path",
		}
		require.Equal(t, "example.com;/path;test", e.id())
	})

	t.Run("domainMatch", func(t *testing.T) {
		hostOnlyCookie := entry{Domain: "example.com", HostOnly: true}
		domainCookie := entry{Domain: "example.com", HostOnly: false}

		// Host-only cookie
		require.True(t, hostOnlyCookie.domainMatch("example.com"))
		require.False(t, hostOnlyCookie.domainMatch("sub.example.com"))

		// Domain cookie
		require.True(t, domainCookie.domainMatch("example.com"))
		require.True(t, domainCookie.domainMatch("sub.example.com"))
		require.False(t, domainCookie.domainMatch("other.com"))
	})

	t.Run("pathMatch", func(t *testing.T) {
		testCases := []struct {
			cookiePath  string
			requestPath string
			shouldMatch bool
		}{
			{"/", "/", true},
			{"/", "/any", true},
			{"/path", "/path", true},
			{"/path/", "/path/sub", true},
			{"/path", "/path/sub", true},
			{"/path", "/other", false},
			{"/path", "/pa", false},
		}

		for _, tc := range testCases {
			e := entry{Path: tc.cookiePath}
			got := e.pathMatch(tc.requestPath)
			require.Equal(t, tc.shouldMatch, got,
				"pathMatch(%q, %q) = %v, want %v",
				tc.cookiePath, tc.requestPath, got, tc.shouldMatch)
		}
	})

	t.Run("shouldSend", func(t *testing.T) {
		e := entry{
			Domain:   "example.com",
			Path:     "/path",
			Secure:   true,
			HostOnly: false,
		}

		// HTTPS request to correct domain and path
		require.True(t, e.shouldSend(true, "example.com", "/path"))

		// HTTP request with secure cookie
		require.False(t, e.shouldSend(false, "example.com", "/path"))

		// Wrong domain
		require.False(t, e.shouldSend(true, "other.com", "/path"))

		// Wrong path
		require.False(t, e.shouldSend(true, "example.com", "/other"))
	})
}

func TestDomainAndTypeErrors(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	testCases := []struct {
		name         string
		host         string
		domain       string
		expectDomain string
		expectHost   bool
		expectError  error
	}{
		// Valid cases
		{"empty domain", "example.com", "", "example.com", true, nil},
		{"same domain", "example.com", "example.com", "example.com", false, nil},
		{"parent domain", "sub.example.com", "example.com", "example.com", false, nil},
		{"domain with dot", "sub.example.com", ".example.com", "example.com", false, nil},

		// IP addresses
		{"IP same", "127.0.0.1", "127.0.0.1", "127.0.0.1", true, nil},
		{"IP different", "127.0.0.1", "192.168.1.1", "", false, errIllegalDomain},

		// Error cases
		{"just dot", "example.com", ".", "", false, errMalformedDomain},
		{"double dot", "example.com", "..example.com", "", false, errMalformedDomain},
		{"trailing dot", "example.com", "example.com.", "", false, errMalformedDomain},
		{"different domain", "example.com", "other.com", "", false, errIllegalDomain},
		{"subdomain setting parent", "example.com", "sub.example.com", "", false, errIllegalDomain},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			domain, hostOnly, err := jar.domainAndType(tc.host, tc.domain)
			if tc.expectError != nil {
				require.ErrorIs(t, err, tc.expectError)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expectDomain, domain)
				require.Equal(t, tc.expectHost, hostOnly)
			}
		})
	}
}

func TestEmptyCookiesList(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	u, _ := url.Parse("https://example.com/")

	// Setting empty cookie list should do nothing
	jar.SetCookies(u, []*http.Cookie{})

	got := jar.Cookies(u)
	require.Empty(t, got)
}

func TestInvalidHost(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	// Invalid host that causes canonicalHost to fail
	u, _ := url.Parse("https://[invalid:host]/")

	cookie := &http.Cookie{
		Name:  "test",
		Value: "value",
	}
	jar.SetCookies(u, []*http.Cookie{cookie})

	// Should not store cookie
	got := jar.Cookies(u)
	require.Empty(t, got)
}

func TestConcurrentAccess(t *testing.T) {
	jar, err := New(nil)
	require.NoError(t, err)

	u, _ := url.Parse("https://example.com/")

	// Run concurrent operations
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			cookie := &http.Cookie{
				Name:  fmt.Sprintf("cookie%d", i),
				Value: fmt.Sprintf("value%d", i),
			}
			jar.SetCookies(u, []*http.Cookie{cookie})
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			_ = jar.Cookies(u)
		}
		done <- true
	}()

	// Wait for both to complete
	<-done
	<-done

	// Verify we have some cookies
	got := jar.Cookies(u)
	require.NotEmpty(t, got)
}

// mockPublicSuffixList implements cookiejar.PublicSuffixList for testing
type mockPublicSuffixList struct {
	publicSuffixes map[string]string
}

func (m *mockPublicSuffixList) PublicSuffix(domain string) string {
	if suffix, ok := m.publicSuffixes[domain]; ok {
		return suffix
	}
	// Default behavior similar to the real implementation
	i := strings.LastIndex(domain, ".")
	if i < 0 {
		return domain
	}
	return domain[i+1:]
}

func (m *mockPublicSuffixList) String() string {
	return "mock public suffix list"
}
